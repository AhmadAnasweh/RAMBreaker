"""
CresCent RAM Forensics Toolkit v4.0 - IOC Extractor

Standalone module for extracting Indicators of Compromise from text data.
Organized by category for easy expansion. Each category can be enabled/disabled.

Usage as standalone:
    from modules.ioc_extractor import IOCExtractor
    ioc = IOCExtractor(logger)
    counts = ioc.extract_from_file("strings.txt", "output_dir/iocs/")

Categories:
    network     - IPs, domains, URLs, MAC addresses, UNC paths, user-agents
    email       - Email addresses
    crypto      - Bitcoin/Monero wallets, cryptocurrency addresses
    credentials - API keys, AWS keys, private keys, SSH keys, passwords
    encoding    - Base64 long strings, hex blobs
    filesystem  - Windows paths, Unix paths, executable names, registry keys
    hashes      - MD5, SHA1, SHA256, SHA512 in context
    commands    - PowerShell commands, cmd patterns, encoded commands
"""

import ipaddress
import logging
import multiprocessing as _mp
import os
import re
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


def _mp_scan_file_chunk(args: tuple) -> Dict[str, list]:
    """Scan a byte-range slice of a file for all IOC patterns.

    Each worker opens the file independently — no shared memory, no COW
    pressure, no serialization of the lines list across the pipe.

    args: (filepath, start_byte, end_byte, pat_specs)
      pat_specs: list of (name, regex_pattern_string)
    """
    filepath, start, end, pat_specs = args
    found: Dict[str, set] = {}
    compiled = [(n, re.compile(p, re.IGNORECASE)) for n, p in pat_specs]
    try:
        # Binary mode: chunk bounds are byte offsets, and text-mode tell() is
        # both slow and unreliable for arbitrary offsets (notably on Windows).
        with open(filepath, "rb") as fh:
            fh.seek(start)
            pos = start
            while pos < end:
                raw = fh.readline()
                if not raw:
                    break
                pos += len(raw)
                line = raw.decode("utf-8", "ignore").strip()
                if not line or len(line) < 4:
                    continue
                for name, regex in compiled:
                    for m in regex.findall(line):
                        val = m[0] if isinstance(m, tuple) else m
                        found.setdefault(name, set()).add(val)
    except OSError:
        pass
    return {n: list(v) for n, v in found.items()}


def _mp_line_scanner(args: tuple):
    """Feed every usable line of a strings file, in file order, to ONE stateful line
    scanner (browser history / comms / e-mail artefacts) inside a worker process.
    The scanner object travels by pickle and comes back with its results, so each
    scanner sees exactly the lines it saw in the old single-process loop."""
    filepath, obj, method = args
    fn = getattr(obj, method)
    n = 0
    with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or len(line) < 4:
                continue
            n += 1
            fn(line)
    return obj, n


def _adopt_state(target, done) -> None:
    """Copy a worker's scanner state back into the caller's object (keep its logger)."""
    for k, v in done.__dict__.items():
        if isinstance(v, logging.Logger):
            continue
        target.__dict__[k] = v


PARALLEL_SCAN_MIN_BYTES = 4 * 1024 * 1024


def _file_chunk_boundaries(filepath: Path, n_chunks: int) -> List[Tuple[int, int]]:
    """Return (start_byte, end_byte) pairs that split filepath into n_chunks
    equal-ish slices aligned to line boundaries."""
    size = filepath.stat().st_size
    if size == 0:
        return [(0, 0)]
    chunk_size = max(1, size // n_chunks)
    boundaries = [0]
    with open(filepath, "rb") as fh:
        for i in range(1, n_chunks):
            pos = i * chunk_size
            if pos >= size:
                break
            fh.seek(pos)
            fh.readline()          # advance to next newline boundary
            boundaries.append(fh.tell())
    boundaries.append(size)
    return list(zip(boundaries[:-1], boundaries[1:]))


# =========================================================================
# IOC PATTERNS - Organized by category
# Each entry: (pattern_name, regex_string, description)
# Add new patterns here to extend detection
# =========================================================================

NETWORK_PATTERNS = {
    "ipv4": (
        # not part of a longer dotted run (ASN.1 OIDs like 1.3.14.3.2.26,
        # version strings like 10.0.19041.1)
        r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?!\.?\d)",
        "IPv4 addresses"
    ),
    "ipv6": (
        r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b",
        "IPv6 addresses (full and shortened)"
    ),
    "url_http": (
        r"https?://[^\s\"'<>\]\)]{4,300}",
        "HTTP/HTTPS URLs"
    ),
    "url_ftp": (
        r"ftp://[^\s\"'<>\]\)]{4,300}",
        "FTP URLs"
    ),
    "domain": (
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
        r"{1,5}(?:com|net|org|io|info|biz|xyz|top|ru|cn|tk|ml|ga|cf|gq|cc|"
        r"pw|su|onion|bit|edu|gov|mil|int|co|us|uk|de|fr|jp|br|in|it|nl|"
        r"au|ca|es|ch|se|no|fi|dk|at|be|cz|pl|pt|ro|hu|bg|hr|sk|si|lt|lv|ee|"
        # Modern / C2-relevant TLDs added for v4.1
        r"app|dev|tech|online|store|cloud|ai|gg|ly|me|tv|sh|zip|mov|"
        r"site|space|live|world|life|today|news|click|link|cam|fun|"
        r"shop|page|wiki|tools|email|host|website|press|run|works)\b",
        "Domain names (common + modern TLDs)"
    ),
    "mac_address": (
        r"\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b",
        "MAC addresses"
    ),
    "unc_path": (
        r"\\\\[a-zA-Z0-9._\-]+\\[^\s\"'<>]{2,200}",
        "UNC paths (\\\\server\\share)"
    ),
    "user_agent": (
        r"(?:Mozilla|Opera|curl|wget|python-requests|Go-http-client|Java|"
        r"PowerShell|CobaltStrike|Metasploit)/[\d\.]+[^\r\n]{0,200}",
        "HTTP User-Agent strings"
    ),
}

EMAIL_PATTERNS = {
    "email": (
        r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b",
        "Email addresses"
    ),
}

CRYPTO_PATTERNS = {
    "bitcoin_address": (
        r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
        "Bitcoin addresses (legacy)"
    ),
    "bitcoin_bech32": (
        r"\bbc1[a-z0-9]{25,90}\b",
        "Bitcoin Bech32 addresses"
    ),
    "monero_address": (
        r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b",
        "Monero addresses"
    ),
    "ethereum_address": (
        r"\b0x[0-9a-fA-F]{40}\b",
        "Ethereum addresses"
    ),
}

CREDENTIAL_PATTERNS = {
    "aws_access_key": (
        r"\bAKIA[0-9A-Z]{16}\b",
        "AWS Access Key IDs"
    ),
    "aws_secret_key": (
        # Require an explicit AWS-context anchor to avoid matching every
        # 40-char base64/hex blob (SHA1 hashes, JWT segments, etc.).
        # Capture group 1 is the actual key value.
        r"(?:aws[_\-]?(?:secret|access)[_\-]?key(?:[_\-]?id)?|"
        r"AWS_SECRET_ACCESS_KEY|AWSSecretKey)"
        r"[\"':\s=]+([0-9a-zA-Z/+]{40})\b",
        "AWS Secret Key (context-anchored, 40 chars)"
    ),
    "private_key_header": (
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
        "Private key headers"
    ),
    "ssh_public_key": (
        r"\bssh-(?:rsa|ed25519|dss|ecdsa)\s+[A-Za-z0-9+/=]{40,}",
        "SSH public keys"
    ),
    "api_token": (
        r"\b(?:api[_\-]?key|token|bearer|authorization)[\"':\s=]+[A-Za-z0-9_\-\.]{20,100}",
        "API keys/tokens (generic patterns)"
    ),
    "password_in_url": (
        r"(?:password|passwd|pwd|pass)[=:][^\s&\"']{3,50}",
        "Password values in URLs/configs"
    ),
    # ---- v2 additions (provider-specific formats = low false-positive) ----
    "jwt": (
        r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}",
        "JSON Web Tokens (header.payload.signature)"
    ),
    "bearer_token": (
        r"\bBearer\s+([A-Za-z0-9\-._~+/]{20,500}=*)",
        "HTTP Authorization: Bearer tokens"
    ),
    "session_cookie": (
        r"(?:Set-)?Cookie:\s*[^\r\n]{0,200}?\b((?:[A-Za-z0-9_.-]*sess(?:ion)?(?:id)?|"
        r"PHPSESSID|JSESSIONID|ASP\.NET_SessionId|connect\.sid|sid|SID|SSID|"
        r"__Secure-[A-Za-z0-9_-]+|ESTSAUTH[A-Z]*|_ga)=[^;\s]{8,400})",
        "Session cookies from Cookie/Set-Cookie headers"
    ),
    "gcp_api_key": (
        r"\bAIza[0-9A-Za-z_\-]{35}\b",
        "Google Cloud / Firebase API keys"
    ),
    "gcp_service_account": (
        r"\"type\"\s*:\s*\"service_account\"[^}]{0,400}\"private_key_id\"\s*:\s*\"([0-9a-f]{40})\"",
        "GCP service-account key JSON (private_key_id)"
    ),
    "google_oauth_token": (
        r"\bya29\.[0-9A-Za-z_\-]{30,}",
        "Google OAuth access tokens"
    ),
    "azure_storage_key": (
        r"AccountKey=([A-Za-z0-9+/]{86}==)",
        "Azure Storage account keys (connection strings)"
    ),
    "azure_sas_token": (
        r"[?&]sv=\d{4}-\d{2}-\d{2}&[^\s\"'<>]{0,300}?sig=[A-Za-z0-9%+/=]{30,}",
        "Azure Shared Access Signature (SAS) tokens"
    ),
    "azure_client_secret": (
        r"\b[A-Za-z0-9_~.\-]{3}[78]Q~[A-Za-z0-9_~.\-]{31,34}\b",
        "Azure AD / Entra client secrets (new format)"
    ),
    "github_token": (
        r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b",
        "GitHub personal/OAuth/app tokens"
    ),
    "gitlab_token": (
        r"\bglpat-[A-Za-z0-9_\-]{20,}\b",
        "GitLab personal access tokens"
    ),
    "slack_token": (
        r"\bxox[abposr]-[A-Za-z0-9-]{10,200}\b",
        "Slack tokens"
    ),
    "slack_webhook": (
        r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,}",
        "Slack incoming webhooks"
    ),
    "stripe_key": (
        r"\b(?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{24,99}\b",
        "Stripe API keys"
    ),
    "openai_key": (
        r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}\b",
        "OpenAI API keys"
    ),
    "anthropic_key": (
        # api03/admin01 keys and oat01/ort01 OAuth tokens: tag + 93 chars + 'AA'.
        # No trailing \b: memory strings often glue the next field on.
        r"\bsk-ant-(?:api|admin|oat|ort)\d{2}-[A-Za-z0-9_\-]{93}AA",
        "Anthropic API keys / OAuth tokens"
    ),
    "sendgrid_key": (
        # no trailing \b: memory strings glue the next byte on (seen: 44-char tail)
        r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",
        "SendGrid API keys"
    ),
    "twilio_key": (
        r"\bSK[0-9a-fA-F]{32}\b",
        "Twilio API key SIDs"
    ),
    "telegram_bot_token": (
        r"\b\d{8,10}:AA[0-9A-Za-z_\-]{33}\b",
        "Telegram bot tokens"
    ),
    "ntlm_pwdump": (
        r"^[^:\s]{1,64}:\d{1,10}:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}:::",
        "NTLM hashes in pwdump/hashdump format (user:rid:LM:NT:::)"
    ),
    "netntlmv2": (
        r"\b[^:\s]{1,64}::[^:\s]{1,64}:[0-9a-fA-F]{16}:[0-9a-fA-F]{32}:[0-9a-fA-F]{50,}\b",
        "NetNTLMv2 challenge/response (crackable)"
    ),
}

ENCODING_PATTERNS = {
    "base64_long": (
        r"(?:[A-Za-z0-9+/]{60,}={0,2})",
        "Long Base64 strings (60+ chars)"
    ),
    "hex_blob": (
        r"\b(?:[0-9a-fA-F]{2}){20,}\b",
        "Hex-encoded blobs (40+ hex chars)"
    ),
}

FILESYSTEM_PATTERNS = {
    "windows_path": (
        r"[A-Za-z]:\\(?:[^\s\\/:*?\"<>|]+\\)*[^\s\\/:*?\"<>|]+",
        "Windows file paths"
    ),
    "unix_path": (
        r"(?:/(?:usr|etc|var|tmp|home|opt|bin|sbin|root|mnt|dev|proc|sys|run)/"
        r"[^\s\"'<>]{2,150})",
        "Unix file paths"
    ),
    "registry_key": (
        r"(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_[A-Z_]+)\\[^\s\"']{4,200}",
        "Windows registry keys"
    ),
    "executable_name": (
        # '.com' only as an 8.3 upper-case DOS name (COMMAND.COM); lower-case
        # 'name.com' is almost always a domain (microsoft.com)
        r"\b(?:[a-zA-Z0-9_\-]{1,60}\.(?:exe|dll|bat|cmd|ps1|vbs|js|wsf|scr|"
        r"pif|msi|jar|hta|cpl|inf|reg|lnk|sys|drv)|(?-i:[A-Z0-9_\-]{1,8}\.COM))\b",
        "Executable/script filenames"
    ),
}

HASH_PATTERNS = {
    "md5_hash": (
        r"\b[a-fA-F0-9]{32}\b",
        "MD5 hashes (32 hex chars)"
    ),
    "sha1_hash": (
        r"\b[a-fA-F0-9]{40}\b",
        "SHA1 hashes (40 hex chars)"
    ),
    "sha256_hash": (
        r"\b[a-fA-F0-9]{64}\b",
        "SHA256 hashes (64 hex chars)"
    ),
}

COMMAND_PATTERNS = {
    "powershell_encoded": (
        r"(?:powershell|pwsh)[^\n]{0,50}-[Ee](?:nc|ncodedCommand)\s+[A-Za-z0-9+/=]{20,}",
        "PowerShell encoded commands"
    ),
    "powershell_download": (
        # word-bounded keywords (the old pattern hit 'IExplorer', 'wGetVersion');
        # wget/curl only when a URL follows
        # short aliases / .NET method names only in call form ('iex (', 'irm http',
        # '.DownloadString(') - bare 'Irm,' / 'downloadData' are minified JS.
        r"(?:\b(?:Invoke-WebRequest|Invoke-Expression|Invoke-RestMethod|Net\.WebClient|"
        r"Start-BitsTransfer)\b|\b(?:IEX|iwr|irm)\s*\(\s*(?:New-Object|\[|\$|'|\")|"
        r"\b(?:IEX|iwr|irm)\s+[\$'\"]|\b(?:iwr|irm|iex)\s+https?://|"
        r"\.Download(?:String|File|Data)(?:Async)?\s*\(|"
        r"\b(?:wget|curl)(?:\.exe)?\s[^\n]{0,60}?(?:https?|ftp)://)"
        r"[^\n]{0,300}",
        "PowerShell download patterns"
    ),
    "cmd_suspicious": (
        r"(?:certutil\s+-urlcache|bitsadmin\s+/transfer|"
        r"wmic\s+process\s+call|schtasks\s+/create|"
        r"reg\s+add|netsh\s+advfirewall|attrib\s+\+h)[^\n]{0,200}",
        "Suspicious cmd.exe commands"
    ),
    "shell_reverse": (
        r"(?:bash\s+-i\s+>&|nc\s+-[elp]|ncat\s+-|"
        r"python[23]?\s+-c\s+['\"]import\s+socket|"
        r"perl\s+-e\s+['\"]use\s+Socket|"
        r"ruby\s+-rsocket)[^\n]{0,200}",
        "Reverse shell patterns"
    ),
}

# Provider token formats are case-SENSITIVE: matching them case-insensitively
# (the global default) turns e.g. "akia..." / "aiza..." text into fake keys.
CASE_SENSITIVE = {
    "aws_access_key", "jwt", "gcp_api_key", "google_oauth_token",
    "azure_storage_key", "azure_client_secret", "github_token", "gitlab_token",
    "slack_token", "slack_webhook", "stripe_key", "openai_key", "anthropic_key",
    "sendgrid_key", "twilio_key", "telegram_bot_token", "bearer_token",
    "private_key_header", "ssh_public_key", "domain",
}


# ASN.1 OID arcs that look like IPv4 in certificate data: 1.2.x.x (ISO member
# body), 1.3.x.x (identified-organization, e.g. 1.3.14.3 = OIW/SHA-1),
# 2.5.x.x (X.500/X.509 attributes+extensions), 2.16.x.x, 2.23.x.x (CA/B).
_OID_ARC = re.compile(r"^(?:1\.[23]\.|2\.(?:5|16|23)\.)\d{1,3}\.\d{1,3}$")

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _btc_valid(addr: str) -> bool:
    """Base58Check (legacy) / bech32 checksum - shape-only regexes matched
    things like '3aaaaaaaaaaaaaaaaaaaaaaaaa3' and '1CPublishWMIOperationEvent'."""
    import hashlib
    if addr.lower().startswith("bc1"):
        CH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
        a = addr.lower()
        if a != addr and a.upper() != addr:
            return False
        hrp, data = a[:2], a[3:]
        if any(c not in CH for c in data) or len(data) < 6:
            return False
        vals = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp] + [CH.index(c) for c in data]
        gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
        chk = 1
        for v in vals:
            b = chk >> 25
            chk = (chk & 0x1ffffff) << 5 ^ v
            for i in range(5):
                chk ^= gen[i] if (b >> i) & 1 else 0
        return chk in (1, 0x2bc830a3)          # bech32 / bech32m
    n = 0
    for c in addr:
        if c not in _B58:
            return False
        n = n * 58 + _B58.index(c)
    raw = n.to_bytes(25, "big") if n.bit_length() <= 200 else b""
    if len(raw) != 25:
        return False
    return hashlib.sha256(hashlib.sha256(raw[:21]).digest()).digest()[:4] == raw[21:]


_TLDS = None


def _tlds():
    global _TLDS
    if _TLDS is None:
        p = Path(__file__).resolve().parent.parent / "data" / "tlds-alpha-by-domain.txt"
        try:
            _TLDS = {l.strip().lower() for l in p.read_text(encoding="utf-8").splitlines()
                     if l.strip() and not l.startswith("#")}
        except OSError:
            _TLDS = set()
    return _TLDS


def _pattern_source(name: str, regex: str) -> str:
    """Pattern text as compiled (case-sensitive ones scoped with (?-i:...))."""
    return f"(?-i:{regex})" if name in CASE_SENSITIVE else regex


# File extensions that are also TLDs: "setup.zip", "install.sh", "clip.mov"
# are file names far more often than domains in memory strings.
_EXT_TLDS = {"zip", "mov", "sh", "run", "app", "page", "tools", "link", "py",
             "pl", "md", "rs", "ps", "cc", "in", "it", "me", "so", "to", "co"}
# Email "TLDs" that are really file extensions (icon@2x.png, lib@1.2.js)
_FILE_EXT = {"png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "bmp", "js",
             "css", "map", "json", "xml", "html", "htm", "dll", "exe", "sys",
             "txt", "log", "dat", "tmp", "bin", "mui", "ttf", "woff", "woff2",
             "pdb", "ini", "cfg", "yml", "yaml", "lock", "ts", "tsx", "jsx"}

# All categories combined with labels
ALL_CATEGORIES = {
    "network":     ("Network Indicators", NETWORK_PATTERNS),
    "email":       ("Email Addresses", EMAIL_PATTERNS),
    "crypto":      ("Cryptocurrency", CRYPTO_PATTERNS),
    "credentials": ("Credentials & Keys", CREDENTIAL_PATTERNS),
    "encoding":    ("Encoded Data", ENCODING_PATTERNS),
    "filesystem":  ("File System", FILESYSTEM_PATTERNS),
    "hashes":      ("Hash Values", HASH_PATTERNS),
    "commands":    ("Suspicious Commands", COMMAND_PATTERNS),
}


# =========================================================================
# EMAIL ARTIFACTS (v2) - full messages, not just addresses
# =========================================================================

_HDR = re.compile(
    r"^(From|To|Cc|Bcc|Subject|Date|Message-ID|Reply-To|Return-Path|Received|"
    r"X-Mailer|User-Agent|X-Originating-IP|Content-Type|Content-Disposition|"
    r"In-Reply-To|References|Sender|Delivered-To|Thread-Topic|Thread-Index|"
    r"X-MS-Exchange-[\w-]+|X-MS-Has-Attach|DKIM-Signature|Authentication-Results|"
    r"MIME-Version|Importance|X-Priority)\s*:\s?(.*)$", re.I)
_ADDR = re.compile(r"[A-Za-z0-9._%+\-']+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}")
_ATTACH = re.compile(r"""\b(?:file)?name\*?=(?:utf-8'')?"?([^";\r\n]{1,200}\.[A-Za-z0-9]{1,8})"?""", re.I)
_ATTACH_EXT = (r"pdf|docx?|docm|xlsx?|xlsm|pptx?|zip|rar|7z|gz|tar|exe|dll|scr|js|"
               r"vbs|hta|html?|txt|csv|rtf|png|jpe?g|gif|iso|img|vhdx?|lnk|one|msg|eml|ics")
_J = {
    "subject": re.compile(r'"(?:subject|Subject|ConversationTopic|title)"\s*:\s*"((?:[^"\\]|\\.){1,300})"'),
    # value may be a plain string or nested objects ({"EmailAddress":{"Address":..}});
    # take the first address after the key without running into the next
    # recipient field.
    "from": re.compile(r'"(?:from|From|sender|Sender)"\s*:\s*(?:(?!"(?:to|To|ToRecipients|toRecipients|cc|Cc|CcRecipients|subject|Subject)")[^\]]){0,300}?'
                       r'([A-Za-z0-9._%+\-\']{1,64}@[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,24})'),
    "to": re.compile(r'"(?:to|To|toRecipients|ToRecipients|recipients)"\s*:\s*(?:(?!"(?:from|From|cc|Cc|subject|Subject|sender)")[^\]]){0,300}?'
                     r'([A-Za-z0-9._%+\-\']{1,64}@[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,24})'),
    "date": re.compile(r'"(?:DateTimeReceived|DateTimeSent|receivedDateTime|sentDateTime|internalDate|date|Date|timestamp)"\s*:\s*"?([0-9][0-9T:\-+. Z]{5,38})'),
    "preview": re.compile(r'"(?:BodyPreview|bodyPreview|snippet|preview|Preview|body|Body|content)"\s*:\s*"((?:[^"\\]|\\.){1,500})"'),
    "attach": re.compile(r'"(?:Name|name|filename|fileName|FileName)"\s*:\s*"([^"]{1,200}\.(?:' + _ATTACH_EXT + r'))"', re.I),
}
# Webmail window/tab titles kept in browser history & window-title memory:
#   https://mail.google.com/mail/u/0/#inbox/FMfcgx...<32>Mega Drive Key - user@gmail.com - Gmail
#   Invoice 4471 - Jane Doe - Outlook   |   Re: offer - Yahoo Mail
_GMAIL_TITLE = re.compile(
    r"(?:mail\.google\.com/mail/u/\d+/#([a-z]+)(?:/[^/\s]*?)?/((?:FMfcg|KtbxL|QgrcJ|WhctK)[A-Za-z0-9]{27}))?"
    r"([^\r\n]{1,200}?) - ([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}) - Gmail")
_OWA_TITLE = re.compile(
    r"([^\r\n]{2,200}?) - ([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}|[^\r\n-]{2,60}?) - Outlook(?:\s|$)")
_YAHOO_TITLE = re.compile(r"([^\r\n]{2,200}?) - (?:([^\r\n-]{2,80}?) - )?Yahoo Mail\b")
_TITLE_SKIP = {"inbox", "sent mail", "drafts", "spam", "trash", "all mail", "starred",
               "important", "mail", "search results", "outbox", "deleted items", "junk email",
               "calendar", "people", "contacts", "settings"}

_MAILTO = re.compile(r"mailto:([^?\s\"'<>]{3,320})(\?[^\s\"'<>]{0,1000})?", re.I)
_PROTO = [
    ("smtp_mail_from", re.compile(r"\bMAIL FROM:\s*<([^>]{0,320})>", re.I)),
    ("smtp_rcpt_to", re.compile(r"\bRCPT TO:\s*<([^>]{1,320})>", re.I)),
    ("smtp_ehlo", re.compile(r"^(?:EHLO|HELO)\s+(\S{3,255})$", re.I)),
    ("smtp_auth", re.compile(r"\bAUTH (LOGIN|PLAIN|XOAUTH2|NTLM|CRAM-MD5)\b(?:\s+(\S{4,}))?")),
    ("imap_fetch", re.compile(r"\b(?:UID )?FETCH [\d:,*]+ \(?[^\r\n]{0,80}(?:BODY|RFC822|ENVELOPE)[^\r\n]{0,120}", re.I)),
    ("imap_login", re.compile(r"^\S{1,10} LOGIN (\S{1,320}) \S+")),
    ("pop3_user", re.compile(r"^USER ([^\s@]{1,64}@?\S{0,253})$")),
    ("mail_server", re.compile(r"(?<![\w.\-])((?:smtp|imap|pop3?|mail|mx\d?|outlook|exchange)\.[a-z0-9.\-]{1,200}\.[a-z]{2,24})(?::(25|465|587|143|993|110|995))?(?![\w\-(]|\.\w)", re.I)),
]


def _proto_ok(kind: str, value: str, m) -> bool:
    """Reject protocol 'traces' that are really code/config noise."""
    if kind != "mail_server" and re.search(r"%(?:\d+\$)?[-+ #0]*\d*[sdiuxXlcp@]|%\d", value):
        return False                                      # printf template: 'USER %s', 'RCPT TO:<%s@%s>'
    if kind == "mail_server":
        host = m.group(1)
        if not (host.islower() or host.isupper()):        # 'mX.prototype', 'MX.prototype'
            return False
        tld = host.rsplit(".", 1)[-1].lower()
        labels = set(host.lower().split("."))
        if labels & {"prototype", "constructor", "exports", "fn", "default", "proto"}:
            return False                                  # minified JS: 'mx.prototype.lb'
        return not _tlds() or tld in _tlds()              # '.prototype', '.useremail'
    if kind in ("pop3_user", "imap_login"):
        u = m.group(1)
        if not u or set(u) <= set("*x") or (u.isupper() and "@" not in u):
            return False                                  # 'USER ***', 'USER PINNED'
        if u[:1].isupper() and u[1:].islower() and u.isalpha():
            return False                                  # plain word: 'USER Objects'
    if kind == "smtp_ehlo":
        return "." in m.group(1)
    return True
_OUTLOOK = [
    ("message_class", re.compile(r"\bIPM\.(?:Note|Schedule\.Meeting|Appointment|Contact|Task)[\w.]*")),
    ("pst_ost_path", re.compile(r"[A-Za-z]:\\[^\r\n\"<>|*?]{1,250}\.(?:pst|ost|nst)\b", re.I)),
    ("eml_msg_path", re.compile(r"[A-Za-z]:\\[^\r\n\"<>|*?]{1,250}\.(?:eml|msg)\b", re.I)),
    ("exchange_header", re.compile(r"\bX-MS-Exchange-[\w-]+:\s?\S[^\r\n]{0,200}")),
]


def _jstr(s: str) -> str:
    try:
        import json as _json
        return _json.loads('"' + s + '"')
    except Exception:
        return s


class EmailArtifactScanner:
    """Streaming e-mail artefact reconstructor (feed it strings lines).

    Memory gives fragments, so every item carries a confidence:
      high   - From + To/Cc + Subject + Date (a near-complete message)
      medium - three of those, or Subject + an address
      low    - partial: two fields / single protocol trace
    Results are de-duplicated (same from/subject/date -> one record with a
    hit count, keeping the most complete copy).
    """

    BODY_LINES = 12

    def __init__(self):
        self.messages: Dict[tuple, Dict] = {}
        self.mailto: Dict[str, Dict] = {}
        self.proto: Dict[tuple, int] = {}
        self.outlook: Dict[tuple, int] = {}
        self._blk: Optional[Dict] = None
        self._since = 0

    # ---- header blocks ----
    def _close(self):
        b, self._blk = self._blk, None
        if not b:
            return
        h = b["h"]
        # Message *templates* in memory (Windows message resources 'From: %1',
        # JS constants 'From: MAIN_MESSAGE_TYPE,') are not e-mails: require a
        # real address in From/To/Cc and drop %n / %s placeholders.
        if not any(_ADDR.search(h.get(k, "")) for k in ("from", "to", "cc")):
            return
        for k in ("from", "to", "cc", "subject", "date"):
            if re.search(r"%\d|%s\b", h.get(k, "")):
                h.pop(k, None)
        key_fields = [k for k in ("from", "to", "subject", "date") if h.get(k)]
        if "cc" in h and "to" not in key_fields:
            key_fields.append("to")
        if len(key_fields) < 2:
            return
        n = len(key_fields)
        conf = "high" if n == 4 else ("medium" if n == 3 or
                                       ("subject" in key_fields and
                                        ("from" in key_fields or "to" in key_fields)) else "low")
        rec = {"kind": "rfc822", "confidence": conf,
               "from": h.get("from", ""), "to": h.get("to", ""), "cc": h.get("cc", ""),
               "subject": h.get("subject", ""), "date": h.get("date", ""),
               "message_id": h.get("message-id", ""),
               "headers": {k: v for k, v in h.items()
                           if k not in ("from", "to", "cc", "subject", "date")},
               "attachments": sorted(b["att"]),
               "body_preview": " | ".join(b["body"])[:800]}
        self._add(rec)

    def _add(self, rec: Dict):
        key = (_ADDR.findall(rec.get("from", "").lower())[:1] and
               _ADDR.findall(rec.get("from", "").lower())[0] or rec.get("from", "").lower().strip(),
               rec.get("subject", "").strip().lower()[:200], rec.get("date", "").strip()[:40])
        old = self.messages.get(key)
        rank = {"high": 3, "medium": 2, "low": 1}
        if old is None:
            rec["seen"] = 1
            self.messages[key] = rec
            return
        old["seen"] += 1
        filled = lambda r: sum(1 for k in ("from", "to", "subject", "date", "body_preview",
                                           "message_id") if r.get(k))
        if (rank[rec["confidence"]], filled(rec)) > (rank[old["confidence"]], filled(old)):
            rec["seen"] = old["seen"]
            rec["attachments"] = sorted(set(old.get("attachments", [])) |
                                        set(rec.get("attachments", [])))
            self.messages[key] = rec
        else:
            old["attachments"] = sorted(set(old.get("attachments", [])) |
                                        set(rec.get("attachments", [])))

    def feed(self, line: str):
        m = _HDR.match(line)
        if m:
            name, val = m.group(1).lower(), m.group(2).strip()
            if self._blk is not None:
                h = self._blk["h"]
                # a key header that repeats after a Subject = the next message
                if name in ("return-path", "from", "date", "subject", "message-id",
                            "to") and "subject" in h and name in h:
                    self._close()
            if self._blk is None:
                self._blk = {"h": {}, "att": set(), "body": []}
            h = self._blk["h"]
            if name in ("received", "dkim-signature", "authentication-results"):
                h.setdefault(name, val[:300])
            elif name not in h:
                h[name] = val[:500]
            if name in ("content-type", "content-disposition"):
                a = _ATTACH.search(val)
                if a:
                    self._blk["att"].add(a.group(1).strip())
            self._since = 0
        elif self._blk is not None:
            a = _ATTACH.search(line)
            if a and ("filename" in line.lower() or "name=" in line.lower()):
                self._blk["att"].add(a.group(1).strip())
            self._since += 1
            if len(self._blk["h"]) >= 2 and len(self._blk["body"]) < self.BODY_LINES \
                    and len(line) >= 6 and not line.startswith(("--", "Content-")):
                self._blk["body"].append(line[:200])
            if self._since > self.BODY_LINES + 8:
                self._close()
        # ---- single-line sources (always) ----
        if '"' in line and ("subject" in line or "Subject" in line or "title" in line):
            self._json(line)
        if "mailto:" in line.lower():
            self._mailto(line)
        if " - Gmail" in line or " - Outlook" in line or "Yahoo Mail" in line:
            self._titles(line)
        for name, rx in _PROTO:
            for mm in rx.finditer(line):
                if not _proto_ok(name, mm.group(0), mm):
                    continue
                k = (name, mm.group(0)[:200])
                self.proto[k] = self.proto.get(k, 0) + 1
        if "IPM." in line or ".pst" in line.lower() or ".ost" in line.lower() or \
                "X-MS-Exchange" in line or ".eml" in line.lower() or ".msg" in line.lower():
            for name, rx in _OUTLOOK:
                for mm in rx.finditer(line):
                    k = (name, mm.group(0)[:260])
                    self.outlook[k] = self.outlook.get(k, 0) + 1

    def _json(self, line: str):
        f = {}
        for k, rx in _J.items():
            if k == "attach":
                f[k] = sorted({x for x in rx.findall(line)})[:20]
                continue
            mm = rx.search(line)
            if mm:
                f[k] = _jstr(mm.group(1))
        if not f.get("subject") or not (f.get("from") or f.get("to")):
            return  # "subject" alone is far too common in unrelated JSON
        n = sum(1 for k in ("from", "to", "subject", "date") if f.get(k))
        low = line.lower()
        src = ("outlook_web" if ("emailaddress" in low or "owa" in low or "outlook" in low) else
               "gmail" if ("snippet" in low or "gmail" in low or "mail.google" in low) else
               "yahoo" if "yahoo" in low else "webmail_json")
        self._add({"kind": src, "confidence": "high" if n == 4 else "medium" if n == 3 else "low",
                   "from": f.get("from", ""), "to": f.get("to", ""), "cc": "",
                   "subject": f.get("subject", ""), "date": f.get("date", ""),
                   "message_id": "", "headers": {}, "attachments": f.get("attach", []),
                   "body_preview": f.get("preview", "")[:800]})

    def _titles(self, line: str):
        """Webmail message titles (subject + mailbox) from tab/window titles."""
        hits = []
        for m in _GMAIL_TITLE.finditer(line):
            folder, mid, subj, acct = m.groups()
            subj = re.sub(r"^.*mail\.google\.com/\S*", "", subj).strip(" -")
            hits.append(("gmail_title", subj, acct, folder or "", mid or ""))
        if not hits:
            for m in _OWA_TITLE.finditer(line):
                hits.append(("outlook_web_title", m.group(1).strip(), m.group(2).strip(), "", ""))
            for m in _YAHOO_TITLE.finditer(line):
                hits.append(("yahoo_title", m.group(1).strip(), (m.group(2) or "").strip(), "", ""))
        for kind, subj, acct, folder, mid in hits:
            s = re.sub(r"^\(\d+\)\s*", "", subj).strip()          # '(3) Inbox' unread counts
            if not s or s.lower() in _TITLE_SKIP or s.lower().startswith(("inbox", "http")):
                continue
            if len(s) < 3 or not re.search(r"[A-Za-z]{2}", s):
                continue
            self._add({"kind": kind, "confidence": "medium" if (mid or "@" in acct) else "low",
                       "from": "", "to": acct, "cc": "", "subject": s[:300], "date": "",
                       "message_id": mid, "headers": {"folder": folder} if folder else {},
                       "attachments": [], "body_preview": ""})

    def _mailto(self, line: str):
        from urllib.parse import parse_qs, unquote
        for mm in _MAILTO.finditer(line):
            to = unquote(mm.group(1))
            if "@" not in to:
                continue
            q = parse_qs((mm.group(2) or "")[1:])
            rec = self.mailto.setdefault(to.lower(), {"to": to, "subject": "", "body": "",
                                                      "cc": "", "seen": 0})
            rec["seen"] += 1
            for k in ("subject", "body", "cc"):
                if q.get(k) and not rec[k]:
                    rec[k] = q[k][0][:500]

    def _collapse_title_fragments(self):
        """Memory holds truncated copies of the same tab title ('Drive Key',
        'Key' for 'Mega Drive Key'): fold a title into a longer one for the
        same mailbox when it is that title's tail (or head)."""
        titles = [(k, r) for k, r in self.messages.items() if r["kind"].endswith("_title")]
        for k, r in titles:
            s = r["subject"]
            for k2, r2 in titles:
                if k2 == k or k2 not in self.messages or k not in self.messages:
                    continue
                s2 = r2["subject"]
                if r2["to"] == r["to"] and len(s2) > len(s) and (s2.endswith(s) or s2.startswith(s)):
                    r2["seen"] = r2.get("seen", 1) + r.get("seen", 1)
                    r2["message_id"] = r2["message_id"] or r["message_id"]
                    del self.messages[k]
                    break

    def finish(self) -> Dict:
        self._close()
        self._collapse_title_fragments()
        order = {"high": 0, "medium": 1, "low": 2}
        msgs = sorted(self.messages.values(),
                      key=lambda r: (order[r["confidence"]], -r.get("seen", 1)))
        proto = [{"type": k[0], "value": k[1], "seen": n} for k, n in
                 sorted(self.proto.items(), key=lambda x: -x[1])][:2000]
        outl = [{"type": k[0], "value": k[1], "seen": n} for k, n in
                sorted(self.outlook.items(), key=lambda x: -x[1])][:2000]
        by = {c: sum(1 for m in msgs if m["confidence"] == c) for c in order}
        return {"messages": msgs, "mailto": list(self.mailto.values()),
                "protocol": proto, "outlook": outl,
                "summary": {"messages": len(msgs), "by_confidence": by,
                            "mailto": len(self.mailto), "protocol_traces": len(proto),
                            "outlook_artifacts": len(outl)}}


def write_email_artifacts(output_dir: Path, res: Dict, source: str) -> None:
    import json as _json
    od = Path(output_dir)
    (od / "json").mkdir(parents=True, exist_ok=True)
    records = []
    for m in res["messages"]:
        records.append({"confidence": m["confidence"], "kind": m["kind"],
                        "date": m["date"], "from": m["from"], "to": m["to"],
                        "cc": m.get("cc", ""), "subject": m["subject"],
                        "attachments": ", ".join(m.get("attachments", [])),
                        "body_preview": m.get("body_preview", "")[:300],
                        "message_id": m.get("message_id", ""), "seen": m.get("seen", 1)})
    for t in res["mailto"]:
        records.append({"confidence": "medium", "kind": "mailto", "date": "", "from": "",
                        "to": t["to"], "cc": t["cc"], "subject": t["subject"],
                        "attachments": "", "body_preview": t["body"][:300],
                        "message_id": "", "seen": t["seen"]})
    doc = {"type": "email_artifacts", "category": "email", "source": source,
           "description": "E-mail messages / fragments reconstructed from memory strings",
           "summary": res["summary"], "count": len(records), "records": records,
           "protocol": res["protocol"], "outlook": res["outlook"]}
    (od / "json" / "email_artifacts.json").write_text(
        _json.dumps(doc, indent=2, default=str), encoding="utf-8")
    with open(od / "email_artifacts.txt", "w", encoding="utf-8") as f:
        s = res["summary"]
        f.write(f"E-MAIL ARTIFACTS  messages={s['messages']} {s['by_confidence']} "
                f"mailto={s['mailto']} protocol={s['protocol_traces']} "
                f"outlook={s['outlook_artifacts']}\n\n")
        for m in res["messages"]:
            f.write(f"[{m['confidence'].upper()}] ({m['kind']}, seen {m.get('seen', 1)}x)\n")
            for k in ("date", "from", "to", "cc", "subject", "message_id"):
                if m.get(k):
                    f.write(f"  {k:10s}: {m[k]}\n")
            if m.get("attachments"):
                f.write(f"  attachments: {', '.join(m['attachments'])}\n")
            if m.get("body_preview"):
                f.write(f"  body      : {m['body_preview'][:400]}\n")
            f.write("\n")
        if res["protocol"]:
            f.write("PROTOCOL TRACES (SMTP/IMAP/POP3):\n")
            for p in res["protocol"][:300]:
                f.write(f"  {p['type']:15s} x{p['seen']:<4d} {p['value']}\n")
        if res["outlook"]:
            f.write("\nOUTLOOK / MAIL-STORE ARTIFACTS:\n")
            for p in res["outlook"][:300]:
                f.write(f"  {p['type']:15s} x{p['seen']:<4d} {p['value']}\n")


class IOCExtractor:
    """Extract Indicators of Compromise from text files.

    Patterns are organized by category and can be individually enabled/disabled.
    Results are saved as one file per pattern type plus a summary report.
    """

    def __init__(self, logger: logging.Logger,
                 categories: Optional[List[str]] = None):
        """Initialize the IOC extractor.

        Args:
            logger: Logger instance.
            categories: List of category names to enable. None = all.
                        Options: network, email, crypto, credentials,
                                 encoding, filesystem, hashes, commands
        """
        self.log = logger

        # Build active pattern set
        self._patterns: Dict[str, Tuple[re.Pattern, str, str]] = {}

        if categories is None:
            active_cats = list(ALL_CATEGORIES.keys())
        else:
            active_cats = [c for c in categories if c in ALL_CATEGORIES]

        for cat_name in active_cats:
            cat_label, patterns = ALL_CATEGORIES[cat_name]
            for pat_name, (regex, desc) in patterns.items():
                try:
                    compiled = re.compile(_pattern_source(pat_name, regex),
                                          re.IGNORECASE)
                    self._patterns[pat_name] = (compiled, desc, cat_name)
                except re.error as e:
                    self.log.warning("Bad regex for %s: %s", pat_name, e)

        self.log.debug("IOC Extractor: %d patterns across %d categories",
                       len(self._patterns), len(active_cats))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract_from_file(self, input_file: Path, output_dir: Path,
                          line_callback=None, line_scanners=None,
                          ) -> Dict[str, int]:
        """Scan a text file for IOC patterns.

        Args:
            input_file: Path to the text file (e.g. strings.txt).
            output_dir: Directory to save IOC result files.
            line_callback: Optional callable(line_str) invoked for each line.
                          Allows piggy-backing another scanner (e.g. browser
                          history) on the same file read — zero extra I/O.
            line_scanners: Optional list of scanner objects with a
                          `_process_line(line)` method (v2.4). Same job as
                          line_callback, but on big files each scanner runs in
                          its own process, side by side with the IOC pattern
                          scan, and its state is copied back into the object.
                          Results are identical to the serial loop.

        Returns:
            Dict mapping pattern_name to count of unique matches.
        """
        input_file = Path(input_file)
        output_dir = Path(output_dir)

        if not input_file.exists():
            self.log.error("Input file not found: %s", input_file)
            return {}

        output_dir.mkdir(parents=True, exist_ok=True)
        self.log.info("IOC scan: %s (%d patterns)", input_file.name,
                      len(self._patterns))

        start = time.time()
        line_count = 0

        # v2: e-mail artefact reconstruction rides on the same streaming pass
        email_scan = (EmailArtifactScanner()
                      if any(c == "email" for _p, _d, c in self._patterns.values())
                      else None)

        line_scanners = list(line_scanners or [])
        workers = min(max(1, os.cpu_count() or 4), 8)
        chunks = _file_chunk_boundaries(input_file, workers)
        pat_specs = [(name, regex.pattern)   # already (?-i:)-scoped where needed
                     for name, (regex, _d, _c) in self._patterns.items()]
        task_args = [(str(input_file), s, e, pat_specs) for s, e in chunks]
        found: Dict[str, Set[str]] = {}
        pass2_done = False

        # v2.4 fast path: the stateful line scanners (each in its own process, each
        # reading the file in order) run at the same time as the pattern scan.
        # The old loop fed them one line at a time in this process (79 s of a 96 s
        # scan on a 2 GB dump) while the 8 pattern workers waited for it to end.
        par = [(o, "_process_line") for o in line_scanners]
        if email_scan is not None:
            par.append((email_scan, "feed"))
        use_parallel = (
            bool(par) and line_callback is None
            and os.environ.get("RAMBREAKER_SERIAL_SCAN") != "1"
            and (os.cpu_count() or 1) >= 4
            and input_file.stat().st_size >= PARALLEL_SCAN_MIN_BYTES)
        if use_parallel:
            try:
                from concurrent.futures import ProcessPoolExecutor
                with ProcessPoolExecutor(max_workers=len(chunks) + len(par)) as pool:
                    lfuts = [pool.submit(_mp_line_scanner, (str(input_file), o, m))
                             for o, m in par]
                    cfuts = [pool.submit(_mp_scan_file_chunk, a) for a in task_args]
                    ldone = [f.result() for f in lfuts]
                    cdone = [f.result() for f in cfuts]
                for (o, _m), (done, n) in zip(par, ldone):
                    _adopt_state(o, done)
                    line_count = n
                for chunk_result in cdone:
                    for name, matches in chunk_result.items():
                        found.setdefault(name, set()).update(matches)
                pass2_done = True
                self.log.info("Line scanners + pattern scan ran in parallel (%d + %d processes)",
                              len(par), len(chunks))
                if email_scan:
                    try:
                        eres = email_scan.finish()
                        write_email_artifacts(output_dir, eres, input_file.name)
                        self.log.info("  [email] artefacts: %s", eres["summary"])
                    except Exception as e:
                        self.log.warning("E-mail artefact pass failed: %s", e)
            except Exception as exc:
                # nothing was adopted yet, so the serial loop below starts clean
                self.log.warning("Parallel line scan failed (%s) - using the serial loop", exc)
                found = {}
                line_count = 0
                use_parallel = False
        if not use_parallel and line_scanners:
            _prev_cb = line_callback

            def line_callback(line, _prev=_prev_cb, _objs=tuple(line_scanners)):
                if _prev:
                    _prev(line)
                for o in _objs:
                    o._process_line(line)

        # Pass 1 — streaming: fire piggyback callbacks (browser/comms) line by line.
        # Nothing is stored in RAM; this is O(1) memory regardless of file size.
        if not use_parallel and (line_callback or email_scan):
            try:
                with open(input_file, "r", encoding="utf-8", errors="ignore") as fh:
                    for raw in fh:
                        line = raw.strip()
                        if not line or len(line) < 4:
                            continue
                        line_count += 1
                        if line_callback:
                            line_callback(line)
                        if email_scan:
                            email_scan.feed(line)
            except OSError as e:
                self.log.error("Error reading %s: %s", input_file, e)
                return {}
            if email_scan:
                try:
                    eres = email_scan.finish()
                    write_email_artifacts(output_dir, eres, input_file.name)
                    self.log.info("  [email] artefacts: %s", eres["summary"])
                except Exception as e:
                    self.log.warning("E-mail artefact pass failed: %s", e)

        # Pass 2 — parallel IOC scan over file-byte-range chunks.
        # Workers open the file themselves so no large data crosses the pipe
        # and there is no COW pressure from a forked lines list.
        try:
            # ProcessPoolExecutor (not multiprocessing.Pool): if a worker dies,
            # Pool silently respawns and can hang forever; the executor raises
            # BrokenProcessPool so the single-thread fallback below takes over.
            from concurrent.futures import ProcessPoolExecutor
            if not pass2_done:
                with ProcessPoolExecutor(max_workers=len(chunks)) as pool:
                    for chunk_result in pool.map(_mp_scan_file_chunk, task_args):
                        for name, matches in chunk_result.items():
                            found.setdefault(name, set()).update(matches)
        except Exception as exc:
            self.log.warning("Multiprocessing scan failed (%s) — falling back to single thread", exc)
            try:
                with open(input_file, "r", encoding="utf-8", errors="ignore") as fh:
                    for raw in fh:
                        line = raw.strip()
                        if not line or len(line) < 4:
                            continue
                        for name, (regex, _d, _c) in self._patterns.items():
                            for m in regex.findall(line):
                                found.setdefault(name, set()).add(
                                    m[0] if isinstance(m, tuple) else m)
            except OSError as e:
                self.log.error("Fallback scan failed: %s", e)
                return {}

        if not line_count:
            # no callback pass — count wasn't tracked; use a fast line count
            try:
                with open(input_file, "rb") as fh:
                    line_count = sum(1 for _ in fh)
            except OSError:
                line_count = 0

        duration = time.time() - start
        self.log.info("Scanned %d lines in %.1fs", line_count, duration)

        # Write results per pattern
        counts: Dict[str, int] = {}
        for name, matches in found.items():
            if not matches:
                continue

            # Filter false positives for certain patterns
            matches = self._filter_matches(name, matches)
            if not matches:
                continue

            counts[name] = len(matches)
            _, desc, cat = self._patterns[name]

            # TXT output
            out_path = output_dir / f"ioc_{name}.txt"
            with open(out_path, "w", encoding="utf-8") as fh:
                fh.write(f"# IOC Type: {desc}\n")
                fh.write(f"# Category: {cat}\n")
                fh.write(f"# Count: {len(matches)}\n")
                fh.write(f"# Source: {input_file.name}\n")
                fh.write("#" + "-" * 60 + "\n")
                for m in sorted(matches):
                    fh.write(m + "\n")

            # Individual JSON output per IOC type
            import json as _json
            json_dir = output_dir / "json"
            json_dir.mkdir(parents=True, exist_ok=True)
            json_out = json_dir / f"ioc_{name}.json"
            json_out.write_text(
                _json.dumps({
                    "type": name,
                    "description": desc,
                    "category": cat,
                    "count": len(matches),
                    "source": input_file.name,
                    "values": sorted(matches),
                }, indent=2, default=str),
                encoding="utf-8")

            self.log.info("  [%s] %s: %d unique", cat, name, len(matches))

        # Write JSON results
        self._write_json_results(output_dir, found, input_file, counts,
                                  line_count, duration)

        # Write summary report
        self._write_summary(output_dir, input_file, counts, line_count, duration)

        if not counts:
            self.log.info("  No IOCs found")

        return counts

    def extract_from_directory(self, input_dir: Path, output_dir: Path,
                               extensions: Optional[Set[str]] = None,
                               ) -> Dict[str, int]:
        """Scan all text files in a directory for IOCs.

        Args:
            input_dir: Directory containing text files.
            output_dir: Directory to save results.
            extensions: File extensions to scan (default: .txt).

        Returns:
            Aggregated dict of pattern_name -> total count.
        """
        if extensions is None:
            extensions = {".txt"}

        input_dir = Path(input_dir)
        output_dir = Path(output_dir)

        if not input_dir.is_dir():
            self.log.error("Input directory not found: %s", input_dir)
            return {}

        import json as _json
        # Accumulate all matches across every txt file before writing JSON,
        # so ioc_*.json reflects the combined dataset, not just the last file.
        combined: Dict[str, Set[str]] = {name: set() for name in self._patterns}
        total_counts: Dict[str, int] = {}
        files_scanned = 0

        for fp in sorted(input_dir.iterdir()):
            if fp.suffix.lower() not in extensions or not fp.is_file():
                continue
            files_scanned += 1
            try:
                with open(fp, "r", encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line or len(line) < 4:
                            continue
                        for name, (regex, _, _cat) in self._patterns.items():
                            for m in regex.findall(line):
                                combined[name].add(m[0] if isinstance(m, tuple) else m)
            except OSError:
                pass

        # Filter and write combined results
        json_dir = output_dir / "json"
        json_dir.mkdir(parents=True, exist_ok=True)
        output_dir.mkdir(parents=True, exist_ok=True)
        for name, matches in combined.items():
            matches = self._filter_matches(name, matches)
            if not matches:
                continue
            _, desc, cat = self._patterns[name]
            total_counts[name] = len(matches)
            # TXT
            out_path = output_dir / f"ioc_{name}.txt"
            with open(out_path, "w", encoding="utf-8") as fh:
                fh.write(f"# IOC Type: {desc}\n# Category: {cat}\n")
                fh.write(f"# Count: {len(matches)}\n# Source: {input_dir.name}/\n")
                fh.write("#" + "-" * 60 + "\n")
                for m in sorted(matches):
                    fh.write(m + "\n")
            # JSON
            (json_dir / f"ioc_{name}.json").write_text(
                _json.dumps({"type": name, "description": desc, "category": cat,
                             "count": len(matches), "source": str(input_dir.name),
                             "values": sorted(matches)}, indent=2, default=str),
                encoding="utf-8")

        self.log.info("IOC scan complete: %d files, %d pattern types found",
                      files_scanned, len(total_counts))
        return total_counts

    def scan_single_string(self, text: str) -> List[Dict[str, str]]:
        """Check a single string against all IOC patterns.

        Args:
            text: The string to check.

        Returns:
            List of dicts with 'pattern', 'match', 'category', 'description'.
        """
        results = []
        for name, (regex, desc, cat) in self._patterns.items():
            for match in regex.findall(text):
                if isinstance(match, tuple):
                    match = match[0]
                if not self._is_valid_match(name, match):
                    continue
                results.append({
                    "pattern": name,
                    "match": match,
                    "category": cat,
                    "description": desc,
                })
        return results

    # ------------------------------------------------------------------
    # Filtering
    # ------------------------------------------------------------------


    @staticmethod
    def _ipv4_class(ip: str) -> Optional[str]:
        """Return classful IPv4 class A/B/C/D/E, or None if invalid.

        CresCent only keeps class A/B/C unicast addresses as IOC candidates.
        Class D multicast and Class E reserved/experimental addresses are
        filtered out, and 0.x/127.x special ranges are not treated as IOCs.
        """
        try:
            addr = ipaddress.IPv4Address(ip)
        except ipaddress.AddressValueError:
            return None

        first = int(str(addr).split(".", 1)[0])
        if 1 <= first <= 126:
            return "A"
        if 128 <= first <= 191:
            return "B"
        if 192 <= first <= 223:
            return "C"
        if 224 <= first <= 239:
            return "D"
        if 240 <= first <= 255:
            return "E"
        return None

    @classmethod
    def _is_valid_ipv4_ioc(cls, ip: str) -> bool:
        """Validate an IPv4 IOC candidate after regex extraction."""
        try:
            addr = ipaddress.IPv4Address(ip)
        except ipaddress.AddressValueError:
            return False

        # Reject non-canonical dotted decimals such as 001.002.003.004.
        # ipaddress already rejects these on modern Python, but keep the
        # explicit string check for clarity and older runtime behavior.
        if str(addr) != ip:
            return False

        ip_class = cls._ipv4_class(ip)
        if ip_class not in {"A", "B", "C"}:
            return False

        # Keep private A/B/C ranges because internal IPs can matter in RAM
        # forensics. Drop special-purpose noise that is rarely useful as IOC
        # evidence in strings output.
        if (addr.is_unspecified or addr.is_loopback or addr.is_multicast or
                addr.is_reserved or addr.is_link_local or
                addr == ipaddress.IPv4Address("255.255.255.255")):
            return False

        return True

    @staticmethod
    def _is_valid_ipv6_ioc(ip: str) -> bool:
        """Validate an IPv6 IOC candidate after regex extraction."""
        try:
            addr = ipaddress.IPv6Address(ip)
        except ipaddress.AddressValueError:
            return False

        if (addr.is_unspecified or addr.is_loopback or addr.is_multicast or
                addr.is_link_local or addr.is_reserved):
            return False

        return True

    @staticmethod
    def _plausible_domain(d: str) -> bool:
        """Reject code identifiers / filenames that merely end in a TLD.

        - case: real hostnames in memory are lower (or all upper) case;
          'System.Net', 'Microsoft.CSharp.Foo' are .NET namespaces.
        - extension-TLDs (.zip/.sh/.mov/...): need 3+ labels or www.
        - labels must not start/end with '-' and the name must have a letter.
        """
        # TLD case is enforced by the (case-sensitive) regex; here reject
        # camelCase labels ("CSharp", "WebClient") = code identifiers.
        if re.search(r"[a-z][A-Z]", d):
            return False
        dl = d.lower().rstrip(".")
        labels = dl.split(".")
        if len(labels) < 2 or any(not l or l[0] == "-" or l[-1] == "-" for l in labels):
            return False
        if labels[-1] in _EXT_TLDS and len(labels) < 3 and labels[0] != "www":
            return False
        if all(ch.isdigit() or ch == "." for ch in dl):
            return False
        return True

    @staticmethod
    def _plausible_email(e: str) -> bool:
        local, _, dom = e.rpartition("@")
        if not local or not dom or "." not in dom:
            return False
        tld = dom.rsplit(".", 1)[-1].lower()
        if tld in _FILE_EXT or not tld.isalpha() or len(tld) > 24:
            return False
        if _tlds() and tld not in _tlds():          # 'Brontok@mm.gen' (AV name)
            return False
        if not (dom.islower() or dom.isupper()):    # 'E@d.EAd', 'BA@5Dh.Fh.Gh'
            return False
        if len(dom.split(".")[0]) < 2 or (len(local) < 2 and len(dom) < 8):
            return False                            # 'W@Q.ny'
        if local.startswith(".") or local.endswith(".") or ".." in local:
            return False
        first = dom.split(".")[0]
        if first.isdigit() and len(first) <= 2:   # "@2x.png" style asset names
            return False
        return True

    @staticmethod
    def _plausible_token(t: str) -> bool:
        """Drop low-entropy / repetitive strings that only look like tokens."""
        body = t.replace(".", "").replace("-", "").replace("_", "")
        return len(set(body)) >= 12

    def _is_valid_match(self, name: str, match: str) -> bool:
        """Run pattern-specific validation before returning a match."""
        if name == "ipv4":
            return self._is_valid_ipv4_ioc(match)
        if name == "ipv6":
            return self._is_valid_ipv6_ioc(match)
        return True

    def _filter_matches(self, name: str, matches: Set[str]) -> Set[str]:
        """Remove common false positives for specific pattern types.

        Args:
            name: Pattern name.
            matches: Set of raw matches.

        Returns:
            Filtered set.
        """
        if name == "ipv4":
            return {ip for ip in matches if self._is_valid_ipv4_ioc(ip)
                    and not _OID_ARC.match(ip)}

        if name == "ipv6":
            return {ip for ip in matches if self._is_valid_ipv6_ioc(ip)}

        if name in ("md5_hash", "sha1_hash", "sha256_hash"):
            # Real digests are uniformly random hex: they contain both digits
            # and a-f letters (all-digit 32 hex chars has p~3e-7) and many
            # distinct symbols. Drops 0000..., 7777555544443333..., decimal runs.
            need = {"md5_hash": 7, "sha1_hash": 8, "sha256_hash": 9}[name]
            return {h for h in matches
                    if len(set(h.lower())) >= need
                    and any(c.isdigit() for c in h) and any(c.isalpha() for c in h)
                    and not re.search(r"(.)\1{5,}", h)}

        if name in ("bitcoin_address", "bitcoin_bech32"):
            return {a for a in matches if _btc_valid(a)}

        if name == "password_in_url":
            out = set()
            for p in matches:
                val = re.split(r"[=:]", p, 1)[1] if re.search(r"[=:]", p) else ""
                if (not val or val.startswith(":") or "%" in val
                        # JS/code, not a value: 'PASS:()=>x', 'password:t.password}'
                        or re.search(r"[(){};\[\]]|=>|===", val)
                        or re.match(r"=|!\d|!?[01],", val)          # 'PASS===void', '!0,'
                        or re.search(r",[A-Za-z_$][\w$]*:", val)    # JS object literal 'a:1,b:'
                        or re.search(r"[A-Za-z]:$", val)            # ObjC selector 'Pass:error:'
                        or re.match(r"[a-z]\w*:[A-Za-z]", val)      # 'Pass:forView:withX:'
                        # shell $PWD is the working directory, not a password
                        or (p[:3].lower() == "pwd" and re.match(r"(?:/|~|[A-Za-z]:\\)", val))
                        or re.match(r"[A-Za-z_$][\w$]*\.[A-Za-z_$]", val)
                        or re.fullmatch(r"(?:IDC?_|IDS_|IDM_)?[A-Z][A-Z0-9_]{2,}", val)
                        or val.lower() in ("null", "none", "true", "false", "password")):
                    continue
                out.add(p)
            return out

        if name == "aws_secret_key":
            # Even with the context anchor, validate that the captured value
            # isn't actually a SHA1 hash (pure hex) — that's a different
            # IOC type and shouldn't double-report here.
            filtered = set()
            for k in matches:
                # Pure-hex 40-char strings are SHA1 hashes, not AWS secrets
                if re.fullmatch(r"[0-9a-fA-F]{40}", k):
                    continue
                # Real AWS secrets are base64-ish: contain mix of cases + digits
                # and usually at least one '/' or '+' or non-hex letter.
                has_lower = any(c.islower() and c not in "abcdef" for c in k)
                has_upper = any(c.isupper() and c not in "ABCDEF" for c in k)
                has_special = any(c in "/+" for c in k)
                if not (has_lower or has_upper or has_special):
                    continue
                filtered.add(k)
            return filtered

        if name == "domain":
            # Remove obvious non-domains
            boring_prefixes = ("www.w3.org", "schemas.microsoft.com",
                               "schemas.openxmlformats.org", "purl.org",
                               "ns.adobe.com", "xml.org", "relaxng.org")
            return {d for d in matches
                    if not any(d.startswith(b) for b in boring_prefixes)
                    and self._plausible_domain(d)}

        if name == "email":
            return {e for e in matches if self._plausible_email(e)}

        if name in ("jwt", "bearer_token"):
            # a token starts with an alphanumeric ('Bearer /type.googleapis.com'
            # is a URL path, not a credential)
            return {t for t in matches if t[:1].isalnum() and self._plausible_token(t)}

        if name in ("unc_path", "windows_path"):
            # Regex / escaped-string source looks path-like: '\\.\\d', 'e:\d+',
            # 'I:\n\n1.', '\\Anthropic\\Messages'. A backslash followed by an
            # escape letter and then a non-alnum is an escape, not a folder.
            esc = re.compile(r"\\[dDwWsSbBnrtuxv](?![A-Za-z0-9])|\\[()\[\]{}+*?^$|]")
            out = set()
            for p in matches:
                if name == "unc_path":
                    m = re.match(r"\\\\([^\\]+)\\(.*)", p)
                    if not m:
                        continue
                    srv, rest = m.group(1), m.group(2)
                    if not (srv == "." or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}", srv)):
                        continue
                    if not re.match(r"[A-Za-z0-9_$]", rest) or esc.search(rest):
                        continue
                    # JS-escaped text: '\\u003E\x22,...' (one '\x86\' may be a real folder)
                    if (re.search(r"\\u[0-9a-fA-F]{4}", p)
                            or len(re.findall(r"\\x[0-9a-fA-F]{2}", p)) >= 2):
                        continue
                    # binary noise: Windows-illegal path chars, empty components,
                    # or punctuation-dense
                    if re.search(r'[|^`<>"*?]', rest) or "\\\\" in rest or (
                            sum(c.isalnum() or c in "\\._- $" for c in rest) < 0.9 * len(rest)):
                        continue
                else:
                    rest = p[3:]
                    if esc.search(p[2:]) or not re.search(r"[A-Za-z]{2}", rest):
                        continue
                    if re.search(r'[|^`<>"*?]', rest) or "\\\\" in rest:   # illegal chars / empty component
                        continue
                out.add(p)
            return out

        if name == "api_token":
            # 'apiKey:process.env.X', 'ApiKey = Environment.GetEnv...' are code,
            # not secrets: a real key value mixes digits and letters.
            out = set()
            for t in matches:
                if re.match(r"\w+::", t):                 # Perl/C++ namespace 'Token::HereDoc'
                    continue
                v = re.split(r"[\"':\s=]+", t, maxsplit=1)[-1]
                if (re.search(r"\d", v) and re.search(r"[A-Za-z]", v)
                        and self._plausible_token(v)):
                    out.add(t)
            return out

        if name == "executable_name":
            # Remove common Windows system files that are just noise
            boring_exes = {"ntdll.dll", "kernel32.dll", "user32.dll",
                           "advapi32.dll", "msvcrt.dll", "ws2_32.dll",
                           "shell32.dll", "ole32.dll", "gdi32.dll",
                           "shlwapi.dll", "comctl32.dll"}
            return {e for e in matches if e.lower() not in boring_exes}

        return matches

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def _write_summary(self, output_dir: Path, source: Path,
                       counts: Dict[str, int], lines: int,
                       duration: float) -> None:
        """Write an IOC summary report."""
        summary_path = output_dir / "ioc_summary.txt"
        with open(summary_path, "w", encoding="utf-8") as f:
            f.write("=" * 60 + "\n")
            f.write("  IOC EXTRACTION SUMMARY\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"  Source:    {source}\n")
            f.write(f"  Lines:     {lines:,}\n")
            f.write(f"  Duration:  {duration:.1f}s\n")
            f.write(f"  Patterns:  {len(self._patterns)}\n\n")

            if counts:
                # Group by category
                by_cat: Dict[str, List[Tuple[str, int]]] = {}
                for name, count in sorted(counts.items(), key=lambda x: -x[1]):
                    _, desc, cat = self._patterns[name]
                    by_cat.setdefault(cat, []).append((name, count, desc))

                for cat_name, cat_items in by_cat.items():
                    cat_label = dict(
                        (k, v[0]) for k, v in ALL_CATEGORIES.items()
                    ).get(cat_name, cat_name)
                    f.write(f"  --- {cat_label} ---\n")
                    for name, count, desc in cat_items:
                        f.write(f"    {name:30s} {count:>6d}   ({desc})\n")
                    f.write("\n")

                total = sum(counts.values())
                f.write(f"  TOTAL: {total:,} unique IOCs across "
                        f"{len(counts)} pattern types\n")
            else:
                f.write("  No IOCs found.\n")

            f.write("\n" + "=" * 60 + "\n")
            f.write("  Files generated:\n")
            for name in sorted(counts.keys()):
                f.write(f"    ioc_{name}.txt\n")
            f.write("  ioc_summary.txt (this file)\n")
            f.write("=" * 60 + "\n")

    # ------------------------------------------------------------------
    # Category info (for UI)
    # ------------------------------------------------------------------

    @staticmethod
    def list_categories() -> Dict[str, Tuple[str, int]]:
        """Return available categories with label and pattern count.

        Returns:
            Dict of category_name -> (label, pattern_count)
        """
        result = {}
        for cat_name, (cat_label, patterns) in ALL_CATEGORIES.items():
            result[cat_name] = (cat_label, len(patterns))
        return result

    @staticmethod
    def list_all_patterns() -> List[Dict[str, str]]:
        """Return all available patterns with metadata.

        Returns:
            List of dicts with 'name', 'category', 'description'.
        """
        result = []
        for cat_name, (cat_label, patterns) in ALL_CATEGORIES.items():
            for pat_name, (regex, desc) in patterns.items():
                result.append({
                    "name": pat_name,
                    "category": cat_name,
                    "category_label": cat_label,
                    "description": desc,
                })
        return result

    def _write_json_results(self, output_dir, found, input_file, counts,
                            line_count, duration):
        """Write all IOC results as a single JSON file.

        Creates ioc_results.json with all matches grouped by category.
        """
        import json as _json

        json_path = Path(output_dir) / "ioc_results.json"
        report = {
            "source": str(input_file),
            "lines_scanned": line_count,
            "duration_seconds": round(duration, 2),
            "total_iocs": sum(counts.values()) if counts else 0,
            "pattern_counts": counts,
            "categories": {},
            "results": {},
        }

        for name, matches in found.items():
            if not matches:
                continue
            matches = self._filter_matches(name, matches)
            if not matches:
                continue
            _, desc, cat = self._patterns[name]
            report["results"][name] = {
                "description": desc,
                "category": cat,
                "count": len(matches),
                "values": sorted(matches),
            }
            # Category summary
            if cat not in report["categories"]:
                cat_label = dict(
                    (k, v[0]) for k, v in ALL_CATEGORIES.items()
                ).get(cat, cat)
                report["categories"][cat] = {"label": cat_label, "patterns": {}}
            report["categories"][cat]["patterns"][name] = len(matches)

        json_path.write_text(
            _json.dumps(report, indent=2, default=str), encoding="utf-8")
        self.log.info("IOC JSON: %s", json_path)
