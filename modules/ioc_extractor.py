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
        with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
            fh.seek(start)
            while fh.tell() < end:
                line = fh.readline()
                if not line:
                    break
                line = line.strip()
                if not line or len(line) < 4:
                    continue
                for name, regex in compiled:
                    for m in regex.findall(line):
                        val = m[0] if isinstance(m, tuple) else m
                        found.setdefault(name, set()).add(val)
    except OSError:
        pass
    return {n: list(v) for n, v in found.items()}


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
        r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b",
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
        r"\b[a-zA-Z0-9_\-]{1,60}\.(?:exe|dll|bat|cmd|ps1|vbs|js|wsf|scr|"
        r"com|pif|msi|jar|hta|cpl|inf|reg|lnk|sys|drv)\b",
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
        r"(?:Invoke-WebRequest|Invoke-Expression|IEX|"
        r"Net\.WebClient|DownloadString|DownloadFile|"
        r"Start-BitsTransfer|wget|curl)[^\n]{0,300}",
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
                    compiled = re.compile(regex, re.IGNORECASE)
                    self._patterns[pat_name] = (compiled, desc, cat_name)
                except re.error as e:
                    self.log.warning("Bad regex for %s: %s", pat_name, e)

        self.log.debug("IOC Extractor: %d patterns across %d categories",
                       len(self._patterns), len(active_cats))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract_from_file(self, input_file: Path, output_dir: Path,
                          line_callback=None,
                          ) -> Dict[str, int]:
        """Scan a text file for IOC patterns.

        Args:
            input_file: Path to the text file (e.g. strings.txt).
            output_dir: Directory to save IOC result files.
            line_callback: Optional callable(line_str) invoked for each line.
                          Allows piggy-backing another scanner (e.g. browser
                          history) on the same file read — zero extra I/O.

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

        # Pass 1 — streaming: fire piggyback callbacks (browser/comms) line by line.
        # Nothing is stored in RAM; this is O(1) memory regardless of file size.
        if line_callback:
            try:
                with open(input_file, "r", encoding="utf-8", errors="ignore") as fh:
                    for raw in fh:
                        line = raw.strip()
                        if not line or len(line) < 4:
                            continue
                        line_count += 1
                        line_callback(line)
            except OSError as e:
                self.log.error("Error reading %s: %s", input_file, e)
                return {}

        # Pass 2 — parallel IOC scan over file-byte-range chunks.
        # Workers open the file themselves so no large data crosses the pipe
        # and there is no COW pressure from a forked lines list.
        workers = min(max(1, os.cpu_count() or 4), 8)
        chunks = _file_chunk_boundaries(input_file, workers)
        pat_specs = [(name, regex.pattern)
                     for name, (regex, _d, _c) in self._patterns.items()]
        task_args = [(str(input_file), s, e, pat_specs) for s, e in chunks]

        found: Dict[str, Set[str]] = {}
        try:
            with _mp.Pool(processes=len(chunks)) as pool:
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
            return {ip for ip in matches if self._is_valid_ipv4_ioc(ip)}

        if name == "ipv6":
            return {ip for ip in matches if self._is_valid_ipv6_ioc(ip)}

        if name == "md5_hash":
            # MD5 is 32 hex chars -- overlaps with many things
            # Only keep if it looks like a standalone hash (not part of a path etc.)
            filtered = set()
            for h in matches:
                # Skip if all same char (like "00000000...") or fewer than
                # 4 distinct hex characters
                if len(set(h.lower())) <= 3:
                    continue
                filtered.add(h)
            return filtered

        if name in ("sha1_hash", "sha256_hash"):
            # Same low-variety filter as md5_hash. Catches 0000...00 / ffff...ff /
            # repeating-pattern noise that survives the regex but is obviously
            # not a real digest. Threshold of 4 distinct hex chars keeps
            # cryptographic hashes (which have ~16 distinct chars on average)
            # while dropping placeholder strings.
            filtered = set()
            for h in matches:
                if len(set(h.lower())) <= 3:
                    continue
                filtered.add(h)
            return filtered

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
                    if not any(d.startswith(b) for b in boring_prefixes)}

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
