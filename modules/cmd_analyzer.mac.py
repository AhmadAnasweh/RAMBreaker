"""cmd_analyzer.mac.py — macOS-specific command analyzer (v6.0)

Contains macOS CMD_PATTERNS, SUSPICIOUS_CHAINS, MITRE_TECHNIQUES,
CommandAnalyzer, and MitreMapper for macOS memory images.
"""

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from utils.json_converter import load_json_by_pattern


def _gv(item, *keys):
    for k in keys:
        if k in item:
            return item[k]
    lower_map = {str(k).lower(): k for k in item}
    for k in keys:
        lk = str(k).lower()
        if lk in lower_map:
            return item[lower_map[lk]]
    return None


MITRE_TECHNIQUES = {
    "T1059.001": ("Execution", "PowerShell"),
    "T1059.004": ("Execution", "Unix Shell"),
    "T1059.003": ("Execution", "Windows Command Shell"),
    "T1059.005": ("Execution", "Visual Basic"),
    "T1059.006": ("Execution", "Python"),
    "T1059.007": ("Execution", "JavaScript"),
    "T1047": ("Execution", "WMI"),
    "T1053.005": ("Persistence", "Scheduled Task"),
    "T1543.003": ("Persistence", "Windows Service"),
    "T1547.001": ("Persistence", "Registry Run Keys"),
    "T1547.004": ("Persistence", "Winlogon Helper DLL"),
    "T1547.009": ("Persistence", "Shortcut Modification"),
    "T1136.001": ("Persistence", "Local Account Creation"),
    "T1003.001": ("Credential Access", "LSASS Memory"),
    "T1003.002": ("Credential Access", "SAM Database"),
    "T1003.004": ("Credential Access", "LSA Secrets"),
    "T1003.005": ("Credential Access", "Cached Domain Credentials"),
    "T1552.001": ("Credential Access", "Credentials In Files"),
    "T1552.002": ("Credential Access", "Credentials in Registry"),
    "T1110": ("Credential Access", "Brute Force"),
    "T1055.001": ("Defense Evasion", "DLL Injection"),
    "T1055.003": ("Defense Evasion", "Thread Execution Hijacking"),
    "T1055.012": ("Defense Evasion", "Process Hollowing"),
    "T1070.001": ("Defense Evasion", "Clear Windows Event Logs"),
    "T1070.004": ("Defense Evasion", "File Deletion"),
    "T1036.005": ("Defense Evasion", "Match Legitimate Name/Location"),
    "T1027": ("Defense Evasion", "Obfuscated Files or Information"),
    "T1218.005": ("Defense Evasion", "Mshta"),
    "T1218.010": ("Defense Evasion", "Regsvr32"),
    "T1218.011": ("Defense Evasion", "Rundll32"),
    "T1202": ("Defense Evasion", "Indirect Command Execution"),
    "T1564.001": ("Defense Evasion", "Hidden Files and Directories"),
    "T1071.001": ("Command and Control", "Web Protocols (HTTP/HTTPS)"),
    "T1071.004": ("Command and Control", "DNS"),
    "T1105": ("Command and Control", "Ingress Tool Transfer"),
    "T1572": ("Command and Control", "Protocol Tunneling"),
    "T1573": ("Command and Control", "Encrypted Channel"),
    "T1021.001": ("Lateral Movement", "Remote Desktop Protocol"),
    "T1021.002": ("Lateral Movement", "SMB/Windows Admin Shares"),
    "T1021.003": ("Lateral Movement", "DCOM"),
    "T1021.004": ("Lateral Movement", "SSH"),
    "T1021.006": ("Lateral Movement", "Windows Remote Management"),
    "T1570": ("Lateral Movement", "Lateral Tool Transfer"),
    "T1053.003": ("Persistence", "Cron"),
    "T1543.002": ("Persistence", "Systemd Service"),
    "T1098.004": ("Persistence", "SSH Authorized Keys"),
    "T1548.001": ("Privilege Escalation", "Setuid and Setgid"),
    "T1548.003": ("Privilege Escalation", "Sudo and Sudo Caching"),
    "T1055":     ("Defense Evasion", "Process Injection"),
    "T1574.006": ("Defense Evasion", "Dynamic Linker Hijacking (LD_PRELOAD)"),
    "T1222.002": ("Defense Evasion", "Linux File Permission Modification"),
    "T1140":     ("Defense Evasion", "Deobfuscate/Decode Files or Information"),
    "T1070.003": ("Defense Evasion", "Clear Command History"),
    "T1215":     ("Persistence", "Kernel Modules and Extensions"),
    "T1018": ("Discovery", "Remote System Discovery"),
    "T1016": ("Discovery", "System Network Configuration"),
    "T1033": ("Discovery", "System Owner/User Discovery"),
    "T1082": ("Discovery", "System Information Discovery"),
    "T1083": ("Discovery", "File and Directory Discovery"),
    "T1049": ("Discovery", "System Network Connections"),
    "T1057": ("Discovery", "Process Discovery"),
    "T1007": ("Discovery", "System Service Discovery"),
    "T1087.001": ("Discovery", "Local Account Discovery"),
    "T1087.002": ("Discovery", "Domain Account Discovery"),
    "T1482": ("Discovery", "Domain Trust Discovery"),
    "T1567": ("Exfiltration", "Exfiltration Over Web Service"),
    "T1041": ("Exfiltration", "Exfiltration Over C2 Channel"),
    "T1048": ("Exfiltration", "Exfiltration Over Alternative Protocol"),
    "T1486": ("Impact", "Data Encrypted for Impact (Ransomware)"),
    "T1489": ("Impact", "Service Stop"),
    "T1490": ("Impact", "Inhibit System Recovery"),
}


CMD_PATTERNS: List[Tuple[re.Pattern, str, str, str]] = [
    (re.compile(r'echo\s+[A-Za-z0-9+/=]{20,}\s*\|\s*base64\s*(?:-d|--decode)', re.I),
     "Base64 decode piped to execution", "CRITICAL", "T1140"),
    (re.compile(r'(?:bash|sh|python\d?|perl|ruby)\s+.*\|\s*base64\s*(?:-d|--decode)', re.I),
     "Interpreter receiving base64-decoded input", "CRITICAL", "T1140"),
    (re.compile(r'base64\s*(?:-d|--decode)\s*.*\|\s*(?:bash|sh|exec)', re.I),
     "Base64 decode piped directly into shell", "CRITICAL", "T1059.004"),
    (re.compile(r'(?:wget|curl)\s+.*(?:http|ftp).*(?:/tmp/|/dev/shm/|/var/tmp/)', re.I),
     "Download to writable directory (/tmp or /dev/shm)", "CRITICAL", "T1105"),
    (re.compile(r'(?:wget|curl)\s+.*-[oO]\s+/(?:tmp|dev/shm|var/tmp)/', re.I),
     "curl/wget writing to writable directory", "CRITICAL", "T1105"),
    (re.compile(r'(?:bash|sh|exec|python\d?|perl)\s+/(?:tmp|dev/shm|var/tmp|run/shm)/\S+', re.I),
     "Shell executing file from /tmp or /dev/shm", "CRITICAL", "T1059.004"),
    (re.compile(r'nohup\s+/(?:tmp|dev/shm|var/tmp)/\S+', re.I),
     "nohup backgrounding binary from writable path", "HIGH", "T1059.004"),
    (re.compile(r'/proc/\d+/(?:mem|maps|fd)', re.I),
     "Direct /proc memory access (possible injection)", "HIGH", "T1055"),
    (re.compile(r'LD_PRELOAD\s*=\s*\S+', re.I),
     "LD_PRELOAD set (dynamic linker hijacking)", "CRITICAL", "T1574.006"),
    (re.compile(r'crontab\s+-[eli]', re.I),
     "Crontab modification", "HIGH", "T1053.003"),
    (re.compile(r'(?:echo|printf).*>>\s*/etc/crontab', re.I),
     "Writing to /etc/crontab", "CRITICAL", "T1053.003"),
    (re.compile(r'systemctl\s+(?:enable|daemon-reload)', re.I),
     "Systemd service enable/reload", "MEDIUM", "T1543.002"),
    (re.compile(r'(?:echo|cat|tee).*>>\s*(?:~|/root|/home/\S+)/\.(?:bashrc|profile|bash_profile)', re.I),
     "Writing to shell startup file (persistence)", "HIGH", "T1543.002"),
    (re.compile(r'(?:echo|cat|tee).*authorized_keys', re.I),
     "SSH authorized_keys modification", "HIGH", "T1098.004"),
    (re.compile(r'\binsmod\b|\bmodprobe\b\s+\S+', re.I),
     "Kernel module loading (possible rootkit)", "HIGH", "T1215"),
    (re.compile(r'chmod\s+(?:[ug]\+s|[46][0-7]{3})\s+', re.I),
     "SUID/SGID bit set (privilege escalation)", "CRITICAL", "T1548.001"),
    (re.compile(r'\bsudo\s+-l\b', re.I),
     "Sudo privilege enumeration", "LOW", "T1548.003"),
    (re.compile(r'(?:echo|printf).*>>\s*/etc/sudoers', re.I),
     "Writing to /etc/sudoers", "CRITICAL", "T1548.003"),
    (re.compile(r'(?:cat|less|more|cp)\s+/etc/shadow', re.I),
     "Reading /etc/shadow (password hashes)", "CRITICAL", "T1003.001"),
    (re.compile(r'(?:cat|less|more|cp|grep)\s+/etc/passwd', re.I),
     "Reading /etc/passwd", "MEDIUM", "T1087.001"),
    (re.compile(r'find\s+.*-name\s+["\']?\*(?:id_rsa|\.pem|\.key)["\']?', re.I),
     "Searching for SSH private keys", "HIGH", "T1552.001"),
    (re.compile(r'(?:cat|less)\s+~/\.ssh/id_rsa', re.I),
     "Reading SSH private key", "CRITICAL", "T1552.001"),
    (re.compile(r'(?:history\s+-[cw]|unset\s+HISTFILE|HISTFILESIZE\s*=\s*0|>\s*~/\.bash_history)', re.I),
     "Bash history clearing or disabling", "HIGH", "T1070.003"),
    (re.compile(r'chmod\s+\+x\s+/(?:tmp|dev/shm|var/tmp)/\S+', re.I),
     "chmod +x on file in writable directory", "HIGH", "T1222.002"),
    (re.compile(r'(?:shred|wipe|srm)\s+', re.I),
     "Secure file deletion tool", "MEDIUM", "T1070.004"),
    (re.compile(r'\buname\s+-[ar]\b', re.I),
     "Kernel/arch enumeration", "LOW", "T1082"),
    (re.compile(r'\bwhoami\b', re.I),
     "User identity discovery", "LOW", "T1033"),
    (re.compile(r'\bid\b(?:\s|$)', re.I),
     "UID/GID discovery", "LOW", "T1033"),
    (re.compile(r'(?:ifconfig|ip\s+(?:addr|link|route))\b', re.I),
     "Network interface discovery", "LOW", "T1016"),
    (re.compile(r'\bnetstat\b|\bss\s+-', re.I),
     "Network connection discovery", "LOW", "T1049"),
    (re.compile(r'(?:find|locate)\s+.*-(?:perm|name)\s+.*suid', re.I),
     "SUID binary enumeration", "MEDIUM", "T1548.001"),
    (re.compile(r'(?:nc|ncat|netcat|socat)\s+.*-[lLp]', re.I),
     "Netcat/socat listener (possible backdoor)", "HIGH", "T1059.004"),
    (re.compile(r'(?:nc|ncat|netcat)\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\d+', re.I),
     "Netcat outbound connection (possible reverse shell)", "CRITICAL", "T1059.004"),
    (re.compile(r'bash\s+-i\s+>&?\s*/dev/tcp/', re.I),
     "Bash TCP reverse shell", "CRITICAL", "T1059.004"),
    (re.compile(r'python\d?\s+-c\s+[\'"].*(?:socket|subprocess).*connect', re.I),
     "Python reverse shell one-liner", "CRITICAL", "T1059.006"),
    (re.compile(r'perl\s+-e\s+[\'"].*socket.*connect', re.I),
     "Perl reverse shell one-liner", "CRITICAL", "T1059.006"),
    (re.compile(r'\buseradd\b|\badduser\b', re.I),
     "User account creation", "HIGH", "T1136.001"),
    (re.compile(r'(?:echo|printf).*:\d+:\d+:.*:/home/.*:/bin/(?:bash|sh).*>>\s*/etc/passwd', re.I),
     "Manual /etc/passwd entry injection", "CRITICAL", "T1136.001"),
    # === macOS-specific ===
    (re.compile(r'osascript\s+(?:-e|.*\.scpt)', re.I),
     "osascript execution (AppleScript / JXA)", "HIGH", "T1059.007"),
    (re.compile(r'launchctl\s+(?:load|unload|submit|start|stop)', re.I),
     "launchctl persistence manipulation", "HIGH", "T1543.001"),
    (re.compile(r'xattr\s+-(?:d|r)\s+com\.apple\.quarantine', re.I),
     "Quarantine attribute removal (Gatekeeper bypass)", "HIGH", "T1553.001"),
    (re.compile(r'defaults\s+write\s+.*(?:LSUIElement|LSBackgroundOnly)', re.I),
     "App hiding via defaults write", "MEDIUM", "T1564.001"),
    (re.compile(r'plutil\s+-(?:insert|replace|convert)', re.I),
     "plist manipulation (possible persistence)", "MEDIUM", "T1543.001"),
    (re.compile(r'spctl\s+--(?:disable|master-disable)', re.I),
     "Disabling Gatekeeper (spctl)", "CRITICAL", "T1553.001"),
]

SUSPICIOUS_CHAINS = [
    ({"apache2", "nginx", "httpd", "lighttpd", "php-fpm", "php"},
     {"sh", "bash", "dash", "zsh", "python", "python3", "perl", "ruby",
      "nc", "ncat", "netcat", "socat"},
     "Web server spawning shell (possible webshell/RCE)", "CRITICAL", "T1059.004"),
    ({"python", "python3", "python2", "ruby", "perl", "lua"},
     {"sh", "bash", "dash", "nc", "ncat", "netcat", "socat"},
     "Interpreter spawning shell or netcat", "HIGH", "T1059.004"),
    ({"sshd"},
     {"bash", "sh", "dash", "nc", "ncat", "python", "perl"},
     "SSH daemon spawning unusual child (possible exploitation)", "HIGH", "T1021.004"),
    ({"cron", "crond", "anacron", "atd"},
     {"bash", "sh", "python", "python3", "perl", "ruby", "nc", "wget", "curl"},
     "Cron spawning network/interpreter (verify legitimacy)", "MEDIUM", "T1053.003"),
    ({"mysql", "mysqld", "postgres", "mongod"},
     {"sh", "bash", "python", "perl"},
     "Database daemon spawning shell (possible SQL injection RCE)", "CRITICAL", "T1059.004"),
]


class CommandAnalyzer:
    """Analyze Windows process command lines for suspicious patterns."""

    def __init__(self, logger: logging.Logger):
        self.log = logger

    def analyze(self, output_dir: Path) -> Dict[str, Any]:
        jd = Path(output_dir) / "json"
        if not jd.is_dir():
            return {"flags": [], "chains": [], "mitre": {}}

        processes: Dict[str, Dict] = {}
        for item in load_json_by_pattern(jd, "pslist"):
            pid = str(_gv(item, "PID", "pid") or "")
            name = str(_gv(item, "ImageFileName", "Name", "COMM", "Comm") or "").lower()
            ppid = str(_gv(item, "PPID", "ppid", "InheritedFromPID") or "")
            if pid:
                processes[pid] = {"name": name, "ppid": ppid, "cmdline": ""}

        for item in load_json_by_pattern(jd, "cmdline"):
            pid = str(_gv(item, "PID", "pid") or "")
            args = str(_gv(item, "Args", "args", "CommandLine") or "").strip()
            if pid in processes and args:
                processes[pid]["cmdline"] = args

        # Linux: psaux has full argv in Arguments field
        for item in load_json_by_pattern(jd, "psaux"):
            pid = str(_gv(item, "PID", "pid") or "")
            args = str(_gv(item, "Arguments", "Args", "args", "CommandLine") or "").strip()
            if not pid:
                continue
            if pid not in processes:
                name = str(_gv(item, "COMM", "Comm", "Name", "name") or "").lower()
                ppid = str(_gv(item, "PPID", "ppid") or "")
                processes[pid] = {"name": name, "ppid": ppid, "cmdline": args}
            elif args and not processes[pid]["cmdline"]:
                processes[pid]["cmdline"] = args

        active_patterns = CMD_PATTERNS
        active_chains = SUSPICIOUS_CHAINS

        flags = []
        mitre_hits: Dict[str, List[str]] = {}

        for pid, proc in processes.items():
            cmdline = proc["cmdline"]
            if not cmdline or len(cmdline) < 5:
                continue
            for pattern, desc, severity, mitre_id in active_patterns:
                if pattern.search(cmdline):
                    flags.append({
                        "pid": pid,
                        "process": proc["name"],
                        "ppid": proc["ppid"],
                        "cmdline": cmdline,
                        "description": desc,
                        "severity": severity,
                        "mitre_id": mitre_id,
                        "mitre_name": MITRE_TECHNIQUES.get(mitre_id, ("", ""))[1],
                        "mitre_tactic": MITRE_TECHNIQUES.get(mitre_id, ("", ""))[0],
                    })
                    mitre_hits.setdefault(mitre_id, []).append(
                        f"[PID {pid}] {proc['name']}: {desc}")

        chains = []
        for pid, proc in processes.items():
            ppid = proc["ppid"]
            if ppid not in processes:
                continue
            parent = processes[ppid]
            parent_n = (parent.get("name") or "").lower()
            child_n = (proc.get("name") or "").lower()
            for parent_set, child_set, chain_desc, sev, mitre_id in active_chains:
                if parent_n in parent_set and child_n in child_set:
                    chains.append({
                        "parent_pid": ppid, "parent_name": parent["name"],
                        "parent_cmdline": parent["cmdline"],
                        "child_pid": pid, "child_name": proc["name"],
                        "child_cmdline": proc["cmdline"],
                        "description": chain_desc, "severity": sev,
                        "mitre_id": mitre_id,
                    })
                    mitre_hits.setdefault(mitre_id, []).append(
                        f"Chain: {parent['name']}[{ppid}] → {proc['name']}[{pid}]: {chain_desc}")

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        flags.sort(key=lambda f: severity_order.get(f["severity"], 9))

        self.log.info("Command analysis (mac): %d flags, %d chains, %d MITRE techniques",
                      len(flags), len(chains), len(mitre_hits))
        return {"flags": flags, "chains": chains, "mitre": mitre_hits, "os_type": "mac"}

    def write_report(self, output_dir: Path, results: Dict[str, Any]) -> Path:
        od = Path(output_dir)
        txt_path = od / "command_analysis.txt"
        json_dir = od / "json"
        json_dir.mkdir(parents=True, exist_ok=True)
        json_path = json_dir / "command_analysis.json"

        flags = results["flags"]
        chains = results["chains"]
        mitre = results["mitre"]

        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("  COMMAND LINE ANALYSIS — CresCent RAM Forensics Toolkit v6.0 (macOS)\n")
            f.write(f"  Flagged commands: {len(flags)}\n")
            f.write(f"  Suspicious chains: {len(chains)}\n")
            f.write(f"  MITRE techniques: {len(mitre)}\n")
            f.write("=" * 80 + "\n\n")

            if not flags and not chains:
                f.write("  No suspicious commands detected.\n")
            else:
                if chains:
                    f.write("  SUSPICIOUS PROCESS CHAINS\n")
                    f.write("  " + "-" * 76 + "\n\n")
                    for c in chains:
                        f.write(f"  [{c['severity']}] {c['description']}\n")
                        f.write(f"    MITRE: {c['mitre_id']}\n")
                        f.write(f"    Parent: [{c['parent_pid']}] {c['parent_name']}\n")
                        if c["parent_cmdline"]:
                            f.write(f"      CMD: {c['parent_cmdline'][:150]}\n")
                        f.write(f"    Child:  [{c['child_pid']}] {c['child_name']}\n")
                        if c["child_cmdline"]:
                            f.write(f"      CMD: {c['child_cmdline'][:150]}\n")
                        f.write("\n")

                if flags:
                    f.write("  FLAGGED COMMANDS\n")
                    f.write("  " + "-" * 76 + "\n\n")
                    current_sev = ""
                    for fl in flags:
                        if fl["severity"] != current_sev:
                            current_sev = fl["severity"]
                            f.write(f"  --- {current_sev} ---\n\n")
                        f.write(f"  [{fl['severity']}] {fl['description']}\n")
                        f.write(f"    MITRE: {fl['mitre_id']} ({fl['mitre_tactic']} / {fl['mitre_name']})\n")
                        f.write(f"    PID:   {fl['pid']} ({fl['process']})\n")
                        cmd = fl["cmdline"][:200]
                        f.write(f"    CMD:   {cmd}\n\n")

            f.write("=" * 80 + "\n")

        json_path.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
        self.log.info("Command analysis: %s", txt_path)
        return txt_path


class MitreMapper:
    """Map ALL toolkit findings to MITRE ATT&CK technique IDs (Linux variant)."""

    def __init__(self, logger: logging.Logger):
        self.log = logger

    def map_all(self, output_dir: Path, cmd_results: Optional[Dict] = None) -> Dict[str, Any]:
        od = Path(output_dir)
        jd = od / "json"
        hits: Dict[str, List[str]] = {}

        def add(tid: str, evidence: str):
            if tid not in hits:
                hits[tid] = []
            hits[tid].append(evidence)

        if cmd_results:
            for tid, evidences in cmd_results.get("mitre", {}).items():
                for ev in evidences:
                    add(tid, ev)

        if not jd.is_dir():
            return self._compile(hits)

        for item in load_json_by_pattern(jd, "malfind"):
            pid = str(_gv(item, "PID", "pid") or "")
            name = str(_gv(item, "Process", "Name", "ImageFileName", "COMM", "Comm") or "")
            protection = str(_gv(item, "Protection", "Protect") or "")
            if "EXECUTE" in protection.upper():
                add("T1055.001", f"Malfind: [{pid}] {name} — executable memory region")

        reg_json = jd / "registry_report.json"
        if reg_json.exists():
            try:
                reg = json.loads(reg_json.read_text(encoding="utf-8", errors="ignore"))
                persist = reg.get("persistence", []) if isinstance(reg, dict) else []
                for p in persist:
                    path = str(p.get("path", p.get("key", "")))
                    if "Run" in path:
                        add("T1547.001", f"Registry: {path}")
                    elif "Winlogon" in path:
                        add("T1547.004", f"Registry: {path}")
                    elif "Services" in path:
                        add("T1543.003", f"Registry: {path}")
            except Exception:
                pass

        _EXTERNAL_STATES = {"ESTABLISHED", "CLOSE_WAIT", "CLOSED", "SYN_SENT"}
        for source in ("netscan", "netstat"):
            for item in load_json_by_pattern(jd, source):
                foreign = str(_gv(item, "ForeignAddr", "Foreign Address",
                                   "RemoteAddr", "Remote IP", "Foreign IP", "Dst") or "")
                state = str(_gv(item, "State", "state", "Status") or "").upper()
                owner = str(_gv(item, "Owner", "Process", "Comm", "comm") or "")
                if not foreign:
                    continue
                ip = foreign.split(":")[0].strip().strip("[]")
                if state and state not in _EXTERNAL_STATES:
                    continue
                if ip and not ip.startswith(
                        ("10.", "192.168.", "172.", "127.", "0.", "::", "*", "")):
                    add("T1071.001",
                        f"External connection: {owner} → {foreign} [{state}]")

        for item in load_json_by_pattern(jd, "svcscan"):
            binary = str(_gv(item, "Binary", "Binary Path", "BinaryPath") or "")
            name = str(_gv(item, "Name", "Service Name") or "")
            if binary and ("\\temp\\" in binary.lower()
                           or "\\appdata\\" in binary.lower()
                           or "cmd.exe" in binary.lower()
                           or "powershell" in binary.lower()):
                add("T1543.003", f"Suspicious service: {name} → {binary}")

        comms_json = jd / "comms_report.json"
        if comms_json.exists():
            try:
                comms = json.loads(comms_json.read_text(encoding="utf-8", errors="ignore"))
                for app, data in comms.get("apps", {}).items():
                    for cat in data.get("categories", {}):
                        if any(x in cat for x in ("token", "key", "secret", "credential")):
                            count = data["categories"][cat]["count"]
                            add("T1552.001", f"{app}: {count} {cat} found in memory")
            except Exception:
                pass

        return self._compile(hits)

    def _compile(self, hits: Dict[str, List[str]]) -> Dict[str, Any]:
        techniques = []
        for tid, evidences in sorted(hits.items()):
            tactic, name = MITRE_TECHNIQUES.get(tid, ("Unknown", "Unknown"))
            techniques.append({
                "technique_id": tid,
                "tactic": tactic,
                "technique_name": name,
                "evidence_count": len(evidences),
                "evidence": evidences[:20],
            })
        by_tactic: Dict[str, List] = {}
        for t in techniques:
            tac = t["tactic"]
            if tac not in by_tactic:
                by_tactic[tac] = []
            by_tactic[tac].append(t)
        return {
            "technique_count": len(techniques),
            "techniques": techniques,
            "by_tactic": by_tactic,
            "tactic_count": len(by_tactic),
        }

    def write_report(self, output_dir: Path, results: Dict[str, Any]) -> Path:
        od = Path(output_dir)
        txt_path = od / "mitre_report.txt"
        json_dir = od / "json"
        json_dir.mkdir(parents=True, exist_ok=True)
        json_path = json_dir / "mitre_report.json"

        techniques = results["techniques"]
        by_tactic = results["by_tactic"]

        tactic_order = [
            "Execution", "Persistence", "Privilege Escalation",
            "Defense Evasion", "Credential Access", "Discovery",
            "Lateral Movement", "Collection", "Command and Control",
            "Exfiltration", "Impact",
        ]

        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("  MITRE ATT&CK MAPPING — CresCent RAM Forensics Toolkit v6.0 (macOS)\n")
            f.write(f"  Techniques identified: {results['technique_count']}\n")
            f.write(f"  Tactics covered: {results['tactic_count']}\n")
            f.write("=" * 80 + "\n\n")

            if not techniques:
                f.write("  No MITRE ATT&CK techniques identified.\n")
            else:
                f.write("  TACTIC COVERAGE\n")
                f.write("  " + "-" * 76 + "\n")
                for tactic in tactic_order:
                    if tactic in by_tactic:
                        count = len(by_tactic[tactic])
                        f.write(f"    {tactic:30s}  {count} technique(s)\n")
                f.write("\n")

                for tactic in tactic_order:
                    if tactic not in by_tactic:
                        continue
                    f.write(f"  {tactic.upper()}\n")
                    f.write("  " + "-" * 76 + "\n\n")
                    for t in by_tactic[tactic]:
                        f.write(f"    {t['technique_id']:12s}  {t['technique_name']}\n")
                        f.write(f"    {'':12s}  Evidence ({t['evidence_count']}):\n")
                        for ev in t["evidence"][:5]:
                            f.write(f"    {'':12s}    * {ev[:120]}\n")
                        if t["evidence_count"] > 5:
                            f.write(f"    {'':12s}    ... and {t['evidence_count'] - 5} more\n")
                        f.write("\n")

                f.write("  " + "-" * 76 + "\n")
                f.write("  Technique IDs (for ATT&CK Navigator import):\n")
                f.write("  " + ", ".join(t["technique_id"] for t in techniques) + "\n")

            f.write("\n" + "=" * 80 + "\n")

        json_path.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
        self.log.info("MITRE report: %s (%d techniques)", txt_path,
                      results["technique_count"])
        return txt_path
