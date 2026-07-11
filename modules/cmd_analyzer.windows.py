"""cmd_analyzer.windows.py — Windows-specific command analyzer (v6.0)

Contains Windows CMD_PATTERNS, SUSPICIOUS_CHAINS, MITRE_TECHNIQUES,
CommandAnalyzer, and MitreMapper for Windows memory images.
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
    (re.compile(r'-(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]{10,}', re.I),
     "Encoded PowerShell command", "CRITICAL", "T1059.001"),
    (re.compile(r'(?:powershell|pwsh).*(?:IEX|Invoke-Expression|iex)\s*\(', re.I),
     "PowerShell Invoke-Expression (download cradle)", "CRITICAL", "T1059.001"),
    (re.compile(r'(?:powershell|pwsh).*(?:Net\.WebClient|DownloadString|DownloadFile|wget|curl)', re.I),
     "PowerShell download cradle", "CRITICAL", "T1105"),
    (re.compile(r'(?:powershell|pwsh).*(?:Start-Process|Invoke-Command|Invoke-WmiMethod)', re.I),
     "PowerShell remote execution", "HIGH", "T1059.001"),
    (re.compile(r'(?:powershell|pwsh).*-(?:nop|noni|sta|w\s+hidden|ep\s+bypass)', re.I),
     "PowerShell with evasion flags", "HIGH", "T1059.001"),
    (re.compile(r'(?:wscript|cscript).*\.(?:vbs|vbe|wsf|wsc)', re.I),
     "VBScript execution", "MEDIUM", "T1059.005"),
    (re.compile(r'mshta\s+(?:http|vbscript|javascript)', re.I),
     "MSHTA executing remote/script content", "CRITICAL", "T1218.005"),
    (re.compile(r'rundll32.*(?:javascript|vbscript|http|shell32|advpack)', re.I),
     "Rundll32 proxy execution", "HIGH", "T1218.011"),
    (re.compile(r'regsvr32\s+/s\s+/(?:n|u).*(?:scrobj|http)', re.I),
     "Regsvr32 squiblydoo (AppLocker bypass)", "CRITICAL", "T1218.010"),
    (re.compile(r'wmic\s+(?:process\s+call|os\s+get|/node)', re.I),
     "WMI command execution", "MEDIUM", "T1047"),
    (re.compile(r'certutil.*-urlcache.*-(?:split\s+)?f\s+http', re.I),
     "Certutil downloading file (LOLBin)", "CRITICAL", "T1105"),
    (re.compile(r'bitsadmin.*(?:/transfer|/addfile).*http', re.I),
     "BITSAdmin file download (LOLBin)", "HIGH", "T1105"),
    (re.compile(r'curl\s+.*-[oO]\s+.*http', re.I),
     "curl downloading file", "MEDIUM", "T1105"),
    (re.compile(r'\bwhoami\b(?:\s+/(?:all|priv|groups))?', re.I),
     "User/privilege discovery", "LOW", "T1033"),
    (re.compile(r'\bipconfig\b(?:\s+/all)?', re.I),
     "Network configuration discovery", "LOW", "T1016"),
    (re.compile(r'\bsysteminfo\b', re.I),
     "System information discovery", "LOW", "T1082"),
    (re.compile(r'\bnet\s+(?:user|group|localgroup)\b', re.I),
     "Account discovery", "MEDIUM", "T1087.001"),
    (re.compile(r'\bnet\s+(?:view|share|use)\b', re.I),
     "Network share discovery", "MEDIUM", "T1018"),
    (re.compile(r'\bnltest\s+/domain_trusts', re.I),
     "Domain trust discovery", "MEDIUM", "T1482"),
    (re.compile(r'\bnetstat\b.*-(?:an|ano|anob)', re.I),
     "Network connection discovery", "LOW", "T1049"),
    (re.compile(r'\btasklist\b', re.I),
     "Process discovery", "LOW", "T1057"),
    (re.compile(r'\bsc\s+query\b', re.I),
     "Service discovery", "LOW", "T1007"),
    (re.compile(r'\bdir\s+.*(?:\\Users\\|\\Documents|\\Desktop)', re.I),
     "File and directory discovery", "LOW", "T1083"),
    (re.compile(r'mimikatz|sekurlsa|lsadump|kerberos::list', re.I),
     "Mimikatz credential dumping", "CRITICAL", "T1003.001"),
    (re.compile(r'procdump.*(?:lsass|pid\s+\d+)', re.I),
     "LSASS process dump (credential theft)", "CRITICAL", "T1003.001"),
    (re.compile(r'reg\s+save\s+(?:hklm\\sam|hklm\\system|hklm\\security)', re.I),
     "Registry SAM/SYSTEM hive export", "CRITICAL", "T1003.002"),
    (re.compile(r'ntdsutil.*(?:ifm|snapshot|activate)', re.I),
     "NTDS.dit extraction (domain creds)", "CRITICAL", "T1003.003"),
    (re.compile(r'comsvcs\.dll.*MiniDump', re.I),
     "MiniDump via comsvcs.dll (LSASS dump)", "CRITICAL", "T1003.001"),
    (re.compile(r'schtasks\s+/create', re.I),
     "Scheduled task creation", "HIGH", "T1053.005"),
    (re.compile(r'sc\s+(?:create|config)\s+', re.I),
     "Service creation/modification", "HIGH", "T1543.003"),
    (re.compile(r'reg\s+add\s+.*(?:Run|RunOnce)', re.I),
     "Registry Run key persistence", "HIGH", "T1547.001"),
    (re.compile(r'reg\s+add\s+.*Winlogon', re.I),
     "Winlogon persistence", "HIGH", "T1547.004"),
    (re.compile(r'wevtutil\s+(?:cl|clear-log)', re.I),
     "Clearing Windows event logs", "CRITICAL", "T1070.001"),
    (re.compile(r'(?:del|erase)\s+/[fFqQ]', re.I),
     "Forced file deletion", "MEDIUM", "T1070.004"),
    (re.compile(r'attrib\s+\+[hH]', re.I),
     "Hiding files", "MEDIUM", "T1564.001"),
    (re.compile(r'taskkill\s+/(?:f|im)\s+', re.I),
     "Force killing process (AV/EDR?)", "MEDIUM", "T1489"),
    (re.compile(r'bcdedit.*(?:recoveryenabled.*no|safeboot)', re.I),
     "Disabling recovery (ransomware indicator)", "CRITICAL", "T1490"),
    (re.compile(r'vssadmin\s+delete\s+shadows', re.I),
     "Deleting shadow copies (ransomware indicator)", "CRITICAL", "T1490"),
    (re.compile(r'psexec', re.I),
     "PsExec lateral movement", "HIGH", "T1021.002"),
    (re.compile(r'winrs\s+', re.I),
     "WinRM remote command", "HIGH", "T1021.006"),
    (re.compile(r'(?:net\s+use|copy)\s+\\\\', re.I),
     "SMB file copy / share access", "MEDIUM", "T1021.002"),
    (re.compile(r'mstsc|rdp|Remote\s+Desktop', re.I),
     "RDP usage", "LOW", "T1021.001"),
]

SUSPICIOUS_CHAINS = [
    ({"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"},
     {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"},
     "Office application spawning shell (possible macro)", "CRITICAL", "T1059.001"),
    ({"msedge.exe", "chrome.exe", "firefox.exe", "iexplore.exe"},
     {"cmd.exe", "powershell.exe", "pwsh.exe"},
     "Browser spawning shell (possible exploit/download)", "HIGH", "T1059.003"),
    ({"svchost.exe"},
     {"cmd.exe", "powershell.exe"},
     "Svchost spawning shell (possible service exploit)", "HIGH", "T1059.003"),
    ({"wmiprvse.exe"},
     {"cmd.exe", "powershell.exe"},
     "WMI spawning shell (possible lateral movement)", "HIGH", "T1047"),
]


class CommandAnalyzer:
    """Analyze Windows process command lines for suspicious patterns."""

    def __init__(self, logger: logging.Logger):
        self.log = logger

    @staticmethod
    def _flatten_pstree(nodes: list) -> list:
        result = []
        for n in nodes:
            result.append(n)
            children = n.get("__children") or n.get("Children") or n.get("children") or []
            if children:
                result.extend(CommandAnalyzer._flatten_pstree(children))
        return result

    def analyze(self, output_dir: Path) -> Dict[str, Any]:
        jd = Path(output_dir) / "json"
        if not jd.is_dir():
            return {"flags": [], "chains": [], "mitre": {}}

        processes: Dict[str, Dict] = {}
        pslist_raw = load_json_by_pattern(jd, "pslist")
        if not pslist_raw:
            # Vol3 pslist exits 0 on failure; fall back to pstree
            raw_tree = load_json_by_pattern(jd, "pstree")
            if raw_tree:
                pslist_raw = self._flatten_pstree(raw_tree)
                self.log.info("cmd_analyzer: pslist empty — loaded %d procs from pstree",
                              len(pslist_raw))

        for item in pslist_raw:
            pid = str(_gv(item, "PID", "pid") or "")
            name = str(_gv(item, "ImageFileName", "Name", "Process", "COMM", "Comm") or "").lower()
            ppid = str(_gv(item, "PPID", "ppid", "InheritedFromPID") or "")
            if pid:
                processes[pid] = {"name": name, "ppid": ppid, "cmdline": ""}

        for item in load_json_by_pattern(jd, "cmdline"):
            pid = str(_gv(item, "PID", "pid") or "")
            args = str(_gv(item, "Args", "args", "CommandLine", "Command Line") or "").strip()
            if not pid and not args:
                continue
            if pid in processes and args:
                processes[pid]["cmdline"] = args
            elif pid and pid not in processes and args:
                # cmdline entry for a PID not in pslist (e.g. psscan-only process)
                name = str(_gv(item, "Process", "Name", "ImageFileName") or "").lower()
                processes[pid] = {"name": name, "ppid": "", "cmdline": args}

        # Extract commands from cmdscan/consoles (interactive console history).
        # These capture historically-typed commands even after the process exits,
        # so they surface evidence not visible in the live cmdline list.
        shell_history: List[Dict[str, str]] = []
        _CMD_FIELD_RE = re.compile(r'^(?:Cmd\s+#\d+|Input\s*#\d+)\s+@\s+0x', re.I)
        for item in load_json_by_pattern(jd, "cmdscan"):
            proc_raw = str(_gv(item, "CommandProcess", "CommandHistoryProcess") or "")
            # "conhost.exe Pid: 2284" → extract name + pid
            m = re.search(r'^(.*?)\s+[Pp]id:\s*(\d+)', proc_raw)
            c_name = m.group(1).strip().lower() if m else ""
            c_pid = m.group(2) if m else ""
            # Collect each "Cmd #N @ 0x..." field value as a typed command
            for k, v in item.items():
                if _CMD_FIELD_RE.match(k) and isinstance(v, str) and v.strip():
                    cmd_str = v.strip()
                    if len(cmd_str) >= 3:
                        shell_history.append({"pid": c_pid, "name": c_name,
                                              "cmdline": cmd_str, "source": "cmdscan"})
            # Also extract application name from CommandHistory summary
            ch = str(item.get("CommandHistory") or "")
            app_m = re.search(r'Application:\s*(\S+)', ch)
            if app_m:
                shell_history.append({"pid": c_pid, "name": c_name,
                                      "cmdline": app_m.group(1), "source": "cmdscan"})

        for item in load_json_by_pattern(jd, "consoles"):
            proc_raw = str(_gv(item, "ConsoleProcess", "CommandProcess") or "")
            m = re.search(r'^(.*?)\s+[Pp]id:\s*(\d+)', proc_raw)
            c_name = m.group(1).strip().lower() if m else ""
            c_pid = m.group(2) if m else ""
            for k, v in item.items():
                if _CMD_FIELD_RE.match(k) and isinstance(v, str) and v.strip():
                    cmd_str = v.strip()
                    if len(cmd_str) >= 3:
                        shell_history.append({"pid": c_pid, "name": c_name,
                                              "cmdline": cmd_str, "source": "consoles"})
            title = str(item.get("OriginalTitle") or item.get("Title") or "")
            if title and len(title) >= 3:
                shell_history.append({"pid": c_pid, "name": c_name,
                                      "cmdline": title, "source": "consoles"})

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

        # Scan cmdscan/consoles history against CMD_PATTERNS
        seen_history: Set[Tuple[str, str]] = set()
        for entry in shell_history:
            cmdline = entry["cmdline"]
            if not cmdline or len(cmdline) < 5:
                continue
            for pattern, desc, severity, mitre_id in active_patterns:
                if pattern.search(cmdline):
                    dedup_key = (entry["pid"], desc, cmdline[:80])
                    if dedup_key in seen_history:
                        continue
                    seen_history.add(dedup_key)
                    flags.append({
                        "pid": entry["pid"],
                        "process": entry["name"],
                        "ppid": "",
                        "cmdline": cmdline,
                        "description": f"[{entry['source']}] {desc}",
                        "severity": severity,
                        "mitre_id": mitre_id,
                        "mitre_name": MITRE_TECHNIQUES.get(mitre_id, ("", ""))[1],
                        "mitre_tactic": MITRE_TECHNIQUES.get(mitre_id, ("", ""))[0],
                    })
                    mitre_hits.setdefault(mitre_id, []).append(
                        f"[{entry['source']}] {entry['name']}[{entry['pid']}]: {desc}")

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

        self.log.info("Command analysis (windows): %d flags, %d chains, %d MITRE techniques "
                      "(%d history entries from cmdscan/consoles)",
                      len(flags), len(chains), len(mitre_hits), len(shell_history))
        return {"flags": flags, "chains": chains, "mitre": mitre_hits,
                "shell_history": shell_history, "os_type": "windows"}

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
            f.write("  COMMAND LINE ANALYSIS — CresCent RAM Forensics Toolkit v6.0 (Windows)\n")
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
    """Map ALL toolkit findings to MITRE ATT&CK technique IDs (Windows variant)."""

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
                                   "RemoteAddr", "Foreign IP", "Dst") or "")
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
            f.write("  MITRE ATT&CK MAPPING — CresCent RAM Forensics Toolkit v6.0 (Windows)\n")
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
