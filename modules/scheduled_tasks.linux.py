"""CresCent RAM Forensics Toolkit v6.0 - Scheduled Tasks Scanner (Linux)

Extracts cron / at job evidence from Linux memory images.
Primary sources: Bash history (crontab commands), lsof (cron files), processes (crond/atd), envars.

Windows sources:
  - Registry printkey: TaskCache paths
  - Filescan: .job files, \\Windows\\System32\\Tasks
  - Cmdline / cmdscan: schtasks.exe usage
  - Svcscan: Task Scheduler service

Linux sources:
  - Bash history: crontab / cron command usage
  - Lsof: open files under /etc/cron* or /var/spool/cron
  - Pslist/psaux: crond, cron, atd processes
  - Envars: CRON_TZ and similar

macOS sources:
  - Pslist/psaux: launchd, UserEventAgent, atd
  - Lsof: open LaunchAgent/LaunchDaemon plist files
  - List_files: .plist files under LaunchDaemons / LaunchAgents paths
  - Bash history: launchctl / crontab usage
  - Envars: LAUNCHD_* variables

Output JSON: iocs/json/scheduled_tasks.json  TXT: scheduled_tasks.txt (root)
"""

import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from utils.json_converter import load_json_by_pattern


def _gv(item, *keys):
    for k in keys:
        if k in item:
            return item[k]
    lower_map = {str(k).lower(): k for k in item}
    for k in keys:
        if str(k).lower() in lower_map:
            return item[lower_map[str(k).lower()]]
    return None


# ── Windows ──────────────────────────────────────────────────────────────────
_TASK_REGISTRY_PATHS = [
    r"Microsoft\Windows NT\CurrentVersion\Schedule",
    r"Schedule\TaskCache",
    r"Schedule\TaskCache\Tasks",
    r"Schedule\TaskCache\Tree",
    r"Schedule\TaskCache\Plain",
    r"Schedule\TaskCache\Boot",
    r"Schedule\TaskCache\Logon",
]
_TASK_FILE_PATHS_WIN = [
    r"\Windows\System32\Tasks",
    r"\Windows\SysWOW64\Tasks",
    r"\Windows\Tasks",
]
_TASK_PROCS_WIN = (
    "taskhost.exe", "taskeng.exe", "taskhostw.exe",
    "schtasks.exe", "mstask.exe", "wmiprvse.exe",
)

# ── Linux ─────────────────────────────────────────────────────────────────────
_CRON_PATHS_LINUX = [
    "/etc/cron",
    "/var/spool/cron",
    "/etc/crontab",
    "/etc/anacrontab",
    "/etc/at.allow",
    "/etc/at.deny",
    "/var/spool/at",
]
_TASK_PROCS_LINUX = ("cron", "crond", "anacron", "atd", "fcron")

# ── macOS ─────────────────────────────────────────────────────────────────────
_LAUNCHD_PATHS_MAC = [
    "/Library/LaunchDaemons/",
    "/Library/LaunchAgents/",
    "/System/Library/LaunchDaemons/",
    "/System/Library/LaunchAgents/",
]
_LAUNCHD_USER_PATTERN = re.compile(r"/users/.+/library/launchagents/", re.IGNORECASE)
_TASK_PROCS_MAC = (
    "launchd", "launchctl", "UserEventAgent", "atd",
    "cron", "crond", "cfprefsd",
)

# ── Shared suspicious command patterns ────────────────────────────────────────
_SCHTASKS_PATTERNS = [
    r"schtasks\s*/create",
    r"schtasks\s*/change",
    r"schtasks\s*/run",
    r"schtasks\s*/delete",
    r"at\s+\d+:\d+",
    r"crontab\s+-[eli]",
    r"echo.*crontab",
    r"/etc/cron",
    r"cron\.d/",
    r"launchctl\s+(load|unload|submit|start|stop)",
    r"com\.apple\.\S+\.plist",
    r"plutil\s+",
]


class ScheduledTasksScanner:
    """Scan memory artifacts for scheduled task / cron / launchd evidence."""

    def __init__(self, logger: logging.Logger):
        self.log = logger
        self._image_os: str = "unknown"
        self._registry_tasks: List[Dict[str, Any]] = []
        self._file_tasks: List[Dict] = []
        self._task_processes: List[Dict] = []
        self._suspicious_cmds: List[Dict] = []
        self._linux_cron: List[Dict] = []
        self._mac_launchd: List[Dict] = []

    @staticmethod
    def _detect_image_os(jd: Path) -> str:
        """Determine OS from Vol plugin filename prefixes (most reliable signal)."""
        names = " ".join(p.name for p in jd.iterdir()) if jd.is_dir() else ""
        if any(x in names for x in ("mac_pslist", "mac_pstree", "mac_psaux",
                                     "mac_bash", "mac_netstat")):
            return "mac"
        if any(x in names for x in ("linux_pslist", "linux_pstree", "linux_psaux",
                                     "linux_bash", "linux_lsmod")):
            return "linux"
        if any(x in names for x in ("windows_pslist", "windows_pstree",
                                     "windows_svcscan", "windows_cmdline")):
            return "windows"
        # Vol2 fallback: Windows-only plugins confirm the OS
        if any(x in names for x in ("hivelist_vol2", "hashdump_vol2",
                                     "svcscan_vol2", "cmdline_vol2")):
            return "windows"
        # Vol2 Linux: linux_ prefix is preserved in plugin names
        if any(x in names for x in ("linux_pslist_vol2", "linux_pstree_vol2",
                                     "linux_psaux_vol2", "linux_lsmod_vol2")):
            return "linux"
        return "unknown"

    def scan(self, output_dir: Path) -> Dict[str, Any]:
        jd = output_dir / "json"
        if not jd.is_dir():
            self.log.error("No json/ directory: %s", jd)
            return {}

        # Determine host OS from plugin filename prefixes (most reliable signal).
        self._image_os = self._detect_image_os(jd)

        self._registry_tasks.clear()
        self._file_tasks.clear()
        self._task_processes.clear()
        self._suspicious_cmds.clear()
        self._linux_cron.clear()
        self._mac_launchd.clear()

        # Linux: cron evidence, filescan (cron dirs), process names, cmdlines
        self._scan_linux(jd)
        self._scan_filescan(jd)
        self._scan_processes(jd)
        self._scan_cmdlines(jd)

        total = (len(self._file_tasks) + len(self._task_processes) +
                 len(self._suspicious_cmds) + len(self._linux_cron))

        self.log.info(
            "Scheduled tasks: %d registry, %d files, %d procs, "
            "%d suspicious cmds, %d linux cron, %d mac launchd",
            len(self._registry_tasks), len(self._file_tasks),
            len(self._task_processes), len(self._suspicious_cmds),
            len(self._linux_cron), len(self._mac_launchd),
        )
        return {
            "registry_tasks":      self._registry_tasks,
            "file_tasks":          self._file_tasks,
            "task_processes":      self._task_processes,
            "suspicious_commands": self._suspicious_cmds,
            "linux_cron":          self._linux_cron,
            "mac_launchd":         self._mac_launchd,
            "total_findings":      total,
        }

    def _scan_registry(self, jd: Path):
        for entry in load_json_by_pattern(jd, "printkey"):
            key = str(_gv(entry, "Key", "key", "Path", "Subkey",
                          "Hive Offset", "Name") or "")
            val = str(_gv(entry, "Value", "value", "Data", "data",
                          "Last Write Time", "raw") or "")
            full = (key + " " + val).lower()
            for tp in _TASK_REGISTRY_PATHS:
                if tp.lower() in full:
                    self._registry_tasks.append({
                        "source": "printkey", "key": key,
                        "value": val[:200], "matched_path": tp,
                    })
                    break

        _ua_re = re.compile(r'^REG_\w+\s+(.+?)\s*:$')
        for entry in load_json_by_pattern(jd, "userassist"):
            name = ""
            for k in entry:
                m = _ua_re.match(str(k))
                if m:
                    name = m.group(1).strip()
                    break
            if not name:
                name = str(_gv(entry, "Name", "Value", "name", "Path", "raw") or "")
            if name and any(p.lower() in name.lower() for p in _TASK_PROCS_WIN):
                self._registry_tasks.append({
                    "source": "userassist", "name": name,
                    "count": str(_gv(entry, "Count", "count", "ID") or ""),
                    "last": str(_gv(entry, "Last Write", "LastWrite", "Last Updated") or ""),
                    "note": "Task host executable execution recorded",
                })

    def _scan_filescan(self, jd: Path):
        for entry in (load_json_by_pattern(jd, "filescan") +
                      load_json_by_pattern(jd, "enumerate_files")):
            path = str(_gv(entry, "Name", "FileName", "File", "name",
                           "Path", "path") or "")
            if not path:
                continue
            path_lower = path.lower()
            if path_lower.endswith(".job") or any(
                    tp.lower() in path_lower for tp in _TASK_FILE_PATHS_WIN):
                self._file_tasks.append({
                    "source": "filescan", "path": path,
                    "offset": str(_gv(entry, "Offset", "offset", "Address") or ""),
                    "type": "job_file" if path_lower.endswith(".job") else "task_directory",
                    "os": "windows",
                })
            for cp in _CRON_PATHS_LINUX:
                if cp in path:
                    self._file_tasks.append({
                        "source": "filescan", "path": path,
                        "type": "linux_cron_file", "os": "linux",
                    })
                    break
            self._check_mac_plist_path(
                path, "filescan",
                str(_gv(entry, "Offset", "offset", "Address") or ""))

        for pattern in ("list_files", "mac_list_files"):
            for entry in load_json_by_pattern(jd, pattern):
                path = str(_gv(entry, "Name", "Path", "File", "name", "path",
                               "FileName", "Full Path") or "")
                if path:
                    self._check_mac_plist_path(path, pattern, "")

        for entry in load_json_by_pattern(jd, "lsof"):
            name = str(_gv(entry, "Name", "name", "FILE") or "")
            pid  = str(_gv(entry, "PID", "pid") or "")
            proc = str(_gv(entry, "Process", "Comm", "comm", "name") or "")
            for cp in _CRON_PATHS_LINUX:
                if cp in name:
                    self._file_tasks.append({
                        "source": "lsof", "path": name, "pid": pid,
                        "process": proc, "type": "linux_cron_open_file", "os": "linux",
                    })
                    break
            self._check_mac_plist_path(name, "lsof", "", pid=pid, proc=proc)

    def _check_mac_plist_path(self, path: str, source: str, offset: str,
                               pid: str = "", proc: str = ""):
        if not path:
            return
        path_norm = path.lower()
        is_launchd = (
            any(p.lower() in path_norm for p in _LAUNCHD_PATHS_MAC) or
            bool(_LAUNCHD_USER_PATTERN.search(path_norm))
        )
        if is_launchd and ".plist" in path_norm:
            entry: Dict[str, Any] = {
                "source": source, "path": path,
                "type": "launchd_plist", "os": "mac",
            }
            if offset:
                entry["offset"] = offset
            if pid:
                entry["pid"] = pid
            if proc:
                entry["process"] = proc
            self._mac_launchd.append(entry)

    def _scan_processes(self, jd: Path):
        seen_pids: set = set()
        all_procs = (load_json_by_pattern(jd, "pslist") +
                     load_json_by_pattern(jd, "pstree") +
                     load_json_by_pattern(jd, "psaux"))
        all_task_procs = _TASK_PROCS_WIN + _TASK_PROCS_LINUX + _TASK_PROCS_MAC

        for p in all_procs:
            pid  = str(_gv(p, "PID", "pid", "Pid") or "")
            name = str(_gv(p, "ImageFileName", "Name", "Process",
                           "name", "COMM", "Comm", "comm") or "")
            name_lower = name.lower()
            if any(t.lower() in name_lower for t in all_task_procs):
                if pid not in seen_pids:
                    seen_pids.add(pid)
                    ppid  = str(_gv(p, "PPID", "ppid", "Ppid",
                                    "InheritedFromUniqueProcessId") or "")
                    cmdln = str(_gv(p, "Args", "args", "Arguments",
                                    "CommandLine", "CmdLine") or "")
                    # Prefer image-level OS for processes shared across OS types
                    # (e.g. cron/atd run on both Linux and macOS).
                    if any(m.lower() in name_lower for m in _TASK_PROCS_MAC) and \
                            any(m.lower() in name_lower for m in _TASK_PROCS_LINUX):
                        # Ambiguous: use the image OS we detected from filenames
                        os_guess = self._image_os if self._image_os in ("mac", "linux") else "linux"
                    elif any(m.lower() in name_lower for m in _TASK_PROCS_MAC):
                        os_guess = "mac"
                    elif any(m.lower() in name_lower for m in _TASK_PROCS_LINUX):
                        os_guess = "linux"
                    else:
                        os_guess = "windows"
                    self._task_processes.append({
                        "pid": pid, "ppid": ppid,
                        "name": name, "cmdline": cmdln,
                        "os": os_guess,
                    })

        for svc in load_json_by_pattern(jd, "svcscan"):
            svc_name = str(_gv(svc, "Name", "ServiceName", "name") or "").lower()
            display  = str(_gv(svc, "Display", "DisplayName", "display") or "").lower()
            binary   = str(_gv(svc, "Binary", "BinaryPath", "binary", "ImagePath") or "")
            if ("schedule" in svc_name or "task" in svc_name or
                    "schedule" in display or "task scheduler" in display):
                self._task_processes.append({
                    "source": "svcscan", "os": "windows",
                    "name": _gv(svc, "Name", "ServiceName", "name") or "",
                    "display": _gv(svc, "Display", "DisplayName", "display") or "",
                    "state": str(_gv(svc, "State", "Status", "state") or ""),
                    "binary": binary,
                })

    def _scan_cmdlines(self, jd: Path):
        for entry in (load_json_by_pattern(jd, "cmdline") +
                      load_json_by_pattern(jd, "cmdscan") +
                      load_json_by_pattern(jd, "consoles")):
            pid  = str(_gv(entry, "PID", "pid", "Pid") or "")
            args = str(_gv(entry, "Args", "args", "CommandLine", "CmdLine",
                           "Command", "Output", "raw") or "")
            if not args:
                continue
            for pat in _SCHTASKS_PATTERNS:
                if re.search(pat, args, re.IGNORECASE):
                    self._suspicious_cmds.append({
                        "pid": pid, "cmdline": args[:300],
                        "matched_pattern": pat,
                    })
                    break

    def _scan_linux(self, jd: Path):
        for entry in load_json_by_pattern(jd, "bash"):
            cmd = str(_gv(entry, "Command", "command", "History",
                          "CommandHistory", "raw") or "")
            pid = str(_gv(entry, "PID", "pid", "Pid") or "")
            for pat in _SCHTASKS_PATTERNS:
                if re.search(pat, cmd, re.IGNORECASE):
                    self._linux_cron.append({
                        "source": "bash_history", "pid": pid,
                        "command": cmd[:300], "matched_pattern": pat,
                    })
                    break

        for entry in load_json_by_pattern(jd, "envars"):
            var = str(_gv(entry, "Variable", "variable", "Name", "name",
                          "Var", "Key") or "")
            val = str(_gv(entry, "Value", "value", "Val") or "")
            vu = var.upper()
            # Use exact or start-of-name matches to avoid false positives.
            # e.g. "AT_" as a substring fires on XDG_SEAT_PATH — wrong.
            is_cron_var = (
                vu.startswith("CRON") or        # CRON_TZ, CRONTAB, etc.
                vu == "MAILTO" or               # cron mail target
                vu in ("AT_BID", "AT_JOBID")    # at(1) job env vars
            )
            if is_cron_var:
                self._linux_cron.append({
                    "source": "envars",
                    "pid": str(_gv(entry, "PID", "pid") or ""),
                    "variable": var, "value": val[:200],
                })

    def _scan_mac(self, jd: Path):
        for entry in load_json_by_pattern(jd, "bash"):
            cmd = str(_gv(entry, "Command", "command", "History",
                          "CommandHistory", "raw") or "")
            pid = str(_gv(entry, "PID", "pid", "Pid") or "")
            if re.search(r"launchctl|launchd|\.plist", cmd, re.IGNORECASE):
                for pat in _SCHTASKS_PATTERNS:
                    if re.search(pat, cmd, re.IGNORECASE):
                        self._mac_launchd.append({
                            "source": "bash_history", "os": "mac",
                            "pid": pid, "command": cmd[:300],
                            "matched_pattern": pat,
                        })
                        break

        for entry in load_json_by_pattern(jd, "envars"):
            var = str(_gv(entry, "Variable", "variable", "Name", "name",
                          "Var", "Key") or "")
            val = str(_gv(entry, "Value", "value", "Val") or "")
            if any(x in var.upper() for x in ("LAUNCHD", "LAUNCHCTL", "LAUNCH_")):
                self._mac_launchd.append({
                    "source": "envars", "os": "mac",
                    "pid": str(_gv(entry, "PID", "pid") or ""),
                    "variable": var, "value": val[:200],
                })

    def write_report(self, output_dir: Path, results: Dict) -> Path:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        txt_path = output_dir / "scheduled_tasks.txt"

        json_dir = output_dir / "iocs" / "json"
        json_dir.mkdir(parents=True, exist_ok=True)
        json_path = json_dir / "scheduled_tasks.json"

        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("  SCHEDULED TASKS / CRON / LAUNCHD REPORT\n")
            f.write(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("  NOTE: Raw observations — no automated threat assessments.\n")
            f.write("=" * 80 + "\n\n")

            self._write_section(f, "WINDOWS — REGISTRY-BASED TASK EVIDENCE",
                                results["registry_tasks"],
                                ["source", "key", "value", "matched_path",
                                 "name", "count", "last", "note"])
            self._write_section(f, "WINDOWS — TASK FILES IN FILESYSTEM",
                                [t for t in results["file_tasks"]
                                 if t.get("os") == "windows"],
                                ["source", "path", "type", "pid", "process", "offset"])
            self._write_section(f, "SCHEDULER PROCESSES / SERVICES (ALL OS)",
                                results["task_processes"],
                                ["os", "source", "pid", "ppid", "name", "display",
                                 "state", "cmdline", "binary"])
            self._write_section(f, "SUSPICIOUS TASK-RELATED COMMANDS (ALL OS)",
                                results["suspicious_commands"],
                                ["pid", "cmdline", "matched_pattern"])
            self._write_section(f, "LINUX — CRON / AT JOB EVIDENCE",
                                results["linux_cron"],
                                ["source", "pid", "command", "variable",
                                 "value", "matched_pattern"])
            self._write_section(
                f, "MACOS — LAUNCHD / LAUNCHAGENT / LAUNCHDAEMON EVIDENCE",
                results["mac_launchd"],
                ["source", "os", "pid", "process", "path", "type",
                 "command", "variable", "value", "matched_pattern"])

            f.write("=" * 80 + "\n  SUMMARY\n" + "=" * 80 + "\n\n")
            f.write(f"  Windows registry entries:   {len(results['registry_tasks'])}\n")
            f.write(f"  Task files found:           {len(results['file_tasks'])}\n")
            f.write(f"  Scheduler processes:        {len(results['task_processes'])}\n")
            f.write(f"  Suspicious commands:        {len(results['suspicious_commands'])}\n")
            f.write(f"  Linux cron evidence:        {len(results['linux_cron'])}\n")
            f.write(f"  macOS launchd evidence:     {len(results['mac_launchd'])}\n")
            f.write(f"  Total findings:             {results['total_findings']}\n\n")
            f.write("=" * 80 + "\n  END\n" + "=" * 80 + "\n")

        json_out = dict(results)
        json_out["generated"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        json_path.write_text(json.dumps(json_out, indent=2, default=str), encoding="utf-8")
        self.log.info("Scheduled tasks report: %s  JSON: %s", txt_path, json_path)
        return txt_path

    @staticmethod
    def _write_section(f, title: str, items: List[Dict], fields: List[str]):
        f.write("=" * 80 + f"\n  {title} ({len(items)})\n" + "=" * 80 + "\n\n")
        if not items:
            f.write("  None found.\n\n")
            return
        for item in items:
            for field in fields:
                val = item.get(field, "")
                if val:
                    f.write(f"  {field:20s}: {str(val)[:200]}\n")
            f.write("-" * 40 + "\n")
        f.write("\n")
