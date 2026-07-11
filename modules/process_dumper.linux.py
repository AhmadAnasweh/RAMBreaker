"""CresCent RAM Forensics Toolkit v6.0 - Process Dumper (Linux)"""

import logging
import re
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Set

from modules.volatility import VolatilityWrapper
from utils.json_converter import load_json_by_pattern
from utils.ui import msg_info, msg_ok, msg_warn

_KNOWN_TOOLS_LINUX = {
    "linpeas", "linenum", "linux-exploit", "unix-privesc", "lse.sh",
    "pspy", "mimipenguin", "mimipenguinx", "linuxprivchecker",
    "mettle", "meterpreter", "nc", "ncat", "netcat", "socat",
    "chisel", "ligolo", "frpc", "frps", "rathole",
    "fscan", "masscan", "nmap",
    "ltrace", "ptrace_scope", "gdbserver",
    "reptile", "diamorphine", "azazel",
    "kovid", "suterusu", "adore-ng",
}

_SUSPICIOUS_NAMES_LINUX = {
    "reptile_cmd", "reptile", "azazel", "diamorphine",
    "kovid", "suterusu", "adore",
}

_UNIQUE_PROCS_LINUX = {"init", "systemd"}

_EXP_PARENTS_LINUX = {
    "systemd-journald": "systemd",
    "systemd-udevd":    "systemd",
    "systemd-logind":   "systemd",
    "sshd":             "systemd",
    "cron":             "systemd",
    "crond":            "systemd",
}


def _gv(item, *keys):
    for k in keys:
        if k in item:
            return item[k]
    lower_map = {str(k).lower(): k for k in item}
    for k in keys:
        if str(k).lower() in lower_map:
            return item[lower_map[str(k).lower()]]
    return None


class ProcessDumper:
    """Linux process dumper — suspicious detection + ELF/memory dump."""

    def __init__(self, vol: VolatilityWrapper, logger: logging.Logger,
                 jobs: int = 4, timeout: int = 120):
        self.vol = vol
        self.log = logger
        self.jobs = max(1, min(8, jobs))
        self.timeout = timeout
        self._procs: List[Dict[str, Any]] = []
        self._psscan_pids: Set[str] = set()
        self._pslist_pids: Set[str] = set()

    @staticmethod
    def _flatten_pstree(nodes: list) -> list:
        result = []
        for n in nodes:
            result.append(n)
            children = n.get("__children") or n.get("Children") or n.get("children") or []
            if children:
                result.extend(ProcessDumper._flatten_pstree(children))
        return result

    def load_processes(self, output_dir: Path) -> int:
        jd = output_dir / "json"
        if not jd.is_dir():
            return 0
        pslist = load_json_by_pattern(jd, "pslist")
        for p in pslist:
            pid = _gv(p, "PID", "pid", "Pid")
            if pid:
                self._pslist_pids.add(str(pid))
        if not pslist:
            raw_tree = load_json_by_pattern(jd, "pstree")
            if raw_tree:
                pslist = self._flatten_pstree(raw_tree)
                for p in pslist:
                    pid = _gv(p, "PID", "pid", "Pid")
                    if pid:
                        self._pslist_pids.add(str(pid))
                self.log.info("pslist empty — loaded %d procs from pstree", len(pslist))
        psscan = load_json_by_pattern(jd, "psscan")
        for p in psscan:
            pid = _gv(p, "PID", "pid", "Pid")
            if pid:
                self._psscan_pids.add(str(pid))
        cmdlines: Dict[str, str] = {}
        for c in load_json_by_pattern(jd, "cmdline"):
            pid = str(_gv(c, "PID", "pid", "Pid") or "")
            args = _gv(c, "Args", "args", "CommandLine", "CmdLine") or ""
            if pid:
                cmdlines[pid] = str(args)
        for c in load_json_by_pattern(jd, "psaux"):
            pid = str(_gv(c, "PID", "pid", "Pid") or "")
            args = _gv(c, "Arguments", "Args", "args", "ARGS") or ""
            if pid and str(args).strip() and pid not in cmdlines:
                cmdlines[pid] = str(args).strip()
        seen: Set[str] = set()
        for p in pslist + psscan:
            pid = str(_gv(p, "PID", "pid", "Pid") or "")
            if not pid or pid in seen:
                continue
            seen.add(pid)
            self._procs.append({
                "pid": pid,
                "name": str(_gv(p, "ImageFileName", "Name", "Process", "name",
                                "COMM", "Comm") or ""),
                "ppid": str(_gv(p, "PPID", "ppid", "Ppid") or ""),
                "threads": _gv(p, "Threads", "threads", "NumberOfThreads"),
                "offset": str(_gv(p, "Offset", "offset", "Offset(V)",
                                  "OFFSET (V)") or ""),
                "cmdline": cmdlines.get(pid, ""), "flags": [],
            })
        self.log.info("Loaded %d unique processes", len(self._procs))
        return len(self._procs)

    def detect_suspicious(self) -> List[Dict[str, Any]]:
        n2p: Dict[str, List[str]] = {}
        p2n: Dict[str, str] = {}
        for p in self._procs:
            nl = p["name"].lower()
            n2p.setdefault(nl, []).append(p["pid"])
            p2n[p["pid"]] = p["name"]

        pslist_usable = len(self._pslist_pids) > 0
        if not pslist_usable and self._psscan_pids:
            self.log.warning(
                "pslist returned 0 PIDs but psscan returned %d — "
                "skipping 'Hidden' check to avoid false positives.",
                len(self._psscan_pids))

        for p in self._procs:
            p["flags"] = []
            nl = p["name"].lower()
            cmdl = p.get("cmdline", "").lower()
            nl_parts = set(re.split(r"[\W_/\-]", nl))

            for tool in _KNOWN_TOOLS_LINUX:
                if tool in nl_parts or nl == tool:
                    p["flags"].append(f"Known Linux tool: {tool}")
                    break

            if nl in _SUSPICIOUS_NAMES_LINUX:
                p["flags"].append(f"Known rootkit/malware process name: {nl}")

            for suspicious_path in ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/shm/"):
                if suspicious_path in cmdl or suspicious_path in nl:
                    p["flags"].append(f"Execution from writable path: {suspicious_path}")
                    break

            if "base64" in cmdl and ("-d" in cmdl or "--decode" in cmdl):
                p["flags"].append("Base64 decode in cmdline (possible obfuscated payload)")

            if "ld_preload" in cmdl:
                p["flags"].append("LD_PRELOAD in cmdline (possible injection)")

            if any(t in nl for t in ("nc", "ncat", "netcat", "socat")):
                if any(f in cmdl for f in ("-l", "-listen", "listen")):
                    p["flags"].append("Network listener process")

            for child_pattern, expected_parent in _EXP_PARENTS_LINUX.items():
                if child_pattern in nl:
                    actual = p2n.get(p["ppid"], "").lower()
                    if actual and expected_parent not in actual and actual not in ("", "0"):
                        p["flags"].append(
                            f"Unexpected parent: {actual} (expected {expected_parent})")
                    break

            if nl in _UNIQUE_PROCS_LINUX and "--user" not in cmdl:
                system_pids = [
                    pid for pid in n2p.get(nl, [])
                    if "--user" not in next(
                        (q.get("cmdline", "") for q in self._procs if q["pid"] == pid), ""
                    ).lower()
                ]
                if len(system_pids) > 1:
                    p["flags"].append(f"Multiple {nl} system instances: {len(system_pids)}")

            try:
                if p["threads"] is not None and int(p["threads"]) == 0:
                    p["flags"].append("Zero threads")
            except (ValueError, TypeError):
                pass

            if (pslist_usable
                    and p["pid"] in self._psscan_pids
                    and p["pid"] not in self._pslist_pids):
                p["flags"].append("Hidden (psscan only)")

        sus = [p for p in self._procs if p["flags"]]
        self.log.info("Flagged %d Linux processes with observations", len(sus))
        return sus

    def search_processes(self, pattern: str) -> List[Dict[str, Any]]:
        pat = pattern.strip().lower()
        if not pat:
            return []
        return [p for p in self._procs
                if pat in p["name"].lower() or pat == p["pid"]
                or pat in p["cmdline"].lower()]

    def dump_process_exe_verbose(self, image: str, proc: Dict[str, Any],
                                 dump_dir: Path) -> bool:
        dump_dir = Path(dump_dir)
        dump_dir.mkdir(parents=True, exist_ok=True)
        pid = proc["pid"]
        before = sum(1 for _ in dump_dir.iterdir()) if dump_dir.exists() else 0
        ok = self._try_linux_elfs_dump(image, pid, dump_dir)
        if not ok:
            ok = self._try_linux_proc_maps_dump(image, pid, dump_dir)
        if not ok:
            ok = sum(1 for _ in dump_dir.iterdir()) > before if dump_dir.exists() else False
        return ok

    def dump_process_memory_verbose(self, image: str, proc: Dict[str, Any],
                                    dump_dir: Path) -> bool:
        dump_dir = Path(dump_dir)
        dump_dir.mkdir(parents=True, exist_ok=True)
        pid = proc["pid"]
        before = sum(1 for _ in dump_dir.iterdir()) if dump_dir.exists() else 0
        ok = self._try_linux_proc_maps_dump(image, pid, dump_dir)
        if not ok:
            ok = self._try_linux_elfs_dump(image, pid, dump_dir)
        if not ok:
            ok = sum(1 for _ in dump_dir.iterdir()) > before if dump_dir.exists() else False
        return ok

    def _try_linux_elfs_dump(self, image, pid, dump_dir) -> bool:
        before = sum(1 for _ in dump_dir.iterdir()) if dump_dir.exists() else 0
        if self.vol.vol3_cmd:
            msg_info(f"Trying: Vol3 linux.elfs --pid {pid} --dump")
            if self._run_dump_verbose(
                    self.vol.vol3_cmd.split() + [
                        "-f", image, "-o", str(dump_dir),
                        "linux.elfs.Elfs", "--pid", str(pid), "--dump"],
                    f"Vol3 linux.elfs PID {pid}", dump_dir, before):
                return True
        if self.vol.vol2_cmd and self.vol.profile:
            msg_info(f"Trying: Vol2 linux_procdump -p {pid}")
            if self._run_dump_verbose(
                    self.vol.vol2_cmd.split() + [
                        "-f", image, "--profile=" + self.vol.profile,
                        "linux_procdump", "-p", str(pid), "-D", str(dump_dir)],
                    f"Vol2 linux_procdump PID {pid}", dump_dir, before):
                return True
        return False

    def _try_linux_proc_maps_dump(self, image, pid, dump_dir) -> bool:
        before = sum(1 for _ in dump_dir.iterdir()) if dump_dir.exists() else 0
        if self.vol.vol3_cmd:
            msg_info(f"Trying: Vol3 linux.proc.Maps --pid {pid} --dump")
            if self._run_dump_verbose(
                    self.vol.vol3_cmd.split() + [
                        "-f", image, "-o", str(dump_dir),
                        "linux.proc.Maps", "--pid", str(pid), "--dump"],
                    f"Vol3 linux.proc.Maps PID {pid}", dump_dir, before):
                return True
        return False

    def _run_dump_verbose(self, cmd, label, dump_dir, before_count) -> bool:
        try:
            self.log.info("Command: %s", " ".join(cmd))
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=self.timeout)
            after = sum(1 for _ in dump_dir.iterdir()) if dump_dir.exists() else 0
            if after > before_count:
                msg_ok(f"Success! {after - before_count} file(s) extracted")
                if proc.stdout:
                    for line in proc.stdout.strip().splitlines()[:5]:
                        if line.strip() and not line.startswith("***"):
                            print(f"         {line.strip()}")
                return True
            if proc.stderr and proc.stderr.strip():
                real = [l for l in proc.stderr.strip().splitlines()
                        if not l.startswith("***")]
                msg_warn(f"  {real[0][:150]}") if real else msg_warn(
                    f"  No output (rc={proc.returncode})")
            else:
                msg_warn(f"  No output (rc={proc.returncode})")
            return False
        except subprocess.TimeoutExpired:
            msg_warn(f"  Timed out ({self.timeout}s)")
            return False
        except Exception as e:
            msg_warn(f"  Error: {e}")
            return False

    def dump_process_exe(self, image, pid, dump_dir) -> bool:
        dump_dir = Path(dump_dir)
        dump_dir.mkdir(parents=True, exist_ok=True)
        before = sum(1 for _ in dump_dir.iterdir()) if dump_dir.exists() else 0
        if self.vol.vol3_cmd:
            self._run_cmd(self.vol.vol3_cmd.split() + ["-f", image, "-o", str(dump_dir),
                          "linux.elfs.Elfs", "--pid", str(pid), "--dump"])
        elif self.vol.vol2_cmd and self.vol.profile:
            self._run_cmd(self.vol.vol2_cmd.split() + ["-f", image,
                          "--profile=" + self.vol.profile,
                          "linux_procdump", "-p", str(pid), "-D", str(dump_dir)])
        return sum(1 for _ in dump_dir.iterdir()) > before if dump_dir.exists() else False

    def dump_suspicious(self, image, dump_dir, dump_memory=False):
        sus = self.detect_suspicious()
        if not sus:
            return {"total": 0, "dumped": 0, "duration": 0}
        exe_dir = Path(dump_dir) / "process_exe"
        start = time.time()
        dumped = 0
        for p in sus:
            if self.dump_process_exe(image, p["pid"], exe_dir):
                dumped += 1
            if dump_memory:
                mem_dir = Path(dump_dir) / "process_memory"
                mem_dir.mkdir(parents=True, exist_ok=True)
                if self.vol.vol3_cmd:
                    self._run_cmd(self.vol.vol3_cmd.split() + ["-f", image,
                                  "-o", str(mem_dir), "linux.proc.Maps",
                                  "--pid", str(p["pid"]), "--dump"])
        return {"total": len(sus), "dumped": dumped,
                "duration": time.time() - start}

    def dump_all_processes(self, image, dump_dir, dump_memory=False):
        """Dump EVERY loaded process as its native executable (ELF on Linux)."""
        procs = self.processes
        if not procs:
            return {"total": 0, "dumped": 0, "duration": 0}
        exe_dir = Path(dump_dir) / "process_exe"
        exe_dir.mkdir(parents=True, exist_ok=True)
        start = time.time()
        dumped = 0
        seen = set()
        for p in procs:
            pid = p.get("pid")
            if not pid or pid in seen:
                continue
            seen.add(pid)
            try:
                if self.dump_process_exe(image, pid, exe_dir):
                    dumped += 1
            except Exception as e:
                self.log.debug("dump pid %s failed: %s", pid, e)
            if dump_memory and self.vol.vol3_cmd:
                mem_dir = Path(dump_dir) / "process_memory"
                mem_dir.mkdir(parents=True, exist_ok=True)
                self._run_cmd(self.vol.vol3_cmd.split() + ["-f", image,
                              "-o", str(mem_dir), "linux.proc.Maps",
                              "--pid", str(pid), "--dump"])
        self.log.info("dump_all_processes: %d/%d dumped", dumped, len(seen))
        return {"total": len(seen), "dumped": dumped,
                "duration": time.time() - start}

    def _run_cmd(self, cmd):
        try:
            subprocess.run(cmd, capture_output=True, timeout=self.timeout)
        except Exception:
            pass

    def write_suspicious_report(self, output_dir, suspicious=None):
        if suspicious is None:
            suspicious = self.detect_suspicious()
        rp = Path(output_dir) / "suspicious_processes.txt"
        lines = ["=" * 80, "  SUSPICIOUS PROCESS OBSERVATIONS",
                 f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                 "  NOTE: Raw observations only, not threat assessments.",
                 "=" * 80, ""]
        if not suspicious:
            lines.append("  No processes flagged.")
        else:
            for p in suspicious:
                lines.append(f"  PID: {p['pid']}  Name: {p['name']}")
                lines.append(f"  PPID: {p['ppid']}")
                if p["cmdline"]:
                    lines.append(f"  Cmdline: {p['cmdline']}")
                for flag in p["flags"]:
                    lines.append(f"    -> {flag}")
                lines.append("-" * 40)
        lines += ["", "=" * 80, "  END OF REPORT", "=" * 80]
        rp.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.log.info("Suspicious process report: %s", rp)

    @property
    def processes(self):
        return self._procs
