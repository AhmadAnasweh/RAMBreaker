"""CresCent RAM Forensics Toolkit v6.0 - Process Dumper (Windows)"""

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
from modules.platform_compat import split_cmd

_KNOWN_TOOLS = {"mimikatz", "procdump", "psexec", "nc", "netcat", "ncat",
                "meterpreter", "cobalt", "beacon", "lazagne", "rubeus",
                "seatbelt", "sharphound", "bloodhound", "winpeas", "chisel"}

# csrss.exe runs once PER SESSION (session 0 + each logged-on session), so two
# or more are normal and are not flagged (v2: was a false positive on every
# Win7+ dump with an interactive logon).
# Processes that legitimately show 0 threads to the normal kernel view
# ("Secure System" = VBS/VSM trustlet host; its threads live in VTL1).
_ZERO_THREAD_OK = {"secure system"}

# psscan-only processes created this close to (or after) the capture clock are
# most likely memory smear from a live acquisition, not unlinked/hidden processes.
_SMEAR_WINDOW_S = 15 * 60

_UNIQUE_PROCS = {"lsass.exe", "services.exe", "wininit.exe", "lsm.exe", "smss.exe"}

_EXP_PARENTS = {"svchost.exe": "services.exe", "lsass.exe": "wininit.exe",
                "services.exe": "wininit.exe", "wininit.exe": "smss.exe",
                "csrss.exe": "smss.exe", "winlogon.exe": "smss.exe",
                "smss.exe": "System"}


def _gv(item, *keys):
    for k in keys:
        if k in item:
            return item[k]
    lower_map = {str(k).lower(): k for k in item}
    for k in keys:
        if str(k).lower() in lower_map:
            return item[lower_map[str(k).lower()]]
    return None


def _has_time(v) -> bool:
    """True when a Volatility timestamp field holds a real time (not None/N/A/epoch 0)."""
    if v is None:
        return False
    t = str(v).strip()
    return bool(t) and t.upper() not in ("N/A", "NONE", "NULL", "-", "0") and not t.startswith(("1970-01-01", "1601-01-01"))


def _parse_time(v):
    """Volatility 3 timestamp ('2026-11-12T14:02:42+00:00' / '2026-11-12 14:02:42+00:00')."""
    if not _has_time(v):
        return None
    t = str(v).strip().replace(" ", "T", 1).replace("Z", "+00:00")
    try:
        d = datetime.fromisoformat(t.split(".")[0] if "+" not in t else t)
    except ValueError:
        return None
    if d.tzinfo is None:
        from datetime import timezone
        d = d.replace(tzinfo=timezone.utc)
    return d


class ProcessDumper:
    """Windows process dumper — suspicious detection + exe/memory dump."""

    def __init__(self, vol: VolatilityWrapper, logger: logging.Logger,
                 jobs: int = 4, timeout: int = 120):
        self.vol = vol
        self.log = logger
        self.jobs = max(1, min(8, jobs))
        self.timeout = timeout
        self._procs: List[Dict[str, Any]] = []
        self._psscan_pids: Set[str] = set()
        self._pslist_pids: Set[str] = set()
        self._capture_time = None

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
        for r in load_json_by_pattern(jd, "windows_info"):
            if str(_gv(r, "Variable", "variable") or "") == "SystemTime":
                self._capture_time = _parse_time(_gv(r, "Value", "value"))
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
        seen: Set[str] = set()
        for p in pslist + psscan:
            pid = str(_gv(p, "PID", "pid", "Pid") or "")
            if not pid or pid in seen:
                continue
            seen.add(pid)
            self._procs.append({
                "pid": pid,
                "name": str(_gv(p, "ImageFileName", "Name", "Process", "name") or ""),
                "ppid": str(_gv(p, "PPID", "ppid", "Ppid",
                                "InheritedFromUniqueProcessId") or ""),
                "threads": _gv(p, "Threads", "threads", "NumberOfThreads"),
                "offset": str(_gv(p, "Offset", "offset", "Offset(V)") or ""),
                "exit_time": _gv(p, "ExitTime", "Exit Time", "exit_time"),
                "create_time": _gv(p, "CreateTime", "Create Time", "create_time"),
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
            words = set(re.split(r"[^a-z0-9]+", nl.rsplit(".exe", 1)[0]))
            for tool in sorted(_KNOWN_TOOLS):
                # short names (nc, ...) only as a whole word: 'nc' is inside 'Sync', 'ShellExperienc'
                if (tool in words) if len(tool) <= 4 else (tool in nl):
                    p["flags"].append(f"Known tool: {tool}")
                    break
            if nl in _EXP_PARENTS:
                actual = p2n.get(p["ppid"], "").lower()
                if actual and _EXP_PARENTS[nl].lower() not in actual:
                    p["flags"].append(
                        f"Unexpected parent: {actual} (expected {_EXP_PARENTS[nl]})")
            if nl in {u.lower() for u in _UNIQUE_PROCS}:
                if len(n2p.get(nl, [])) > 1:
                    p["flags"].append(f"Multiple instances: {len(n2p[nl])}")
            # An EPROCESS with an ExitTime is a terminated process whose object is still
            # referenced (or a freed pool block psscan carved): 0 threads and absence from
            # the active list are then normal, not signs of hiding.
            exited = _has_time(p.get("exit_time"))
            try:
                if p["threads"] is not None and int(p["threads"]) == 0 and not exited \
                        and nl not in _ZERO_THREAD_OK:
                    p["flags"].append("Zero threads")
            except (ValueError, TypeError):
                pass
            if (pslist_usable and not exited
                    and p["pid"] in self._psscan_pids
                    and p["pid"] not in self._pslist_pids):
                ct = _parse_time(p.get("create_time"))
                gap = (self._capture_time - ct).total_seconds() \
                    if (ct and self._capture_time) else None
                if gap is not None and gap < 0:
                    self.log.info("PID %s %s: psscan only, created %ds after the capture clock - "
                                  "acquisition smear, not flagged", p["pid"], p["name"], -gap)
                elif gap is not None and gap <= _SMEAR_WINDOW_S:
                    p["flags"].append(f"psscan only, started {int(gap // 60)} min before capture "
                                      "(likely acquisition smear)")
                else:
                    p["flags"].append("Hidden (psscan only, still running)")
        sus = [p for p in self._procs if p["flags"]]
        self.log.info("Flagged %d processes with observations", len(sus))
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
        if self.vol.vol_version == "vol2":
            ok = self._try_vol2_procdump(image, pid, dump_dir)
            if not ok and self.vol.vol3_cmd:
                ok = self._try_vol3_procdump(image, pid, dump_dir)
        else:
            ok = self._try_vol3_procdump(image, pid, dump_dir)
            if not ok and self.vol.vol2_cmd and self.vol.profile:
                ok = self._try_vol2_procdump(image, pid, dump_dir)
        if not ok:
            ok = sum(1 for _ in dump_dir.iterdir()) > before if dump_dir.exists() else False
        return ok

    def dump_process_memory_verbose(self, image: str, proc: Dict[str, Any],
                                    dump_dir: Path) -> bool:
        dump_dir = Path(dump_dir)
        dump_dir.mkdir(parents=True, exist_ok=True)
        pid = proc["pid"]
        before = sum(1 for _ in dump_dir.iterdir()) if dump_dir.exists() else 0
        if self.vol.vol_version == "vol2" and self.vol.vol2_cmd and self.vol.profile:
            msg_info(f"Trying: Vol2 memdump -p {pid}")
            if self._run_dump_verbose(
                    split_cmd(self.vol.vol2_cmd) + [
                        "-f", image, "--profile=" + self.vol.profile,
                        "memdump", "-p", str(pid), "-D", str(dump_dir)],
                    f"Vol2 memdump PID {pid}", dump_dir, before):
                return True
        if self.vol.vol3_cmd:
            msg_info(f"Trying: Vol3 memmap --pid {pid} --dump")
            if self._run_dump_verbose(
                    split_cmd(self.vol.vol3_cmd) + [
                        "-f", image, "-o", str(dump_dir),
                        "windows.memmap.Memmap", "--pid", str(pid), "--dump"],
                    f"Vol3 memmap PID {pid}", dump_dir, before):
                return True
        if self.vol.vol_version != "vol2" and self.vol.vol2_cmd and self.vol.profile:
            msg_info(f"Trying: Vol2 memdump -p {pid}")
            if self._run_dump_verbose(
                    split_cmd(self.vol.vol2_cmd) + [
                        "-f", image, "--profile=" + self.vol.profile,
                        "memdump", "-p", str(pid), "-D", str(dump_dir)],
                    f"Vol2 memdump PID {pid}", dump_dir, before):
                return True
        return False

    def _try_vol2_procdump(self, image, pid, dump_dir) -> bool:
        if not self.vol.vol2_cmd or not self.vol.profile:
            msg_warn("Vol2 not available or no profile")
            return False
        base = split_cmd(self.vol.vol2_cmd) + [
            "-f", image, "--profile=" + self.vol.profile]
        before = sum(1 for _ in dump_dir.iterdir()) if dump_dir.exists() else 0
        msg_info(f"Trying: Vol2 procdump -p {pid}")
        if self._run_dump_verbose(
                base + ["procdump", "-p", str(pid), "-D", str(dump_dir)],
                f"Vol2 procdump PID {pid}", dump_dir, before):
            return True
        msg_info(f"Trying: Vol2 dlldump -p {pid}")
        return self._run_dump_verbose(
            base + ["dlldump", "-p", str(pid), "-D", str(dump_dir)],
            f"Vol2 dlldump PID {pid}", dump_dir, before)

    def _try_vol3_procdump(self, image, pid, dump_dir) -> bool:
        if not self.vol.vol3_cmd:
            return False
        before = sum(1 for _ in dump_dir.iterdir()) if dump_dir.exists() else 0
        msg_info(f"Trying: Vol3 pslist --pid {pid} --dump")
        if self._run_dump_verbose(
                split_cmd(self.vol.vol3_cmd) + [
                    "-f", image, "-o", str(dump_dir),
                    "windows.pslist.PsList", "--pid", str(pid), "--dump"],
                f"Vol3 pslist --pid {pid} --dump", dump_dir, before):
            return True
        msg_info(f"Trying: Vol3 dlllist --pid {pid} --dump")
        return self._run_dump_verbose(
            split_cmd(self.vol.vol3_cmd) + [
                "-f", image, "-o", str(dump_dir),
                "windows.dlllist.DllList", "--pid", str(pid), "--dump"],
            f"Vol3 dlllist --pid {pid} --dump", dump_dir, before)

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
        if self.vol.vol_version == "vol2" and self.vol.vol2_cmd and self.vol.profile:
            self._run_cmd(split_cmd(self.vol.vol2_cmd) + ["-f", image,
                          "--profile=" + self.vol.profile, "procdump",
                          "-p", str(pid), "-D", str(dump_dir)])
        elif self.vol.vol3_cmd:
            self._run_cmd(split_cmd(self.vol.vol3_cmd) + ["-f", image, "-o", str(dump_dir),
                          "windows.pslist.PsList", "--pid", str(pid), "--dump"])
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
                if self.vol.vol_version == "vol2" and self.vol.vol2_cmd and self.vol.profile:
                    self._run_cmd(split_cmd(self.vol.vol2_cmd) + ["-f", image,
                                  "--profile=" + self.vol.profile, "memdump",
                                  "-p", str(p["pid"]), "-D", str(mem_dir)])
                elif self.vol.vol3_cmd:
                    self._run_cmd(split_cmd(self.vol.vol3_cmd) + ["-f", image,
                                  "-o", str(mem_dir), "windows.memmap.Memmap",
                                  "--pid", str(p["pid"]), "--dump"])
        return {"total": len(sus), "dumped": dumped,
                "duration": time.time() - start}

    def dump_all_processes(self, image, dump_dir, dump_memory=False):
        """Dump EVERY loaded process as its native executable (PE on Windows).

        Used by the dump-everything mode. Iterates the full process list (pslist
        + psscan union) and writes each process's on-disk PE image.
        """
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
                self._run_cmd(split_cmd(self.vol.vol3_cmd) + ["-f", image,
                              "-o", str(mem_dir), "windows.memmap.Memmap",
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
                    lines.append(f"  CmdLine: {p['cmdline']}")
                for flag in p["flags"]:
                    lines.append(f"    -> {flag}")
                lines.append("-" * 40)
        lines += ["", "=" * 80, "  END OF REPORT", "=" * 80]
        rp.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.log.info("Suspicious process report: %s", rp)

    @property
    def processes(self):
        return self._procs
