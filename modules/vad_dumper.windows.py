"""vad_dumper.windows.py — VAD (Virtual Address Descriptor) region dumper (Windows).

Dumping a process's PE image (pslist/procdump --dump) gives you the on-disk
executable, NOT what was actually running in memory. The live content — heaps,
stacks, mapped data files, and above all *injected* code — lives in the process's
VAD tree: one node per committed memory region, each with a protection mask, a VAD
tag, and (if backed) a mapped filename.

This module dumps each VAD region to its own file and, crucially, flags the
regions that look like code injection — an executable+writable (RWX) region, or an
executable *private* region with no backing file (classic shellcode). That is how
you see "what was actually going on" inside, say, notepad.exe.

Engine mapping:
  * Vol3:  windows.vadinfo.VadInfo --pid P --dump   (per-region .dmp files + JSON)
  * Vol2:  vaddump -p P -D <dir>                     (per-region .dmp files)
"""

import json
import logging
import subprocess
import time
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from modules.volatility import VolatilityWrapper
from utils.json_converter import load_json_by_pattern
from utils.ui import msg_info, msg_ok, msg_warn, msg_fail


def _gv(item, *keys):
    for k in keys:
        if k in item:
            return item[k]
    low = {str(k).lower(): k for k in item}
    for k in keys:
        if str(k).lower() in low:
            return item[low[str(k).lower()]]
    return None


def _is_injection(protection: str, file_backed: bool) -> Optional[str]:
    """Return a human reason if this VAD region looks like injected code, else None.
    Pure: works off the protection string + whether the region is file-backed.

    Note: PAGE_EXECUTE_WRITECOPY is NORMAL for a mapped image (copy-on-write code),
    so 'WRITE' alone is not enough — only true READWRITE counts as the RWX signal.
    """
    p = (protection or "").upper()
    execu = "EXECUTE" in p
    if execu and "READWRITE" in p:
        return "RWX region (execute+read+write) — classic code injection"
    if execu and not file_backed and "WRITECOPY" not in p:
        return "executable PRIVATE region (no backing file) — possible shellcode"
    return None


class VADDumper:
    """Windows VAD-region dumper: list regions, dump them, flag injection."""

    def __init__(self, vol: VolatilityWrapper, logger: logging.Logger,
                 jobs: int = 4, timeout: int = 300):
        self.vol = vol
        self.log = logger
        self.jobs = max(1, min(8, jobs))
        self.timeout = timeout
        self._procs: List[Dict[str, Any]] = []

    # -- process loading (mirrors process_dumper: read from json/) --
    def load_processes(self, output_dir: Path) -> int:
        jd = Path(output_dir) / "json"
        if not jd.is_dir():
            return 0
        seen: Set[str] = set()
        for p in (load_json_by_pattern(jd, "pslist")
                  + load_json_by_pattern(jd, "psscan")):
            pid = str(_gv(p, "PID", "pid", "Pid") or "")
            if not pid or pid in seen:
                continue
            seen.add(pid)
            self._procs.append({
                "pid": pid,
                "name": str(_gv(p, "ImageFileName", "Name", "Process", "name") or ""),
                "ppid": str(_gv(p, "PPID", "ppid", "InheritedFromUniqueProcessId") or ""),
            })
        self.log.info("VAD dumper loaded %d processes", len(self._procs))
        return len(self._procs)

    def search_processes(self, pattern: str) -> List[Dict[str, Any]]:
        pat = (pattern or "").strip().lower()
        if not pat:
            return []
        return [p for p in self._procs
                if pat in p["name"].lower() or pat == p["pid"]]

    # -- the VAD region map (no dump) — the "what regions exist" view --
    def list_vads(self, image: str, pid: str) -> List[Dict[str, Any]]:
        """Return the VAD regions for a PID: start, end, protection, tag, file."""
        if not self.vol.vol3_cmd:
            return []
        cmd = self.vol.vol3_cmd.split() + [
            "-q", "-r", "json", "-f", image,
            "windows.vadinfo.VadInfo", "--pid", str(pid)]
        rows = self._run_json(cmd)
        out = []
        for r in rows:
            prot = str(_gv(r, "Protection", "protection") or "")
            fn = _gv(r, "File", "FileName", "file")
            fb = bool(fn) and str(fn).lower() not in ("", "none", "null")
            out.append({
                "start": _gv(r, "Start VPN", "Start", "Start Address", "start"),
                "end": _gv(r, "End VPN", "End", "End Address", "end"),
                "tag": _gv(r, "Tag", "VadTag", "tag"),
                "protection": prot,
                "file": fn if fb else None,
                "injection": _is_injection(prot, fb),
            })
        return out

    # -- dump the VAD regions of ONE process --
    def dump_vads(self, image: str, pid: str, dump_dir: Path,
                  name: str = "") -> Dict[str, Any]:
        dump_dir = Path(dump_dir)
        dump_dir.mkdir(parents=True, exist_ok=True)
        before = _snapshot(dump_dir)
        res: Dict[str, Any] = {"pid": pid, "name": name, "regions": 0,
                               "files": [], "injection": [], "bytes": 0, "engine": None}

        ok = False
        if self.vol.vol_version == "vol3" or (self.vol.vol3_cmd and not self.vol.profile):
            ok = self._dump_vol3(image, pid, dump_dir); res["engine"] = "vol3"
            if not ok and self.vol.vol2_cmd and self.vol.profile:
                ok = self._dump_vol2(image, pid, dump_dir); res["engine"] = "vol2"
        else:
            ok = self._dump_vol2(image, pid, dump_dir); res["engine"] = "vol2"
            if not ok and self.vol.vol3_cmd:
                ok = self._dump_vol3(image, pid, dump_dir); res["engine"] = "vol3"

        new_files = [f for f in dump_dir.iterdir() if f.is_file() and str(f) not in before]
        # annotate + hash each dumped region; correlate injection flags by address
        inj_map = {}
        try:
            for v in self.list_vads(image, pid):
                if v.get("injection"):
                    inj_map[_hex(v.get("start"))] = v["injection"]
        except Exception:
            pass
        for f in sorted(new_files):
            try:
                data = f.read_bytes()
            except Exception:
                continue
            entry = {"file": f.name, "size": len(data),
                     "sha256": sha256(data).hexdigest()[:32]}
            for addr, reason in inj_map.items():
                if addr and addr in f.name.lower():
                    entry["injection"] = reason
                    res["injection"].append({"file": f.name, "reason": reason})
                    break
            res["files"].append(entry)
            res["bytes"] += len(data)
        res["regions"] = len(new_files)
        return res

    def _dump_vol3(self, image, pid, dump_dir) -> bool:
        before = _snapshot(dump_dir)
        cmd = self.vol.vol3_cmd.split() + [
            "-q", "-f", image, "-o", str(dump_dir),
            "windows.vadinfo.VadInfo", "--pid", str(pid), "--dump"]
        return self._run_dump(cmd, f"Vol3 vadinfo --dump PID {pid}", dump_dir, before)

    def _dump_vol2(self, image, pid, dump_dir) -> bool:
        if not (self.vol.vol2_cmd and self.vol.profile):
            return False
        before = _snapshot(dump_dir)
        cmd = self.vol.vol2_cmd.split() + [
            "-f", image, "--profile=" + self.vol.profile,
            "vaddump", "-p", str(pid), "-D", str(dump_dir)]
        return self._run_dump(cmd, f"Vol2 vaddump -p {pid}", dump_dir, before)

    # -- DFIR bulk paths --
    def dump_suspicious(self, image: str, dump_dir: Path,
                        suspicious_pids: List[str]) -> Dict[str, Any]:
        """Dump VADs for a given set of PIDs (e.g. the suspicious ones)."""
        return self._dump_many(image, dump_dir,
                               [p for p in self._procs if p["pid"] in set(map(str, suspicious_pids))])

    def dump_all(self, image: str, dump_dir: Path,
                 max_procs: int = 0) -> Dict[str, Any]:
        """Dump VADs for EVERY loaded process (used by DFIR / dump-everything).
        max_procs>0 caps how many processes (0 = no cap)."""
        procs = self._procs[:max_procs] if max_procs else self._procs
        return self._dump_many(image, dump_dir, procs)

    def _dump_many(self, image, dump_dir, procs) -> Dict[str, Any]:
        base = Path(dump_dir) / "vad_dumps"
        base.mkdir(parents=True, exist_ok=True)
        start = time.time()
        per_proc: List[Dict[str, Any]] = []
        total_regions = total_inj = 0
        for p in procs:
            pdir = base / f"pid_{p['pid']}_{_safe(p['name'])}"
            msg_info(f"VAD dump: PID {p['pid']} ({p['name'] or '?'})")
            r = self.dump_vads(image, p["pid"], pdir, p["name"])
            if r["regions"]:
                msg_ok(f"  {r['regions']} regions, {r['bytes']//1024} KB"
                       + (f", {len(r['injection'])} INJECTION FLAG(S)" if r["injection"] else ""))
            per_proc.append(r)
            total_regions += r["regions"]
            total_inj += len(r["injection"])
        return {"processes": len(procs), "total_regions": total_regions,
                "injection_flags": total_inj, "per_proc": per_proc,
                "duration": time.time() - start, "dir": str(base)}

    def write_report(self, output_dir, results: Dict[str, Any]) -> Path:
        rp = Path(output_dir) / "vad_dump_report.txt"
        L = ["=" * 78, "  VAD MEMORY-REGION DUMP REPORT",
             f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
             "  Each region = one process memory area (heap/stack/mapped/injected).",
             "  Injection flags are OBSERVATIONS, not verdicts — verify.",
             "=" * 78, "",
             f"  Processes dumped : {results.get('processes', 0)}",
             f"  Total regions    : {results.get('total_regions', 0)}",
             f"  Injection flags  : {results.get('injection_flags', 0)}",
             f"  Output dir       : {results.get('dir', '?')}", ""]
        for pr in results.get("per_proc", []):
            if not pr.get("regions"):
                continue
            L.append(f"  PID {pr['pid']}  {pr['name']}  —  {pr['regions']} regions,"
                     f" {pr['bytes']//1024} KB  [{pr.get('engine')}]")
            for inj in pr.get("injection", []):
                L.append(f"      [!] {inj['file']} — {inj['reason']}")
            L.append("-" * 40)
        L += ["", "=" * 78, "  END OF REPORT", "=" * 78]
        rp.write_text("\n".join(L) + "\n", encoding="utf-8")
        self.log.info("VAD dump report: %s", rp)
        return rp

    # -- subprocess helpers --
    def _run_json(self, cmd) -> List[Dict[str, Any]]:
        try:
            p = subprocess.run(cmd, capture_output=True, text=True,
                               errors="replace", timeout=self.timeout)
            out = "\n".join(l for l in p.stdout.splitlines()
                            if not l.startswith("Progress:"))
            s = out.strip()
            if s[:1] in ("[", "{"):
                data = json.loads(s)
                return data if isinstance(data, list) else [data]
        except Exception as e:
            self.log.debug("vadinfo json failed: %s", e)
        return []

    def _run_dump(self, cmd, label, dump_dir, before) -> bool:
        try:
            self.log.info("Command: %s", " ".join(cmd))
            p = subprocess.run(cmd, capture_output=True, text=True,
                               errors="replace", timeout=self.timeout)
            after = _snapshot(dump_dir)
            if len(after) > len(before):
                return True
            if p.stderr and p.stderr.strip():
                real = [l for l in p.stderr.strip().splitlines() if not l.startswith("***")]
                if real:
                    self.log.debug("%s: %s", label, real[-1][:200])
            return False
        except subprocess.TimeoutExpired:
            msg_warn(f"  {label}: timed out ({self.timeout}s)")
            return False
        except Exception as e:
            msg_warn(f"  {label}: {e}")
            return False

    @property
    def processes(self):
        return self._procs


def _snapshot(d: Path) -> Set[str]:
    try:
        return {str(f) for f in Path(d).iterdir() if f.is_file()}
    except Exception:
        return set()


def _safe(name: str) -> str:
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in (name or "proc"))[:32]


def _hex(v) -> str:
    try:
        return hex(int(v)).lower() if v is not None and str(v).isdigit() else str(v).lower()
    except Exception:
        return str(v).lower()
