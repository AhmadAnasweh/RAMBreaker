"""vad_dumper.linux.py — memory-region dumper (Linux).

VAD is a Windows term; the Linux equivalent is the process memory map. This module
keeps the same VAD-dumper interface but dumps each mapped region via Vol3
``linux.proc.Maps --pid P --dump`` — heaps, stacks, mapped files, and anonymous
executable regions (the shellcode analogue). Injection heuristic: a region that is
both writable and executable, or an executable region with no backing file.
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
from utils.ui import msg_info, msg_ok, msg_warn


def _gv(item, *keys):
    for k in keys:
        if k in item:
            return item[k]
    low = {str(k).lower(): k for k in item}
    for k in keys:
        if str(k).lower() in low:
            return item[low[str(k).lower()]]
    return None


def _is_injection(flags: str, file_backed: bool) -> Optional[str]:
    f = (flags or "").lower()
    if "w" in f and "x" in f:
        return "writable+executable region — possible code injection"
    if "x" in f and not file_backed:
        return "executable anonymous region (no backing file) — possible shellcode"
    return None


class VADDumper:
    """Linux memory-region dumper (VAD-dumper interface, proc.Maps under the hood)."""

    def __init__(self, vol: VolatilityWrapper, logger: logging.Logger,
                 jobs: int = 4, timeout: int = 300):
        self.vol = vol
        self.log = logger
        self.timeout = timeout
        self._procs: List[Dict[str, Any]] = []

    def load_processes(self, output_dir: Path) -> int:
        jd = Path(output_dir) / "json"
        if not jd.is_dir():
            return 0
        seen: Set[str] = set()
        for p in (load_json_by_pattern(jd, "pslist")
                  + load_json_by_pattern(jd, "psaux")):
            pid = str(_gv(p, "PID", "pid", "Pid") or "")
            if not pid or pid in seen:
                continue
            seen.add(pid)
            self._procs.append({
                "pid": pid,
                "name": str(_gv(p, "COMM", "Comm", "Name", "name", "Process") or ""),
                "ppid": str(_gv(p, "PPID", "ppid") or ""),
            })
        self.log.info("VAD dumper loaded %d Linux processes", len(self._procs))
        return len(self._procs)

    def search_processes(self, pattern: str) -> List[Dict[str, Any]]:
        pat = (pattern or "").strip().lower()
        if not pat:
            return []
        return [p for p in self._procs
                if pat in p["name"].lower() or pat == p["pid"]]

    def list_vads(self, image: str, pid: str) -> List[Dict[str, Any]]:
        if not self.vol.vol3_cmd:
            return []
        cmd = self.vol.vol3_cmd.split() + [
            "-q", "-r", "json", "-f", image,
            "linux.proc.Maps", "--pid", str(pid)]
        out = []
        for r in self._run_json(cmd):
            flags = str(_gv(r, "Flags", "flags", "Protection", "PgOff") or "")
            path = _gv(r, "File Path", "Path", "path", "File")
            fb = bool(path) and str(path).lower() not in ("", "none", "null")
            out.append({
                "start": _gv(r, "Start", "Start Address", "start"),
                "end": _gv(r, "End", "End Address", "end"),
                "protection": flags,
                "file": path if fb else None,
                "injection": _is_injection(flags, fb),
            })
        return out

    def dump_vads(self, image: str, pid: str, dump_dir: Path,
                  name: str = "") -> Dict[str, Any]:
        dump_dir = Path(dump_dir)
        dump_dir.mkdir(parents=True, exist_ok=True)
        before = _snapshot(dump_dir)
        res: Dict[str, Any] = {"pid": pid, "name": name, "regions": 0,
                               "files": [], "injection": [], "bytes": 0, "engine": "vol3"}
        if self.vol.vol3_cmd:
            cmd = self.vol.vol3_cmd.split() + [
                "-q", "-f", image, "-o", str(dump_dir),
                "linux.proc.Maps", "--pid", str(pid), "--dump"]
            self._run_dump(cmd, f"Linux proc.Maps --dump PID {pid}", dump_dir, before)
        new_files = [f for f in dump_dir.iterdir() if f.is_file() and str(f) not in before]
        inj = [v["injection"] for v in self.list_vads(image, pid) if v.get("injection")]
        for f in sorted(new_files):
            try:
                data = f.read_bytes()
            except Exception:
                continue
            res["files"].append({"file": f.name, "size": len(data),
                                 "sha256": sha256(data).hexdigest()[:32]})
            res["bytes"] += len(data)
        # region-level injection is address-correlated best-effort on Linux; report count
        for reason in inj[:20]:
            res["injection"].append({"file": "(region)", "reason": reason})
        res["regions"] = len(new_files)
        return res

    def dump_suspicious(self, image, dump_dir, suspicious_pids) -> Dict[str, Any]:
        return self._dump_many(image, dump_dir,
                               [p for p in self._procs if p["pid"] in set(map(str, suspicious_pids))])

    def dump_all(self, image, dump_dir, max_procs: int = 0) -> Dict[str, Any]:
        procs = self._procs[:max_procs] if max_procs else self._procs
        return self._dump_many(image, dump_dir, procs)

    def _dump_many(self, image, dump_dir, procs) -> Dict[str, Any]:
        base = Path(dump_dir) / "vad_dumps"
        base.mkdir(parents=True, exist_ok=True)
        start = time.time()
        per_proc, total_regions, total_inj = [], 0, 0
        for p in procs:
            pdir = base / f"pid_{p['pid']}_{_safe(p['name'])}"
            msg_info(f"Region dump: PID {p['pid']} ({p['name'] or '?'})")
            r = self.dump_vads(image, p["pid"], pdir, p["name"])
            if r["regions"]:
                msg_ok(f"  {r['regions']} regions, {r['bytes']//1024} KB"
                       + (f", {len(r['injection'])} flag(s)" if r["injection"] else ""))
            per_proc.append(r)
            total_regions += r["regions"]
            total_inj += len(r["injection"])
        return {"processes": len(procs), "total_regions": total_regions,
                "injection_flags": total_inj, "per_proc": per_proc,
                "duration": time.time() - start, "dir": str(base)}

    def write_report(self, output_dir, results) -> Path:
        rp = Path(output_dir) / "vad_dump_report.txt"
        L = ["=" * 78, "  MEMORY-REGION (VAD-equivalent) DUMP REPORT — Linux",
             f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
             "  Each region = one process memory map (heap/stack/mapped/anon).",
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
                     f" {pr['bytes']//1024} KB")
            for inj in pr.get("injection", [])[:8]:
                L.append(f"      [!] {inj['reason']}")
            L.append("-" * 40)
        L += ["", "=" * 78, "  END OF REPORT", "=" * 78]
        rp.write_text("\n".join(L) + "\n", encoding="utf-8")
        self.log.info("VAD dump report: %s", rp)
        return rp

    def _run_json(self, cmd) -> List[Dict[str, Any]]:
        try:
            p = subprocess.run(cmd, capture_output=True, text=True,
                               errors="replace", timeout=self.timeout)
            out = "\n".join(l for l in p.stdout.splitlines() if not l.startswith("Progress:"))
            s = out.strip()
            if s[:1] in ("[", "{"):
                data = json.loads(s)
                return data if isinstance(data, list) else [data]
        except Exception as e:
            self.log.debug("proc.Maps json failed: %s", e)
        return []

    def _run_dump(self, cmd, label, dump_dir, before) -> bool:
        try:
            self.log.info("Command: %s", " ".join(cmd))
            subprocess.run(cmd, capture_output=True, text=True,
                          errors="replace", timeout=self.timeout)
            return len(_snapshot(dump_dir)) > len(before)
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
