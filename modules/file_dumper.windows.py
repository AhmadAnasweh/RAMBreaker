"""CresCent RAM Forensics Toolkit v6.0 - File Dumper (Windows)

Windows file dumping via filescan + windows.dumpfiles.DumpFiles (Vol3)
or dumpfiles -Q (Vol2).
"""

import logging
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional

from modules.volatility import VolatilityWrapper
from utils.json_converter import load_json_safe
from utils.ui import msg_info, msg_ok, msg_warn, progress_line


class FileDumper:
    """Extract files from Windows memory using filescan output."""

    _OFF_KEYS = ("Offset", "offset", "Offset(V)", "Offset(P)", "offset(v)", "offset(p)")
    _NAME_KEYS = ("Name", "name", "FileName", "filename", "File Name", "file name")

    def __init__(self, vol: VolatilityWrapper, logger: logging.Logger,
                 jobs: int = 8, timeout: int = 90):
        self.vol = vol
        self.log = logger
        self.jobs = max(1, min(16, jobs))
        self.timeout = timeout
        self._files: List[Dict[str, str]] = []

    def find_filescan_json(self, output_dir: Path) -> Optional[Path]:
        for sp in [output_dir / "json", output_dir]:
            if not sp.is_dir():
                continue
            for pat in ["*filescan*.json", "*FileScan*.json", "*FILESCAN*.json"]:
                m = list(sp.glob(pat))
                if m:
                    self.log.info("Found filescan JSON: %s", m[0])
                    return m[0]
        self.log.error("No filescan JSON found in %s", output_dir)
        return None

    def parse_filescan(self, path: Path) -> int:
        data = load_json_safe(path)
        if not isinstance(data, list):
            self.log.error("Filescan JSON is not a list (got %s)", type(data).__name__)
            return 0
        self._files.clear()
        skipped = 0
        for item in data:
            if not isinstance(item, dict):
                continue
            off = self._get_off(item)
            nm = self._get_name(item)
            if not off or not nm:
                skipped += 1
                continue
            short = nm.rsplit("\\", 1)[-1] if "\\" in nm else (
                nm.rsplit("/", 1)[-1] if "/" in nm else nm)
            self._files.append({"offset": off, "path": nm, "filename": short})
        if skipped and not self._files and data and isinstance(data[0], dict):
            self.log.debug("Filescan first record keys: %s", list(data[0].keys()))
            self.log.debug("Filescan first record: %s", str(data[0])[:300])
        self.log.info("Parsed %d files from filescan (%d skipped)", len(self._files), skipped)
        return len(self._files)

    def _get_off(self, item):
        for k in self._OFF_KEYS:
            if k in item:
                v = item[k]
                return hex(v) if isinstance(v, int) else str(v)
        for k, v in item.items():
            if "offset" in k.lower():
                return hex(v) if isinstance(v, int) else str(v)
        return None

    def _get_name(self, item):
        for k in self._NAME_KEYS:
            if k in item:
                return str(item[k])
        for k, v in item.items():
            if k.lower().endswith("name") or k.lower() == "name":
                return self._extract_path_from_value(str(v))
        for k, v in item.items():
            sv = str(v)
            if "\\Device\\" in sv or "\\Windows\\" in sv or "\\Users\\" in sv:
                return self._extract_path_from_value(sv)
        return None

    @staticmethod
    def _extract_path_from_value(value: str) -> str:
        value = value.strip()
        if value.startswith("\\") or (len(value) >= 2 and value[1] == ":"):
            return value
        m = re.search(r"(\\Device\\[^\s].*|\\[A-Za-z].*|[A-Z]:\\.*)", value)
        if m:
            return m.group(1)
        parts = value.split()
        for part in reversed(parts):
            if "\\" in part or "/" in part:
                return part
        return value

    def dump_by_extension(self, image, ext, dump_dir):
        ext_l = ext.lower().lstrip(".")
        matches = [f for f in self._files if f["filename"].lower().endswith(f".{ext_l}")]
        if not matches:
            self.log.warning("No .%s files found", ext_l)
            return {"total": 0, "attempted": 0, "dumped_files": 0, "duration": 0}
        return self._dump(image, matches, dump_dir)

    def dump_by_pattern(self, image, pattern, dump_dir):
        pl = pattern.lower()
        matches = [f for f in self._files
                   if pl in f["filename"].lower() or pl in f["path"].lower()]
        if not matches:
            self.log.warning("No files matching '%s'", pattern)
            return {"total": 0, "attempted": 0, "dumped_files": 0, "duration": 0}
        return self._dump(image, matches, dump_dir)

    def dump_all(self, image, dump_dir):
        if not self._files:
            return {"total": 0, "attempted": 0, "dumped_files": 0, "duration": 0}
        return self._dump(image, self._files, dump_dir)

    def _dump(self, image, flist, dump_dir):
        dump_dir = Path(dump_dir)
        dump_dir.mkdir(parents=True, exist_ok=True)
        start = time.time()
        attempted = succeeded = 0
        with ThreadPoolExecutor(max_workers=self.jobs) as pool:
            futures = {pool.submit(self._dump_one, image, f["offset"], dump_dir): f
                       for f in flist}
            total = len(futures)
            done = 0
            for fut in as_completed(futures):
                done += 1
                attempted += 1
                try:
                    if fut.result():
                        succeeded += 1
                except Exception:
                    pass
                if done % 10 == 0 or done == total:
                    progress_line(done, total, "files dumped")
        dur = time.time() - start
        actual = sum(1 for _ in dump_dir.iterdir()) if dump_dir.exists() else 0
        self.log.info("Dump: %d attempted, %d actual files in %s (%.1fs)",
                      attempted, actual, dump_dir, dur)
        return {"total": len(flist), "attempted": attempted,
                "dumped_files": actual, "duration": dur}

    def _dump_one(self, image, offset, dump_dir):
        dump_dir = Path(dump_dir)
        dump_dir.mkdir(parents=True, exist_ok=True)
        before = sum(1 for _ in dump_dir.iterdir()) if dump_dir.exists() else 0
        if self.vol.vol_version == "vol2":
            if self._try_vol2_dump(image, offset, dump_dir):
                return True
            return self._try_vol3_dump(image, offset, dump_dir)
        else:
            if self._try_vol3_dump(image, offset, dump_dir):
                return True
            return self._try_vol2_dump(image, offset, dump_dir)

    def _try_vol3_dump(self, image, offset, dump_dir) -> bool:
        if not self.vol.vol3_cmd:
            return False
        before = sum(1 for _ in dump_dir.iterdir()) if dump_dir.exists() else 0
        for addr_type in ("--physaddr", "--virtaddr"):
            try:
                cmd = (self.vol.vol3_cmd.split()
                       + ["-f", image, "-o", str(dump_dir),
                          "windows.dumpfiles.DumpFiles", addr_type, offset])
                proc = subprocess.run(cmd, capture_output=True, text=True,
                                      timeout=self.timeout)
                after = sum(1 for _ in dump_dir.iterdir()) if dump_dir.exists() else 0
                if after > before:
                    return True
            except subprocess.TimeoutExpired:
                self.log.debug("Vol3 dump timed out for %s", offset)
            except Exception as e:
                self.log.debug("Vol3 dump error: %s", e)
        return False

    def _try_vol2_dump(self, image, offset, dump_dir) -> bool:
        if not self.vol.vol2_cmd or not self.vol.profile:
            return False
        before = sum(1 for _ in dump_dir.iterdir()) if dump_dir.exists() else 0
        base = self.vol.vol2_cmd.split() + [
            "-f", image, "--profile=" + self.vol.profile]
        for extra_flags in ([], ["-n"], ["-u"]):
            try:
                cmd = base + ["dumpfiles", "-Q", offset, "-D", str(dump_dir)] + extra_flags
                subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
                after = sum(1 for _ in dump_dir.iterdir()) if dump_dir.exists() else 0
                if after > before:
                    return True
            except subprocess.TimeoutExpired:
                self.log.debug("Vol2 dump timed out for %s", offset)
            except Exception as e:
                self.log.debug("Vol2 dump error: %s", e)
        return False

    def dump_single_file(self, image: str, file_entry: Dict[str, str],
                         dump_dir: Path, verbose: bool = True) -> bool:
        dump_dir = Path(dump_dir)
        dump_dir.mkdir(parents=True, exist_ok=True)
        offset = file_entry["offset"]
        fname = file_entry["filename"]
        before = sum(1 for _ in dump_dir.iterdir()) if dump_dir.exists() else 0
        if self.vol.vol_version == "vol2":
            ok = self._try_vol2_dump_verbose(image, offset, fname,
                                             file_entry.get("path", ""), dump_dir, verbose)
            if not ok and self.vol.vol3_cmd:
                ok = self._try_vol3_dump_verbose(image, offset, fname, dump_dir, verbose)
        else:
            ok = self._try_vol3_dump_verbose(image, offset, fname, dump_dir, verbose)
            if not ok and self.vol.vol2_cmd and self.vol.profile:
                ok = self._try_vol2_dump_verbose(image, offset, fname,
                                                  file_entry.get("path", ""), dump_dir, verbose)
        if not ok:
            ok = sum(1 for _ in dump_dir.iterdir()) > before if dump_dir.exists() else False
        return ok

    def _try_vol2_dump_verbose(self, image, offset, fname, fpath, dump_dir, verbose) -> bool:
        if not self.vol.vol2_cmd or not self.vol.profile:
            if verbose:
                msg_warn("Vol2 not available or no profile set")
            return False
        before = sum(1 for _ in dump_dir.iterdir()) if dump_dir.exists() else 0
        base_cmd = self.vol.vol2_cmd.split() + [
            "-f", image, "--profile=" + self.vol.profile]
        attempts = [
            (base_cmd + ["dumpfiles", "-Q", offset, "-D", str(dump_dir)],
             f"Vol2 dumpfiles -Q {offset}"),
            (base_cmd + ["dumpfiles", "-Q", offset, "-D", str(dump_dir), "-n"],
             f"Vol2 dumpfiles -Q {offset} -n"),
            (base_cmd + ["dumpfiles", "-Q", offset, "-D", str(dump_dir), "-u"],
             f"Vol2 dumpfiles -Q {offset} -u"),
        ]
        if fname and fname != "(none)":
            safe_name = re.escape(fname)
            attempts.append((
                base_cmd + ["dumpfiles", "-r", safe_name, "-D", str(dump_dir), "-i"],
                f"Vol2 dumpfiles -r '{fname}' -i"))
        for cmd, label in attempts:
            try:
                if verbose:
                    msg_info(f"Trying: {label}")
                proc = subprocess.run(cmd, capture_output=True, text=True,
                                      timeout=self.timeout)
                after = sum(1 for _ in dump_dir.iterdir()) if dump_dir.exists() else 0
                if after > before:
                    if verbose:
                        msg_ok(f"Success! {after - before} file(s) extracted")
                    return True
                if verbose:
                    if proc.stderr and proc.stderr.strip():
                        msg_warn(f"  No output: {proc.stderr.strip().splitlines()[0][:150]}")
                    else:
                        msg_warn(f"  No output (rc={proc.returncode})")
            except subprocess.TimeoutExpired:
                if verbose:
                    msg_warn(f"  Timed out ({self.timeout}s)")
            except Exception as e:
                if verbose:
                    msg_warn(f"  Error: {e}")
        return False

    def _try_vol3_dump_verbose(self, image, offset, fname, dump_dir, verbose) -> bool:
        if not self.vol.vol3_cmd:
            return False
        before = sum(1 for _ in dump_dir.iterdir()) if dump_dir.exists() else 0
        for addr_type in ("--physaddr", "--virtaddr"):
            try:
                cmd = (self.vol.vol3_cmd.split()
                       + ["-f", image, "-o", str(dump_dir),
                          "windows.dumpfiles.DumpFiles", addr_type, offset])
                if verbose:
                    msg_info(f"Trying: Vol3 {addr_type} {offset}")
                proc = subprocess.run(cmd, capture_output=True, text=True,
                                      timeout=self.timeout)
                after = sum(1 for _ in dump_dir.iterdir()) if dump_dir.exists() else 0
                if after > before:
                    if verbose:
                        msg_ok(f"Success! {after - before} file(s) extracted")
                    return True
                if verbose and proc.stderr and proc.stderr.strip():
                    msg_warn(f"  {proc.stderr.strip().splitlines()[0][:150]}")
            except subprocess.TimeoutExpired:
                if verbose:
                    msg_warn(f"  Timed out ({self.timeout}s)")
            except Exception as e:
                if verbose:
                    msg_warn(f"  Error: {e}")
        return False

    def dump_file_list(self, image: str, file_list: List[Dict[str, str]],
                       dump_dir: Path) -> Dict[str, Any]:
        if not file_list:
            return {"total": 0, "attempted": 0, "dumped_files": 0, "duration": 0}
        return self._dump(image, file_list, dump_dir)

    def search_files(self, pattern: str) -> List[Dict[str, str]]:
        pat = pattern.lower().strip()
        if not pat:
            return []
        return [f for f in self._files
                if pat in f["filename"].lower() or pat in f["path"].lower()]

    def list_extensions(self) -> Dict[str, int]:
        exts: Dict[str, int] = {}
        for f in self._files:
            n = f["filename"]
            ext = ("." + n.rsplit(".", 1)[-1].lower()) if "." in n else "(none)"
            exts[ext] = exts.get(ext, 0) + 1
        return dict(sorted(exts.items(), key=lambda x: -x[1]))

    @property
    def file_count(self) -> int:
        return len(self._files)
