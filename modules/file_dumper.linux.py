"""CresCent RAM Forensics Toolkit v6.0 - File Dumper (Linux)

Linux file recovery via linux.pagecache.RecoverFs / InodePages / lsof.
"""

import json as _json
import logging
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List

from modules.volatility import VolatilityWrapper
from utils.ui import msg_info, msg_ok, msg_warn, progress_line


class FileDumper:
    """Recover files from Linux memory images."""

    def __init__(self, vol: VolatilityWrapper, logger: logging.Logger,
                 jobs: int = 8, timeout: int = 90):
        self.vol = vol
        self.log = logger
        self.jobs = max(1, min(16, jobs))
        self.timeout = timeout
        self._linux_files: List[Dict[str, str]] = []
        self.linux_files_source: str = ""

    @property
    def linux_file_count(self) -> int:
        return len(self._linux_files)

    def load_linux_files_from_json(self, output_dir: Path) -> int:
        from utils.json_converter import load_json_by_pattern
        jd = Path(output_dir) / "json"
        if not jd.is_dir():
            return 0
        self._linux_files.clear()
        self.linux_files_source = ""

        for item in load_json_by_pattern(jd, "pagecache"):
            ftype = str(item.get("FileType") or item.get("Type") or "")
            if ftype and ftype != "REG":
                continue
            pages = item.get("InodePages", item.get("CachedPages", 0)) or 0
            if not pages:
                continue
            path = (item.get("FilePath") or item.get("File Path") or item.get("file_path") or
                    item.get("Path") or item.get("path") or
                    item.get("Name") or item.get("name") or "")
            if not path:
                continue
            inode = str(item.get("InodeNum") or item.get("Inode") or item.get("inode") or
                        item.get("INode") or "")
            fname = path.rsplit("/", 1)[-1] if "/" in path else path
            self._linux_files.append({"inode": inode, "path": path, "filename": fname})

        if self._linux_files:
            self.linux_files_source = "pagecache"
            self.log.info("Loaded %d files from pagecache JSON", len(self._linux_files))
            return len(self._linux_files)

        seen_inodes: set = set()
        for item in load_json_by_pattern(jd, "lsof"):
            ftype = str(item.get("Type") or "")
            path = str(item.get("Path") or item.get("Name") or "")
            if ftype not in ("REG", "DIR") or not path or path.startswith("<"):
                continue
            inode = str(item.get("Inode") or "")
            if inode in seen_inodes:
                continue
            seen_inodes.add(inode)
            fname = path.rsplit("/", 1)[-1] if "/" in path else path
            self._linux_files.append({"inode": inode, "path": path, "filename": fname})

        self.linux_files_source = "lsof"
        self.log.info("Loaded %d files from lsof JSON (fallback)", len(self._linux_files))
        return len(self._linux_files)

    def parse_linux_files(self, image: str) -> int:
        vol3 = self.vol.vol3_cmd
        if not vol3:
            self.log.error("Vol3 required for linux.pagecache.Files")
            return 0
        self.log.info("Listing page-cached files (linux.pagecache.Files)...")
        cmd = vol3.split() + ["-f", image, "-r", "json", "linux.pagecache.Files"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=self.timeout * 4)
            lines = [l for l in proc.stdout.splitlines() if not l.startswith("Progress:")]
            output = "\n".join(lines).strip()
            if not output:
                self.log.warning("linux.pagecache.Files returned no output")
                return 0
            try:
                data = _json.loads(output)
            except _json.JSONDecodeError:
                self.log.warning("linux.pagecache.Files output not valid JSON")
                return 0
            if not isinstance(data, list):
                return 0
            self._linux_files.clear()
            for item in data:
                if not isinstance(item, dict):
                    continue
                ftype = str(item.get("FileType") or item.get("Type") or "")
                if ftype and ftype != "REG":
                    continue
                pages = item.get("InodePages", item.get("CachedPages", 0)) or 0
                if not pages:
                    continue
                inode = (item.get("InodeNum") or item.get("Inode") or item.get("inode") or
                         item.get("INode") or "")
                path = (item.get("FilePath") or item.get("File Path") or item.get("file_path") or
                        item.get("Path") or item.get("path") or
                        item.get("Name") or item.get("name") or "")
                if not path:
                    continue
                fname = path.rsplit("/", 1)[-1] if "/" in path else path
                self._linux_files.append({"inode": str(inode), "path": path, "filename": fname})
            self.log.info("Linux pagecache: %d files listed", len(self._linux_files))
            return len(self._linux_files)
        except Exception as e:
            self.log.error("linux.pagecache.Files error: %s", e)
            return 0

    def dump_linux(self, image: str, dump_dir: Path) -> int:
        dump_dir = Path(dump_dir)
        dump_dir.mkdir(parents=True, exist_ok=True)
        vol3 = self.vol.vol3_cmd
        if not vol3:
            self.log.error("Vol3 required for Linux file recovery")
            return 0
        self.log.info("Recovering page-cached files (linux.pagecache.RecoverFs)...")
        before_tarballs = set(dump_dir.glob("*.tar*"))
        # NOTE: linux.pagecache.RecoverFs builds an in-memory tar.gz of every
        # cached file. On some Vol3/Python builds it crashes mid-stream (tar/gzip
        # fileobj issue) or hits an incomplete-ISF 'page.mapping' error, producing
        # nothing. We (1) try each compression format until one yields a tarball,
        # and (2) ALWAYS fall back to writing the file INVENTORY via
        # linux.pagecache.Files so the operator still gets a complete file list.
        for comp in ("gz", "xz", "bz2"):
            cmd = vol3.split() + ["-f", image, "linux.pagecache.RecoverFs",
                                  "--compression-format", comp]
            try:
                subprocess.run(cmd, capture_output=True, text=True,
                               cwd=str(dump_dir), timeout=self.timeout * 8)
            except subprocess.TimeoutExpired:
                self.log.error("RecoverFs (%s) timed out", comp)
            except Exception as e:
                self.log.error("RecoverFs (%s) error: %s", comp, e)
            new_tarballs = set(dump_dir.glob("*.tar*")) - before_tarballs
            if new_tarballs:
                total_size = sum(t.stat().st_size for t in new_tarballs)
                self.log.info("RecoverFs: %d tarball(s) created (%.1f MB)",
                              len(new_tarballs), total_size / 1e6)
                return len(new_tarballs)
        # No tarball produced — record the file inventory instead (always useful).
        self.log.warning("RecoverFs recovered no content (known upstream Vol3 "
                         "tar/ISF issue) — saving file inventory via pagecache.Files")
        listing = dump_dir / "linux_file_inventory.txt"
        try:
            proc = subprocess.run(
                vol3.split() + ["-f", image, "linux.pagecache.Files"],
                capture_output=True, text=True, timeout=self.timeout * 8)
            if proc.stdout and proc.stdout.count("\n") > 2:
                listing.write_text(proc.stdout, encoding="utf-8")
                n = max(0, proc.stdout.count("\n") - 1)
                self.log.info("Saved inventory of %d files → %s", n, listing)
                return n
            self.log.warning("pagecache.Files produced no listing: %s",
                             (proc.stderr or "")[:200])
        except Exception as e:
            self.log.error("pagecache.Files inventory error: %s", e)
        return 0

    def dump_linux_file_by_inode(self, image: str, file_entry: Dict[str, str],
                                  dump_dir: Path, verbose: bool = True) -> bool:
        dump_dir = Path(dump_dir)
        dump_dir.mkdir(parents=True, exist_ok=True)
        vol3 = self.vol.vol3_cmd
        if not vol3:
            if verbose:
                msg_warn("Vol3 required for linux.pagecache.InodePages")
            return False
        inode = file_entry.get("inode", "")
        fname = file_entry.get("filename", "")
        fpath = file_entry.get("path", "")
        before = sum(1 for _ in dump_dir.iterdir()) if dump_dir.exists() else 0

        def _count_after():
            return sum(1 for _ in dump_dir.iterdir()) if dump_dir.exists() else 0

        scan_timeout = self.timeout * 6

        def _try(label, extra_args, op_timeout=scan_timeout):
            cmd = vol3.split() + ["-f", image, "-o", str(dump_dir),
                                   "linux.pagecache.InodePages"] + extra_args + ["--dump"]
            if verbose:
                msg_info(f"Trying: {label}")
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True,
                                      timeout=op_timeout)
                after = _count_after()
                if after > before:
                    if verbose:
                        msg_ok(f"Success! {after - before} file(s) extracted")
                    return True
                stderr = proc.stderr.strip() if proc.stderr else ""
                if verbose and stderr:
                    first_err = stderr.splitlines()[0][:150]
                    if "usage:" not in first_err.lower() and "progress:" not in first_err.lower():
                        msg_warn(f"  {first_err}")
            except subprocess.TimeoutExpired:
                if verbose:
                    msg_warn(f"  Timed out ({op_timeout}s)")
            except Exception as e:
                if verbose:
                    msg_warn(f"  Error: {e}")
            return False

        if fpath and not fpath.startswith("<"):
            if verbose:
                msg_info("  (scanning full image for page-cached content — may take minutes)")
            if _try(f"InodePages --find {fpath}", ["--find", fpath]):
                return True

        if inode and (inode.startswith("0x") or inode.startswith("0X")):
            if _try(f"InodePages --inode {inode} ({fname})", ["--inode", str(inode)],
                    op_timeout=self.timeout):
                return True

        if verbose:
            msg_warn(f"Could not dump {fname} — file content not found in page cache")
        return False

    def dump_linux_by_extension(self, image: str, ext: str,
                                 dump_dir: Path) -> Dict[str, Any]:
        if not self._linux_files:
            return {"total": 0, "attempted": 0, "dumped_files": 0, "duration": 0}
        ext_l = ext.lower().lstrip(".")
        matches = [f for f in self._linux_files
                   if f["filename"].lower().endswith(f".{ext_l}")]
        if not matches:
            return {"total": 0, "attempted": 0, "dumped_files": 0, "duration": 0}
        return self._dump_linux(image, matches, dump_dir)

    def dump_linux_by_pattern(self, image: str, pattern: str,
                               dump_dir: Path) -> Dict[str, Any]:
        if not self._linux_files:
            return {"total": 0, "attempted": 0, "dumped_files": 0, "duration": 0}
        pl = pattern.lower()
        matches = [f for f in self._linux_files
                   if pl in f["filename"].lower() or pl in f["path"].lower()]
        if not matches:
            return {"total": 0, "attempted": 0, "dumped_files": 0, "duration": 0}
        return self._dump_linux(image, matches, dump_dir)

    def _dump_linux(self, image: str, flist: List[Dict[str, str]],
                    dump_dir: Path) -> Dict[str, Any]:
        dump_dir = Path(dump_dir)
        dump_dir.mkdir(parents=True, exist_ok=True)
        start = time.time()
        attempted = succeeded = 0
        with ThreadPoolExecutor(max_workers=self.jobs) as pool:
            futures = {pool.submit(self.dump_linux_file_by_inode, image, f,
                                   dump_dir, False): f for f in flist}
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
                    progress_line(done, total, "linux files dumped")
        dur = time.time() - start
        actual = sum(1 for _ in dump_dir.iterdir()) if dump_dir.exists() else 0
        self.log.info("Linux dump: %d attempted, %d actual files (%.1fs)",
                      attempted, actual, dur)
        return {"total": len(flist), "attempted": attempted,
                "dumped_files": actual, "duration": dur}

    def dump_file_list(self, image: str, file_list: List[Dict[str, str]],
                       dump_dir: Path) -> Dict[str, Any]:
        if not file_list:
            return {"total": 0, "attempted": 0, "dumped_files": 0, "duration": 0}
        return self._dump_linux(image, file_list, dump_dir)

    def list_linux_extensions(self) -> Dict[str, int]:
        exts: Dict[str, int] = {}
        for f in self._linux_files:
            n = f["filename"]
            ext = ("." + n.rsplit(".", 1)[-1].lower()) if "." in n else "(none)"
            exts[ext] = exts.get(ext, 0) + 1
        return dict(sorted(exts.items(), key=lambda x: -x[1]))

    def search_linux_files(self, pattern: str) -> List[Dict[str, str]]:
        pat = pattern.lower().strip()
        if not pat:
            return []
        return [f for f in self._linux_files
                if pat in f["filename"].lower() or pat in f["path"].lower()]
