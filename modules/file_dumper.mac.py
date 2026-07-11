"""CresCent RAM Forensics Toolkit v6.0 - File Dumper (macOS)

macOS file listing via mac.list_files.List_Files (Vol3), plus file CONTENT
recovery from the Unified Buffer Cache via the mac.pagecache.Pagecache plugin
(CresCentC addition — reassembles a file's resident page-cache pages). Only
pages actually resident in RAM are recoverable; the rest come back sparse.
"""

import logging
import subprocess
import time
import json as _json
from pathlib import Path
from typing import Any, Dict, List, Optional

from modules.volatility import VolatilityWrapper
from utils.ui import msg_info, msg_ok, msg_warn


class FileDumper:
    """List and recover files from macOS memory images."""

    def __init__(self, vol: VolatilityWrapper, logger: logging.Logger,
                 jobs: int = 8, timeout: int = 90):
        self.vol = vol
        self.log = logger
        self.jobs = max(1, min(16, jobs))
        self.timeout = timeout
        self._mac_files: List[Dict[str, str]] = []

    def dump_mac(self, image: str, dump_dir: Path) -> int:
        """List files from macOS memory via mac.list_files.List_Files."""
        dump_dir = Path(dump_dir)
        dump_dir.mkdir(parents=True, exist_ok=True)
        vol3 = self.vol.vol3_cmd
        if not vol3:
            self.log.error("Vol3 required for macOS file listing")
            return 0
        self.log.info("Listing files (mac.list_files.List_Files)...")
        cmd = vol3.split() + ["-f", image, "-r", "json", "mac.list_files.List_Files"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=self.timeout * 4)
            lines = [l for l in proc.stdout.splitlines() if not l.startswith("Progress:")]
            out = "\n".join(lines)
            out_file = dump_dir / "mac_file_list.json"
            out_file.write_text(out, encoding="utf-8")
            try:
                data = _json.loads(out)
                self._mac_files = [
                    {"path": str(item.get("Path") or item.get("path") or ""),
                     "filename": str(item.get("Name") or item.get("name") or "")}
                    for item in data if isinstance(item, dict)
                ]
                count = len(data)
            except Exception:
                count = 0
            self.log.info("macOS file list: %d entries → %s", count, out_file)
            return count
        except Exception as e:
            self.log.error("macOS file listing error: %s", e)
            return 0

    def dump_mac_content(self, image: str, dump_dir: Path,
                         name_filter: Optional[str] = None,
                         timeout: Optional[int] = None) -> int:
        """Recover cached file CONTENT from the macOS page cache.

        Runs mac.pagecache.Pagecache --dump (writing reconstructed files into
        dump_dir). `name_filter` is passed through as the plugin's --name (a
        path substring, or comma-separated substrings = match ANY). With no
        filter, every file that has resident page-cache pages is recovered.

        Returns the number of newly written files.
        """
        dump_dir = Path(dump_dir)
        dump_dir.mkdir(parents=True, exist_ok=True)
        vol3 = self.vol.vol3_cmd
        if not vol3:
            self.log.error("Vol3 required for mac.pagecache content recovery")
            return 0
        before = sum(1 for _ in dump_dir.iterdir()) if dump_dir.exists() else 0
        # Vol3 writes reconstructed files into the -o directory (global option,
        # so it precedes the plugin name).
        cmd = vol3.split() + ["-q", "-o", str(dump_dir), "-f", image,
                              "mac.pagecache.Pagecache", "--dump"]
        if name_filter:
            cmd += ["--name", name_filter]
        # Enumerating vnodes alone can take minutes; recovering every cached file
        # adds more. Use a generous ceiling (at least an hour) so a full recovery
        # is not cut short.
        tmo = timeout or max(self.timeout * 40, 3600)
        self.log.info("Recovering macOS file content (mac.pagecache.Pagecache "
                      "--dump%s)...", f" --name {name_filter}" if name_filter else "")
        start = time.time()
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=tmo)
        except subprocess.TimeoutExpired:
            self.log.error("mac.pagecache content recovery timed out after %ds", tmo)
        except Exception as e:
            self.log.error("mac.pagecache content recovery error: %s", e)
        after = sum(1 for _ in dump_dir.iterdir()) if dump_dir.exists() else 0
        n = max(0, after - before)
        self.log.info("mac.pagecache: recovered %d file(s) → %s (%.1fs)",
                      n, dump_dir, time.time() - start)
        return n

    def dump_file_list(self, image: str, file_list: List[Dict[str, str]],
                       dump_dir: Path) -> Dict[str, Any]:
        """Recover content for a specific set of listed files (from a search).

        Builds a comma-separated --name filter from the selected paths so the
        page-cache plugin only reconstructs those files. Files whose pages are
        not resident in RAM recover nothing (reported as 0).
        """
        if not file_list:
            return {"total": 0, "attempted": 0, "dumped_files": 0, "duration": 0}
        names = ",".join(sorted({
            (f.get("path") or f.get("filename") or "").strip()
            for f in file_list
            if (f.get("path") or f.get("filename"))
        }))
        if not names:
            return {"total": len(file_list), "attempted": 0,
                    "dumped_files": 0, "duration": 0}
        start = time.time()
        n = self.dump_mac_content(image, dump_dir, name_filter=names)
        if not n:
            msg_warn("No content recovered — the selected file(s) had no "
                     "page-cache pages resident in this memory image.")
        return {"total": len(file_list), "attempted": len(file_list),
                "dumped_files": n, "duration": time.time() - start}

    def search_files(self, pattern: str) -> List[Dict[str, str]]:
        pat = pattern.lower().strip()
        if not pat:
            return []
        return [f for f in self._mac_files
                if pat in f.get("filename", "").lower()
                or pat in f.get("path", "").lower()]

    @property
    def file_count(self) -> int:
        return len(self._mac_files)
