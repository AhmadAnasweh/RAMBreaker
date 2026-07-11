"""CresCent RAM Forensics Toolkit v4.0 - Strings Extractor

In 'both' mode, ASCII and Unicode extraction run in parallel
(two strings processes simultaneously) for ~2x speedup.
"""

import logging
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict

from utils.ui import format_size


class StringsExtractor:
    """Extract ASCII/Unicode strings from memory images."""

    def __init__(self, logger: logging.Logger):
        self.log = logger

    def check_strings_command(self):
        if shutil.which("strings"):
            return True
        self.log.error("'strings' not found. Install: sudo apt install binutils")
        return False

    def extract(self, image, output_dir, mode="all"):
        if not self.check_strings_command():
            return {"error": "strings command not found"}
        od = Path(output_dir)
        od.mkdir(parents=True, exist_ok=True)
        start = time.time()
        results: Dict[str, Any] = {"mode": mode, "files": {}}

        if mode in ("all", "ascii"):
            out = od / "strings.txt"
            self._run(image, out, False)
            results["files"]["ascii"] = self._stats(out)

        elif mode == "unicode":
            out = od / "strings_unicode.txt"
            self._run(image, out, True)
            results["files"]["unicode"] = self._stats(out)

        elif mode == "both":
            a = od / "strings_ascii.txt"
            u = od / "strings_unicode.txt"

            # === PARALLEL: launch both at the same time ===
            self.log.info("Extracting ASCII + Unicode in PARALLEL from %s...",
                          Path(image).name)
            fa = open(a, "w", encoding="utf-8", errors="ignore")
            fu = open(u, "w", encoding="utf-8", errors="ignore")
            try:
                pa = subprocess.Popen(
                    ["strings", "-a", image], stdout=fa, stderr=subprocess.PIPE)
                pu = subprocess.Popen(
                    ["strings", "-a", "-el", image], stdout=fu, stderr=subprocess.PIPE)
                _, err_a = pa.communicate()
                _, err_u = pu.communicate()
            finally:
                fa.close()
                fu.close()

            if pa.returncode != 0 and err_a:
                self.log.warning("ASCII rc %d: %s",
                                 pa.returncode, err_a.decode()[:300])
            if pu.returncode != 0 and err_u:
                self.log.warning("Unicode rc %d: %s",
                                 pu.returncode, err_u.decode()[:300])

            sz_a = a.stat().st_size if a.exists() else 0
            sz_u = u.stat().st_size if u.exists() else 0
            self.log.info("ASCII:   %s (%s)", a.name, format_size(sz_a))
            self.log.info("Unicode: %s (%s)", u.name, format_size(sz_u))

            # Combine
            c = od / "strings_all.txt"
            try:
                with open(c, "w", encoding="utf-8", errors="ignore") as fo:
                    for src in (a, u):
                        if src.exists():
                            with open(src, "r", encoding="utf-8",
                                      errors="ignore") as fi:
                                for ln in fi:
                                    fo.write(ln)
                results["files"]["combined"] = self._stats(c)
            except OSError as e:
                self.log.error("Failed to combine: %s", e)

            results["files"]["ascii"] = self._stats(a)
            results["files"]["unicode"] = self._stats(u)

        else:
            out = od / "strings.txt"
            self._run(image, out, False)
            results["files"]["ascii"] = self._stats(out)

        results["duration"] = time.time() - start
        self.log.info("Strings complete (%.1fs)", results["duration"])
        return results

    def _run(self, image, output, unicode=False):
        """Single strings extraction (for 'all'/'ascii'/'unicode' modes)."""
        cmd = ["strings", "-a"] + (["-el"] if unicode else []) + [image]
        label = "Unicode" if unicode else "ASCII"
        self.log.info("Extracting %s strings from %s...", label,
                      Path(image).name)
        try:
            with open(output, "w", encoding="utf-8", errors="ignore") as fo:
                proc = subprocess.Popen(cmd, stdout=fo, stderr=subprocess.PIPE)
                _, stderr = proc.communicate()
            if proc.returncode != 0 and stderr:
                self.log.warning("strings rc %d: %s",
                                 proc.returncode, stderr.decode()[:300])
            else:
                sz = output.stat().st_size if output.exists() else 0
                self.log.info("%s: %s (%s)", label, output.name, format_size(sz))
        except Exception as e:
            self.log.error("Failed %s strings: %s", label, e)

    @staticmethod
    def _stats(p):
        p = Path(p)
        if not p.exists():
            return {"path": str(p), "size": 0, "lines": 0}
        sz = p.stat().st_size
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                lns = sum(1 for _ in f)
        except OSError:
            lns = 0
        return {"path": str(p), "size": sz, "lines": lns}
