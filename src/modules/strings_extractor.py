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
        # GNU strings is optional: the built-in pystrings engine is used when
        # it is missing (always on Windows, where binutils does not exist and
        # Sysinternals strings.exe takes different flags).
        return True

    @staticmethod
    def _use_gnu() -> bool:
        from modules.platform_compat import IS_WINDOWS
        return (not IS_WINDOWS) and bool(shutil.which("strings"))

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
            if self._use_gnu():
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
            else:
                # built-in engine: ONE pass over the image for both encodings (v2.4;
                # was two full reads of the dump). Falls back to two passes on error.
                counted = None
                try:
                    from modules import pystrings
                    counted = pystrings.extract_both_to_files(image, a, u)
                except Exception as e:
                    self.log.warning("Single-pass strings failed (%s); using two passes", e)
                    self._run(image, a, False)
                    self._run(image, u, True)

            sz_a = a.stat().st_size if a.exists() else 0
            sz_u = u.stat().st_size if u.exists() else 0
            self.log.info("ASCII:   %s (%s)", a.name, format_size(sz_a))
            self.log.info("Unicode: %s (%s)", u.name, format_size(sz_u))

            # Combine (binary copy: the parts are plain ASCII, so decoding and
            # re-encoding every line only cost time)
            c = od / "strings_all.txt"
            try:
                with open(c, "wb") as fo:
                    for src in (a, u):
                        if src.exists():
                            with open(src, "rb") as fi:
                                shutil.copyfileobj(fi, fo, 8 * 1024 * 1024)
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
        # v2.4: an image always holds strings. Empty output for a real image means the
        # extraction failed (it used to be reported as "Strings done" and the IOC scan
        # then said "No IOCs found").
        try:
            img_size = Path(image).stat().st_size
        except OSError:
            img_size = 0
        total = sum(int(f.get("size") or 0) for f in results["files"].values())
        if img_size > 1024 * 1024 and total == 0:
            self.log.error("Strings extraction produced NO output for a %s image - the step failed",
                           format_size(img_size))
            results["error"] = "strings extraction produced no output (worker processes failed?)"
            return results
        self.log.info("Strings complete (%.1fs)", results["duration"])
        return results

    def _run(self, image, output, unicode=False):
        """Single strings extraction (for 'all'/'ascii'/'unicode' modes)."""
        cmd = ["strings", "-a"] + (["-el"] if unicode else []) + [image]
        label = "Unicode" if unicode else "ASCII"
        self.log.info("Extracting %s strings from %s...", label,
                      Path(image).name)
        try:
            if not self._use_gnu():
                from modules import pystrings
                pystrings.extract_to_file(image, output, unicode=unicode)
                sz = output.stat().st_size if output.exists() else 0
                self.log.info("%s: %s (%s)", label, output.name, format_size(sz))
                return
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
        lns = 0
        try:
            with open(p, "rb") as f:
                while True:
                    b = f.read(8 * 1024 * 1024)
                    if not b:
                        break
                    lns += b.count(b"\n")
        except OSError:
            lns = 0
        return {"path": str(p), "size": sz, "lines": lns}
