"""CresCent RAM Forensics Toolkit v4.0 - Volatility 2/3 Wrapper"""

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from utils.json_converter import parse_vol2_table, load_json_safe
from modules import linux_identify
from modules import platform_compat
from modules.platform_compat import split_cmd

def _size_str(nb):
    if nb < 1024:
        return f"{nb}B"
    elif nb < 1024 * 1024:
        return f"{nb / 1024:.1f}KB"
    return f"{nb / (1024 * 1024):.1f}MB"


def _meaningful_stderr(stderr: str, limit: int = 500) -> str:
    """Return the useful tail of a Vol3 stderr stream.

    Vol3 always writes its banner ("Volatility 3 Framework x.y.z") and a long
    progress bar ("Progress: … Scanning … using BytesScanner") to stderr. When a
    plugin raises, the real cause (the traceback's final line, e.g. a missing
    symbol type) is at the END of the stream. Naively slicing stderr[:500]
    captures only the banner+progress and hides the actual error, so callers see
    a useless "FAILED: Volatility 3 Framework …". This keeps the last few lines
    that are neither the banner nor progress output.
    """
    noise_prefixes = ("Progress:", "Volatility 3 Framework")
    meaningful = []
    for ln in stderr.splitlines():
        s = ln.strip()
        if not s or s.startswith(noise_prefixes) or "Scanning" in ln:
            continue
        # Drop Python's caret/tilde annotation lines (e.g. "   ^^^^^^" / "~~~~^^").
        if s and all(c in "^~ " for c in s):
            continue
        meaningful.append(s)
    if not meaningful:
        # No traceback (e.g. a clean-but-empty run) — fall back to the tail.
        return stderr.strip()[-limit:]
    # The final line of a Python traceback is the exception type + message
    # ("AttributeError: …", "ValueError: …") — the single most useful line.
    for s in reversed(meaningful):
        if re.match(r'^[A-Za-z_][\w.]*(Error|Exception|Warning|Interrupt|Exit):', s):
            return s[-limit:]
    return meaningful[-1][-limit:]


def _is_empty_result(content: str) -> bool:
    """True if a Vol3 JSON body carries no data rows ('', '[]', '{}' modulo
    whitespace). Pure/testable."""
    compact = re.sub(r"\s+", "", content or "")
    return compact in ("", "[]", "{}")


def _is_plugin_exception(err_msg: str) -> bool:
    """True if distilled stderr shows a *systemic* plugin/framework failure — a
    new-kernel struct drift or an incomplete ISF — as opposed to a benign warning.

    Signatures: an incomplete-ISF 'member not present in template', an
    'Unhandled exception' / full traceback, or a bare exception-type line
    ('AttributeError: …', 'TypeError: …') as produced by _meaningful_stderr.
    Warnings and user interrupts/exits are deliberately excluded. Pure/testable."""
    if not err_msg:
        return False
    low = err_msg.lower()
    if "not present in template" in low:
        return True
    if "unhandled exception" in low or "traceback (most recent call last)" in low:
        return True
    return bool(re.match(r'^[A-Za-z_][\w.]*(Error|Exception):', err_msg))


# Windows could not START the process (nothing ran): out of memory / commit / desktop heap.
_START_FAILURES = {0xC0000142: "DLL initialisation failed", 0xC000012D: "commit limit reached",
                   0xC0000017: "no memory", 0xC000009A: "insufficient system resources"}
_NT_OTHER = {0xC0000005: "the plugin process crashed (access violation)",
             0xC000013A: "the plugin process was interrupted (Ctrl+C / console closed)",
             0xC00000FD: "the plugin process crashed (stack overflow)",
             0xC0000409: "the plugin process crashed (stack buffer overrun)"}


def exit_reason(rc: int) -> str:
    """A readable sentence for a plugin process that ended without any error text
    (v2.4: linux.pagecache.Files 'FAILED: ' with exit 3221225794 while the PC was out
    of memory)."""
    u = rc & 0xFFFFFFFF if isinstance(rc, int) else 0
    if u in _START_FAILURES:
        return (f"Windows could not start the plugin process (exit 0x{u:08X}: {_START_FAILURES[u]}). "
                "Usual causes: the PC was out of memory at that moment, or the console / session that "
                "started RAMBreaker was closed. Close other programs and retry this plugin")
    if u in _NT_OTHER:
        return f"{_NT_OTHER[u]} (exit 0x{u:08X})"
    if u >= 0xC0000000:
        return f"the plugin process was ended by Windows (exit 0x{u:08X})"
    return f"exit {rc} with no error message"


def _run_started(cmd_parts, tmo, log, plugin):
    """subprocess.run for one Volatility plugin. If Windows could not even start the
    process (see _START_FAILURES) nothing was analysed, so wait for memory to come
    back and try again - up to 2 more times - before the plugin is reported failed."""
    proc = None
    for attempt in range(3):
        proc = subprocess.run(cmd_parts, capture_output=True, text=True,
                              errors="replace", timeout=tmo)
        u = proc.returncode & 0xFFFFFFFF
        if u not in _START_FAILURES or (proc.stdout or "").strip():
            return proc
        if attempt < 2:
            wait = 20 * (attempt + 1)
            log.warning("%s: Windows could not start the plugin process (exit 0x%08X: out of memory, "
                        "or the starting console was closed); waiting %d s and trying again", plugin, u, wait)
            time.sleep(wait)
    return proc


def _vol3_success(returncode: int, output: str, err_msg: str, os_type: str) -> bool:
    """Decide whether a Vol3 plugin run succeeded. Pure/testable.

    Beyond the obvious (non-zero rc or an error banner in stdout => failure), this
    demotes the *silent new-kernel failure*: on Linux/macOS a plugin that exits 0
    but produced NO rows while logging a systemic exception to stderr (a changed
    kernel struct or a stub ISF) is NOT a clean-empty success — it is a failure
    whose stderr must be surfaced, not discarded. A genuinely clean-but-empty
    plugin (check_modules/tty_check on a quiet host) has no such stderr and stays
    a success."""
    content = (output or "").strip()
    low = content.lower()
    has_error = (low.startswith(("error", "exception", "traceback"))
                 or "unsatisfied requirement" in low
                 or "a translation layer requirement was not fulfilled" in low
                 or "a symbol table requirement was not fulfilled" in low)
    if returncode != 0 or has_error:
        return False
    if os_type in ("linux", "mac"):
        # Silent struct/symbol failure: rc=0, empty result, but an exception on
        # stderr. Everything else (real rows, or empty with clean stderr) is OK.
        if _is_empty_result(content) and _is_plugin_exception(err_msg):
            return False
        return True
    # Windows: keep requiring real content (empty '[]' was already a failure),
    # unless the plugin itself reported that what it reads is absent (Vol3
    # userassist: "UserAssist key not found in ...ntuser.dat") - it ran fine.
    if _is_empty_result(content) and _confirmed_absent(err_msg):
        return True
    return len(content) > 10


def _confirmed_absent(err_msg: str) -> bool:
    """stderr says the plugin looked and the registry key is not there, with no
    exception: a genuine 'nothing to report', not a failure."""
    err = err_msg or ""
    return (bool(re.search(r"\bkey not found\b", err, re.I))
            and not _is_plugin_exception(err)
            and "traceback" not in err.lower())


def _write_empty_marker(out_path, empty_ok: bool) -> None:
    """'<name>.json.empty' next to a Vol2 plugin's '[]' when the plugin ran fine and
    found nothing; removed otherwise. Resume treats the pair as completed."""
    marker = Path(str(out_path) + ".empty")
    try:
        if empty_ok:
            marker.write_text("ran OK, no rows\n", encoding="utf-8")
        elif marker.exists():
            marker.unlink()
    except OSError:
        pass


def vol2_done(json_path) -> bool:
    """Resume test for a Vol2 plugin: real rows, or a clean empty run."""
    p = Path(json_path)
    try:
        if not p.exists() or Path(str(p) + ".error").exists():
            return False
        return p.stat().st_size > 10 or Path(str(p) + ".empty").exists()
    except OSError:
        return False


def _write_error_marker(out_path, ok: bool, error: str) -> None:
    """Leave (or clear) a '<name>.json.error' sidecar next to a plugin's JSON.

    The extractor's resume/skip-existing logic trusts an existing JSON that looks
    valid — so a silent failure that left empty/partial output would be skipped on
    a re-run, caching the failure as good. A sidecar makes the failure durable:
    resume re-runs any plugin that has one. Cleared on success so a recovered
    plugin is not needlessly re-run. Best-effort; never raises."""
    marker = Path(str(out_path) + ".error")
    try:
        if ok:
            if marker.exists():
                marker.unlink()
        else:
            marker.write_text((error or "failed")[:500], encoding="utf-8")
    except Exception:
        pass


class VolatilityWrapper:
    """Unified wrapper around Volatility 2 and 3.

    Auto-discovers installations, detects OS/profile, and runs plugins
    capturing all output, timing, and errors for the log.
    """

    V3_PATHS = [
        "./vol.py", "../vol.py", "./volatility3/vol.py", "../volatility3/vol.py",
        "{home}/volatility3/vol.py", "{home}/Desktop/volatility3/vol.py",
        "{home}/tools/volatility3/vol.py", "/opt/volatility3/vol.py",
    ]
    V3_CMDS = ["vol", "vol3", "volatility3"]
    V2_PATHS = [
        "./vol.py", "../vol.py", "./volatility/vol.py", "../volatility/vol.py",
        "./volatility2/vol.py", "../volatility2/vol.py",
        "{home}/volatility/vol.py", "{home}/Desktop/volatility/vol.py",
        "{home}/tools/volatility/vol.py", "/opt/volatility/vol.py",
        "/usr/share/volatility/vol.py",
    ]
    V2_CMDS = ["volatility", "vol2", "volatility2"]

    def __init__(self, logger: logging.Logger, timeout: int = 600):
        self.log = logger
        self.timeout = timeout
        # v2: per-plugin timeouts from the calibrated model (config/timeouts.json);
        # RAMBREAKER_FIXED_TIMEOUT=1 or --fixed-timeout restores the flat value.
        self.dynamic_timeouts = os.environ.get("RAMBREAKER_FIXED_TIMEOUT") != "1"
        self.vol3_cmd: Optional[str] = None
        self.vol2_cmd: Optional[str] = None
        self.profile: Optional[str] = None
        self.os_type: str = "windows"
        self.vol_version: str = ""

    # -- Discovery --
    def find_volatility(self) -> bool:
        self._find_vol3()
        self._find_vol2()
        found = bool(self.vol3_cmd or self.vol2_cmd)
        if not found:
            self.log.error("No Volatility installation found!")
        return found

    @staticmethod
    def _vol3_global_args() -> List[str]:
        """Bundled symbol dirs + private cache (Windows port; empty if none)."""
        return platform_compat.vol3_global_args()

    def _vol3_candidates(self) -> List[str]:
        home = str(Path.home())
        paths = [str(d / "volatility3" / "vol.py")
                 for d in platform_compat.runtime_dirs()]
        env = os.environ.get("RAMBREAKER_VOL3")
        if env:
            paths.insert(0, env)
        return paths + [rp.replace("{home}", home) for rp in self.V3_PATHS]

    def _find_vol3(self):
        py3 = platform_compat.python3_exe()
        for p in self._vol3_candidates():
            if Path(p).is_file():
                # Resolve to an ABSOLUTE path so the command works even when a
                # plugin is run with a changed cwd (e.g. linux.pagecache.RecoverFs
                # writes its tarball to the current directory, so it is invoked
                # from the dump dir — a relative ../volatility3/vol.py would break).
                p = str(Path(p).resolve())
                cmd = platform_compat.join_cmd([py3, p] + self._vol3_global_args())
                if self._test_vol3(cmd):
                    self.vol3_cmd = cmd
                    self.log.info("Found Vol3: %s", self.vol3_cmd)
                    return
        for cmd in self.V3_CMDS:
            exe = shutil.which(cmd)
            if exe:
                self.vol3_cmd = platform_compat.join_cmd([exe])
                self.log.info("Found Vol3 command: %s", exe)
                return

    def _find_vol2(self):
        home = str(Path.home())
        paths = [str(d / "volatility2" / "vol.py")
                 for d in platform_compat.runtime_dirs()]
        env = os.environ.get("RAMBREAKER_VOL2")
        if env:
            paths.insert(0, env)
        paths += [rp.replace("{home}", home) for rp in self.V2_PATHS]
        pythons = platform_compat.python2_candidates() + ["python"]
        for p in paths:
            if Path(p).is_file():
                p = str(Path(p).resolve())  # absolute — survives cwd changes
                for py in pythons:
                    if os.path.isabs(py) and not Path(py).is_file():
                        continue
                    if not os.path.isabs(py) and not shutil.which(py):
                        continue
                    cmd = platform_compat.join_cmd([py, p] + platform_compat.vol2_global_args())
                    if self._test_vol2(cmd):
                        self.vol2_cmd = cmd
                        self.log.info("Found Vol2: %s", self.vol2_cmd)
                        return
        for cmd in self.V2_CMDS:
            exe = shutil.which(cmd)
            if exe and self._test_vol2(platform_compat.join_cmd([exe])):
                self.vol2_cmd = platform_compat.join_cmd([exe])
                self.log.info("Found Vol2 command: %s", exe)
                return

    def _test_vol3(self, cmd):
        try:
            # 60s (not 15s): `vol.py -h` imports all of volatility3 and discovers
            # plugins, which can exceed 15s when the box is under load (e.g. right
            # after a heavy analysis run) — a slow-but-working Vol must not be
            # misreported as "not installed".
            r = subprocess.run(split_cmd(cmd) + ["-h"], capture_output=True,
                               timeout=60, text=True, errors="replace")
            return r.returncode == 0
        except Exception:
            return False

    def _test_vol2(self, cmd):
        try:
            r = subprocess.run(split_cmd(cmd) + ["--help"], capture_output=True,
                               timeout=60, text=True, errors="replace")
            return "--profile" in (r.stdout + r.stderr)
        except Exception:
            return False

    # -- Detection --
    def auto_detect(self, image: str) -> bool:
        """Auto-detect (with GUI stage events); see _auto_detect_impl."""
        from modules import progress as _pg
        _pg.stage("Detecting OS", "start",
                  "Reading the image header and kernel banners to identify the OS")
        ok = False
        try:
            ok = self._auto_detect_impl(image)
            return ok
        finally:
            _pg.emit("stage", name="Detecting OS", state="done" if ok else "fail",
                     os_type=self.os_type, engine=self.vol_version,
                     profile=self.profile or "")

    def prepare_image(self, image: str) -> Optional[dict]:
        """VMware .vmem without its .vmss/.vmsn: rebuild the guest memory map
        (RAM above the PCI hole) from the guest's page tables, once per image
        (cached). The Vol3 layer / Vol2 address space apply it to every plugin.
        Other images: no-op. Returns the map dict or None."""
        from modules import vmem_gap
        if not image or not vmem_gap.is_vmem_without_metadata(image):
            return None
        return self._ensure_vmem_map(image, "vmem")

    def _ensure_vmem_map(self, image: str, why: str) -> Optional[dict]:
        from modules import vmem_gap
        done = self.__dict__.setdefault("_vmem_maps", {})
        if image in done:
            return done[image]
        map_dir = platform_compat.vmem_map_dir()
        if vmem_gap.load_map(image, map_dir) is None:
            if why == "vmem":
                self.log.info("VMware .vmem without its .vmss/.vmsn - reading the guest page "
                              "tables to find where RAM above the PCI hole belongs (one pass "
                              "over the image, then cached)")
            else:
                self.log.info("Windows markers found but the kernel could not be loaded - "
                              "checking whether the image is a VMware .vmem with a memory hole")
        m = vmem_gap.ensure_map(image, map_dir, self.log)
        done[image] = m
        if m and m.get("remap"):
            self.log.info("Memory map rebuilt: %s", vmem_gap.describe(m))
        elif m and why == "vmem":
            self.log.info("Memory map check: %s", vmem_gap.describe(m))
        return m

    def _vmem_hint(self, image: str) -> None:
        """Last words when detection failed on a .vmem without metadata."""
        try:
            from modules import vmem_gap
            if vmem_gap.is_vmem_without_metadata(image):
                self.log.warning(
                    "This .vmem has no .vmss/.vmsn beside it. If you have the VM snapshot "
                    "file (<name>.vmsn or <name>.vmss), put it in the same folder with the "
                    "same name and run again.")
        except Exception:
            pass

    def _auto_detect_impl(self, image: str) -> bool:
        """Auto-detect OS type and best Volatility engine.

        Detection chain:
          1. Vol3 banners.Banners (no symbols needed)
          2. Vol3 windows.info.Info (needs symbols)
          3. Vol2 imageinfo (profiles)
          4. Raw string scan for kernel signatures

        Supports both Windows and Linux images.
        """
        self.log.info("Auto-detecting OS and Volatility version...")
        self.prepare_image(image)

        # --- Step 0: Fast, high-confidence format pre-check (header + 16 MB read) ---
        # LiME dumps and most Linux/macOS images are identified here in well under a
        # second, letting us skip the slow banners.Banners scan AND the pointless Vol2
        # imageinfo probe — each of which can block for up to 300s on a large image.
        # Windows is deliberately NOT short-circuited here (it still needs Vol2 profile
        # detection downstream), so it falls through to the full chain below.
        fast_os = self._fast_format_detect(image)
        if fast_os in ("linux", "mac") and self.vol3_cmd:
            self.os_type, self.vol_version = fast_os, "vol3"
            self.log.info("Detected: %s (via fast format pre-check) -- Using Volatility 3",
                          "macOS" if fast_os == "mac" else "Linux")
            return True

        # --- Step 0b: Windows kernel markers in the first 64 MB -> windows.info first.
        # banners.Banners only knows Linux/macOS banners, so on Windows it is a
        # whole-image scan that finds nothing (~10-20 s/GB: minutes on a 35 GB dump).
        if self.vol3_cmd and linux_identify.windows_hint(image, self.log):
            self.log.info("Windows kernel markers in the first 64 MB - trying windows.info "
                          "first (skips the whole-image banner scan)")
            rc, out, err = self._probe_windows_info(image)
            if any(kw in out + err for kw in ("NTBuildLab", "Is64Bit", "NTMajorVersion")):
                self.os_type, self.vol_version = "windows", "vol3"
                self.log.info("Detected: Windows -- Using Volatility 3")
                self._maybe_vol2_profile(image, out + err)
                return True
            # Windows markers but no kernel: a VMware .vmem whose RAM above the
            # PCI hole is not where the page tables expect it (no .vmss/.vmsn,
            # or renamed to .raw/.mem). Rebuild the map and probe once more.
            m = self._ensure_vmem_map(image, "recover")
            if m and m.get("remap"):
                rc, out, err = self._probe_windows_info(image)
                if any(kw in out + err for kw in ("NTBuildLab", "Is64Bit", "NTMajorVersion")):
                    self.os_type, self.vol_version = "windows", "vol3"
                    self.log.info("Detected: Windows (memory map rebuilt) -- Using Volatility 3")
                    self._maybe_vol2_profile(image, out + err)
                    return True
            self.log.info("windows.info did not confirm Windows - running the full detection chain")

        if self.vol3_cmd:
            # --- Step 1: Try banners (works without symbols) ---
            self.log.info("Trying Vol3 banners detection...")
            # banners.Banners must, on a cold cache, first build Vol3's ISF
            # identifier index ("Updating caches for N files…") — a one-time cost
            # that scales with the installed symbol packs and the box, not with a
            # number we can guess. A fixed cap (the old min(300, …)) killed it
            # mid-build on slower/larger setups, so the cache never committed and
            # every run repeated the cost. Wait on real progress instead: this
            # both detects the OS and leaves the cache warm for the symbol-resolve
            # verify step and all parallel plugin jobs that follow.
            # NB: do NOT pass -q. -q silences Vol3's progress bar, which is the
            # exact stream run_vol_until_done watches to know the process is alive.
            # With -q, a large image's FileLayer scan runs >stall_grace with no
            # output and is wrongly killed as a "stall" (this is what made an
            # 8.5GB image abort at 180s). warm_isf_cache already learned this;
            # apply it here too. Widen the grace for very large images.
            cmd = split_cmd(self.vol3_cmd) + ["-f", image, "banners.Banners"]
            rc, out, err = linux_identify.run_vol_until_done(
                cmd, self.log, stall_grace=300)
            if rc == 0 and out.strip():
                out_lower = out.lower()
                if "darwin" in out_lower or "mac os x" in out_lower or "xnu" in out_lower:
                    self.os_type, self.vol_version = "mac", "vol3"
                    self.log.info("Detected: macOS (via banners) -- Using Volatility 3")
                    return True
                if any(x in out_lower for x in ("linux", "ubuntu", "debian",
                                                  "centos", "rhel", "kali")):
                    self.os_type = "linux"
                    # Verify Vol3 has a matching ISF for this specific kernel banner.
                    # banners.Banners succeeds without symbols, so we must check the
                    # installed ISF files before committing to Vol3.
                    banner = self._extract_linux_banner(out)
                    if banner and self._has_vol3_linux_isf(banner):
                        self.vol_version = "vol3"
                        self.log.info("Detected: Linux (via banners + ISF verified) -- Using Volatility 3")
                        return True
                    # No matching ISF found — try Vol2 Linux profiles
                    self.log.warning(
                        "Vol3 Linux ISF not found for this kernel banner — trying Vol2")
                    if self.vol2_cmd and self._detect_linux_profile_vol2_list(image):
                        self.vol_version = "vol2"
                        self.log.info("Detected: Linux -- Using Volatility 2 (profile: %s)",
                                      self.profile)
                        return True
                    # No Vol2 profile either — commit to Vol3 and warn
                    self.vol_version = "vol3"
                    self.log.warning(
                        "No prebuilt Linux symbols yet - the symbol ladder (community ISF, "
                        "debug package, BTF from the dump, Vol2 profile) runs next.")
                    return True
                if "windows" in out_lower or "ntbuild" in out_lower:
                    self.os_type = "windows"
                    self.log.info("Detected: Windows (via banners)")
                    # Grab Vol2 profile now while we're here (needed if Vol3 fails)
                    if self.vol2_cmd and not self.profile:
                        self._detect_profile_vol2(image)
                    # Verify Vol3 actually works — Win7/XP often fail Vol3 symbol lookup
                    rc3, out3, err3 = self._probe_windows_info(image)
                    vol3_ok = any(kw in (out3 + err3) for kw in
                                  ("NTBuildLab", "Is64Bit", "NTMajorVersion"))
                    vol3_unsatisfied = "Unsatisfied" in (out3 + err3)
                    if vol3_ok:
                        self.vol_version = "vol3"
                        self.log.info("Detected: Windows -- Using Volatility 3")
                    elif vol3_unsatisfied and self.profile:
                        # Vol3 symbols missing but Vol2 has a profile → use Vol2
                        self.vol_version = "vol2"
                        self.log.warning(
                            "Vol3 symbols unavailable for this build — "
                            "falling back to Vol2 (profile: %s)", self.profile)
                    elif self.profile:
                        self.vol_version = "vol2"
                        self.log.info("Using Vol2 (profile: %s)", self.profile)
                    else:
                        # No Vol2 profile either, hope Vol3 works anyway
                        self.vol_version = "vol3"
                        self.log.warning(
                            "Vol3 Windows symbols missing or incompatible. "
                            "Download: https://downloads.volatilityfoundation.org/"
                            "volatility3/symbols/windows.zip")
                    return True

            # --- Step 2: Try Vol3 windows.info ---
            self.log.info("Trying Vol3 windows.info...")
            rc, out, err = self._probe_windows_info(image)
            combined = out + err
            if any(kw in combined for kw in ("NTBuildLab", "Is64Bit", "NTMajorVersion")):
                self.os_type, self.vol_version = "windows", "vol3"
                self.log.info("Detected: Windows -- Using Volatility 3")
                self._maybe_vol2_profile(image, combined)
                return True
            if "Unsatisfied" in combined or "symbol" in combined.lower():
                self.log.warning("Vol3 Windows symbols missing or incompatible")
                self.log.info("Download: https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip")

        # --- Step 3: Try Vol2 imageinfo ---
        if self.vol2_cmd:
            self.log.info("Trying Volatility 2 detection...")
            if self._detect_profile_vol2(image):
                p = (self.profile or "").lower()
                if "linux" in p:
                    self.os_type, self.vol_version = "linux", "vol2"
                    self.log.info("Detected: Linux (via Vol2 profile)")
                    return True

                # Win10/11/8: force Vol3
                if self.vol3_cmd and any(x in p for x in ("win10", "win11", "win8")):
                    self.log.warning("Win10/11 image: using Vol3 instead of Vol2")
                    self.os_type, self.vol_version = "windows", "vol3"
                    self.log.info("Detected: Windows (Win10/11) -- Forcing Volatility 3")
                    return True

                self.vol_version = "vol2"
                self.os_type = "windows"
                self.log.info("Using Vol2 - Profile: %s", self.profile)
                return True

        # --- Step 4: Raw string scan ---
        self.log.info("Trying raw string scan for OS detection...")
        detected_os = self._raw_os_detect(image)
        if detected_os == "mac":
            self.os_type = "mac"
            self.vol_version = "vol3"
            self.log.info("Detected: macOS (via raw string scan)")
            return True
        if detected_os == "linux":
            self.os_type = "linux"
            # Prefer Vol2 when a matching Linux profile is installed
            if self.vol2_cmd and self._detect_linux_profile_vol2_list(image):
                self.vol_version = "vol2"
                self.log.info("Detected: Linux (raw scan) -- Using Volatility 2 (profile: %s)",
                              self.profile)
                return True
            if self.vol3_cmd:
                self.vol_version = "vol3"
            elif self.vol2_cmd:
                self.vol_version = "vol2"
            self.log.info("Detected: Linux (via raw string scan)")
            return True
        if detected_os == "windows":
            self.os_type = "windows"
            if self.vol3_cmd:
                self.vol_version = "vol3"
            elif self.vol2_cmd:
                self.vol_version = "vol2"
            self.log.info("Detected: Windows (via raw string scan)")
            return True

        # --- All detection failed ---
        if self.vol3_cmd:
            self.vol_version = "vol3"
        elif self.vol2_cmd:
            self.vol_version = "vol2"
        self.os_type = "unknown"
        self.log.error("Could not detect OS.")
        self._vmem_hint(image)
        return False

    def detect_for_os(self, image: str, os_type: str) -> bool:
        """Targeted detection when the operator already knows the OS.

        Skips probing for the other operating systems entirely — for a known
        Linux image we never run the Windows imageinfo probe, and vice versa —
        which is both faster and avoids mis-detection on ambiguous dumps.

        os_type is one of 'windows', 'linux', 'mac'. Returns True.
        """
        os_type = (os_type or "").lower()
        self.log.info("OS provided by operator: %s — skipping cross-OS probing",
                      os_type)
        self.prepare_image(image)

        if os_type in ("linux", "mac"):
            self.os_type = os_type
            # Prefer Vol3 (the resolver auto-fetches the matching ISF afterwards).
            # Fall back to a Vol2 Linux profile only when Vol3 is unavailable.
            if self.vol3_cmd:
                self.vol_version = "vol3"
            elif self.vol2_cmd:
                self.vol_version = "vol2"
                if os_type == "linux" and not self.profile:
                    self._detect_linux_profile_vol2_list(image)
            self.log.info("Using %s for %s image", self.vol_version, os_type)
            return True

        # Windows
        self.os_type = "windows"
        if self.vol3_cmd:
            rc, out, err = self._probe_windows_info(image)
            combined = out + err
            if any(kw in combined for kw in ("NTBuildLab", "Is64Bit", "NTMajorVersion")):
                self.vol_version = "vol3"
                self._maybe_vol2_profile(image, combined)
                self.log.info("Detected: Windows -- Using Volatility 3")
                return True
        # Vol3 unavailable or symbols missing → try a Vol2 profile
        if self.vol2_cmd and self._detect_profile_vol2(image):
            p = (self.profile or "").lower()
            if self.vol3_cmd and any(x in p for x in ("win10", "win11", "win8")):
                self.vol_version = "vol3"
                self.log.info("Win10/11 image: using Vol3")
                return True
            self.vol_version = "vol2"
            self.log.info("Using Vol2 - Profile: %s", self.profile)
            return True
        # Last resort
        self.vol_version = "vol3" if self.vol3_cmd else "vol2"
        self.log.warning("Windows symbols/profile undetermined — defaulting to %s",
                         self.vol_version)
        self._vmem_hint(image)
        return True

    # -- Linux identification (delegated to modules.linux_identify) --
    # These thin wrappers preserve the original signatures/side-effects
    # (set self.profile, return bool) while the real logic lives in
    # linux_identify so it can be reused and run standalone.

    def _detect_linux_profile_vol2(self, image: str) -> bool:
        """Try to detect a Vol2 Linux profile using linux_banner + profile matching."""
        prof = linux_identify.detect_linux_profile_vol2(
            self.vol2_cmd, image, self._run_raw, self.log)
        if prof:
            self.profile = prof
            return True
        return False

    def _extract_linux_banner(self, banners_out: str) -> Optional[str]:
        """Extract the first Linux version banner string from banners.Banners output."""
        return linux_identify.extract_linux_banner(banners_out)

    def _has_vol3_linux_isf(self, banner: str) -> bool:
        """Return True if any installed Vol3 ISF has a linux_banner matching banner."""
        return linux_identify.has_vol3_linux_isf(banner, self.V3_PATHS, self.log)

    def _detect_linux_profile_vol2_list(self, image: str) -> bool:
        """Find and set a working Vol2 Linux profile from installed profiles."""
        prof = linux_identify.detect_linux_profile_vol2_list(
            self.vol2_cmd, image, self.log)
        if prof:
            self.profile = prof
            return True
        return False

    @staticmethod
    def _windows_build(info_text: str) -> int:
        """Build number from windows.info text ('NtBuildLab 22621.1.amd64fre...',
        'Major/Minor 15.22621'); 0 if absent."""
        m = (re.search(r"NtBuildLab\s+(\d{4,5})\.", info_text, re.I)
             or re.search(r"Major/Minor\s+\d+\.(\d{4,5})", info_text, re.I))
        return int(m.group(1)) if m else 0

    def _vol2_newest_windows_build(self) -> int:
        """Newest Windows 10-family build the installed Vol2 has a profile for,
        read from its overlay files (Win10x64_19041 -> 19041); 0 if unknown."""
        if "_vol2_newest_build" in self.__dict__:
            return self.__dict__["_vol2_newest_build"]
        newest = 0
        try:
            vol_py = next((a for a in split_cmd(self.vol2_cmd or "")
                           if a.lower().endswith("vol.py")), "")
            ov = Path(vol_py).parent / "volatility" / "plugins" / "overlays" / "windows"
            for f in ov.glob("*.py"):
                for m in re.finditer(r"Win(?:10|2016|2019)x(?:64|86)_(\d{5})",
                                     f.read_text(encoding="utf-8", errors="replace")):
                    newest = max(newest, int(m.group(1)))
        except Exception:
            newest = 0
        self.__dict__["_vol2_newest_build"] = newest
        return newest

    def _maybe_vol2_profile(self, image: str, info_text: str) -> None:
        """Vol2 imageinfo, unless windows.info already proves no Vol2 profile can
        exist: a build newer than the newest Windows 10-family profile of the
        installed Vol2 (2.6.1: Win10x64_19041) cannot match, so the probe would
        only burn its 300 s timeout (35 GB Win11 sample: 22621; Server 2022:
        20348). Servicing builds of the same kernel (19041-19045) stay within a
        few numbers, so up to +100 still gets the probe."""
        if not self.vol2_cmd or self.profile:
            return
        build = self._windows_build(info_text)
        newest = self._vol2_newest_windows_build() or 19041
        if build > newest + 100:
            self.log.info("Windows build %d is newer than any Volatility 2 profile (newest: "
                          "%d) - skipping Vol2 imageinfo; Vol3 handles this image",
                          build, newest)
            return
        self._detect_profile_vol2(image)

    def _fast_format_detect(self, image: str) -> str:
        """Cheap, high-confidence OS pre-check from the image header + first 16 MB."""
        return linux_identify.fast_format_detect(image, self.log)

    def _raw_os_detect(self, image: str) -> str:
        """Last resort: read first 10MB of image looking for OS signatures."""
        return linux_identify.raw_os_detect(image, self.log)

    def _detect_profile_vol2(self, image: str) -> bool:
        """Detect the Vol2 profile (narrated for the GUI), see _detect_profile_vol2_impl."""
        from modules import progress as _pg
        _pg.info("Windows image - identifying the exact build for Volatility 2 "
                 "(imageinfo, usually under a minute)")
        _pg.stage("Identifying Vol2 profile", "start",
                  "Vol2 imageinfo: matching the kernel debugger block to a profile")
        ok = self._detect_profile_vol2_impl(image)
        _pg.emit("stage", name="Identifying Vol2 profile", state="done" if ok else "fail",
                 profile=self.profile or "")
        return ok

    def _detect_profile_vol2_impl(self, image: str) -> bool:
        """Detect Vol2 profile using imageinfo.

        Handles edge cases:
          - 'No suggestion (Instantiated with Win10x64_15063)' → extract Win10x64_15063
          - 'No suggestion' alone → return False
          - Normal: 'Win7SP1x64, Win7SP0x64, Win2008R2SP1x64' → take first
        """
        if not self.vol2_cmd:
            return False
        rc, out, err = self._run_raw(self.vol2_cmd, image, "imageinfo", 300)
        for line in (out + err).splitlines():
            if "Suggested Profile" in line:
                after = line.split(":", 1)[-1].strip()
                first = after.split(",")[0].strip()

                # Reject "No suggestion" in any form
                if first.lower().startswith("no suggestion") or first.lower().startswith("no "):
                    # Try to extract profile from "Instantiated with ..." text
                    inst_match = re.search(r'Instantiated with (\w+)', after)
                    if inst_match:
                        extracted = inst_match.group(1)
                        # Validate: a real profile starts with Win, Linux, or Mac.
                        # Reject tokens like "no", "none", "unknown", etc.
                        if not re.match(r'^(Win|Linux|Mac)', extracted, re.IGNORECASE):
                            self.log.warning(
                                "Vol2 imageinfo: 'Instantiated with %s' is not a "
                                "recognisable profile — ignoring", extracted)
                            return False
                        self.log.info("Vol2 extracted profile from instantiation: %s",
                                      extracted)
                        if "Win10" in extracted or "Win11" in extracted or "Win8" in extracted:
                            self.log.warning("Win10/11 detected - Vol2 has poor support, will prefer Vol3")
                        self.profile = extracted
                        return True
                    self.log.warning("Vol2 imageinfo: No suggestion")
                    return False

                # Normal profile suggestion
                self.profile = first
                self.log.info("Vol2 profile detected: %s", self.profile)
                return True
        self.log.warning("Vol2 imageinfo did not suggest a profile")
        return False

    # -- Plugin execution --
    # Plugins that iterate every process/VMA/socket — much slower on busy images.
    # Given a longer timeout and forced in-process threading.
    NO_LIMIT_S = 30 * 86400        # "no time limit" on a retry: 30 days, effectively none
    HEAVY_PLUGINS = (
        "sockstat", "library_list", "lsof", "elfs", "psaux",
        "netscan", "mftscan", "vadinfo", "handles", "dlllist",
        "ldrmodules", "proc_maps", "proc.Maps", "list_files",
    )

    # Hard caps override the heavy multiplier for runaway plugins.
    # sockstat scans every socket on large images and can exceed 30 min;
    # lsof already captures open sockets so the gap is covered.
    _PLUGIN_HARD_CAPS = {
        "sockstat": 300,
    }

    def _plugin_timeout(self, plugin: str) -> int:
        """Heavy plugins get 3x the base timeout (min 1800s), with per-plugin hard caps."""
        base = max(self.timeout * 3, 1800) if self._is_heavy(plugin) else self.timeout
        for stem, cap in self._PLUGIN_HARD_CAPS.items():
            if stem in plugin.lower():
                return min(base, cap)
        return base

    def _is_heavy(self, plugin: str) -> bool:
        return any(h in plugin.lower() for h in self.HEAVY_PLUGINS)

    def run_plugin(self, image: str, plugin: str, output_dir: Path,
                   version: Optional[str] = None,
                   extra_args: Optional[List[str]] = None,
                   fixed_timeout: Optional[int] = None) -> Dict[str, Any]:
        """Run a single Volatility plugin and save JSON output.

        Logs the full command, exit code, duration, output size, and any errors.
        fixed_timeout (GUI retry button): the analyst's own limit in seconds, 0 = no
        limit; replaces the calibrated limit and the automatic extended retry.
        """
        ver = version or self.vol_version
        jd = output_dir / "json"
        jd.mkdir(parents=True, exist_ok=True)
        model = None
        size_gb = 1.0
        if self.dynamic_timeouts:
            try:
                from modules import timeout_model
                model = timeout_model.get_model()
                size_gb = timeout_model.image_size_gb(image)
            except Exception as e:  # never let the model break a run
                self.log.debug("timeout model unavailable: %s", e)
        if model is not None:
            # No hard caps on the calibrated path: the old 300 s sockstat cap
            # killed a legitimate 1150 s run (29k sockets, linux.vmem) and lost
            # the image's network data. Measured budgets + one retry decide.
            tmo = model.timeout(plugin, ver, self.os_type, size_gb)
            exp = model.expected(plugin, ver, self.os_type, size_gb)
            self.log.info("Running %s ... (expected ~%ds, timeout %ds for %.1f GB %s dump)",
                          plugin, exp, tmo, size_gb, self.os_type)
        else:
            tmo = self._plugin_timeout(plugin)
            heavy = " (heavy — extended timeout)" if self._is_heavy(plugin) else ""
            self.log.info("Running %s ...%s", plugin, heavy)

        if fixed_timeout is not None:
            tmo = int(fixed_timeout) if fixed_timeout > 0 else self.NO_LIMIT_S
            self.log.info("%s: analyst-chosen time limit %s (retry)", plugin,
                          f"{tmo} s" if fixed_timeout > 0 else "NONE (runs until it finishes or is stopped)")
        from modules import progress as _pg
        _exp = int(model.expected(plugin, ver, self.os_type, size_gb)) if model else 0

        def _once(t):
            st = time.time()
            _pg.emit("plugin", plugin=plugin, engine=ver, state="running",
                     timeout_s=t, expected_s=_exp)
            if ver == "vol3":
                r = self._run_vol3(image, plugin, jd, extra_args, st, t)
            else:
                r = self._run_vol2(image, plugin, jd, extra_args, st, t)
            to = str(r.get("error", "")).startswith("Timeout")
            _pg.emit("plugin", plugin=plugin, engine=ver,
                     state="done" if r.get("success") else ("timeout" if to else "failed"),
                     duration_s=round(r.get("duration", 0.0), 1),
                     error=str(r.get("error", ""))[:200])
            return r

        res = _once(tmo)
        is_to = str(res.get("error", "")).startswith("Timeout")
        if model is not None:
            model.record(plugin, ver, self.os_type, size_gb, res.get("duration", 0.0),
                         bool(res.get("success")), is_to, tmo)
        if is_to and fixed_timeout is not None:
            res["timed_out"] = True
            self.log.error("%s timed out after the chosen %ds limit - marked TIMED OUT in the report",
                           plugin, tmo)
            self._note_timeout(jd, plugin, tmo, tmo, "TIMED OUT (manual retry, your limit)")
        elif is_to and model is not None:
            t2 = model.retry_timeout(tmo)
            self.log.warning("%s timed out after %ds - killed; retrying once with an "
                             "extended timeout of %ds", plugin, tmo, t2)
            _pg.emit("plugin", plugin=plugin, engine=ver, state="retry", timeout_s=t2)
            res2 = _once(t2)
            is_to2 = str(res2.get("error", "")).startswith("Timeout")
            model.record(plugin, ver, self.os_type, size_gb, res2.get("duration", 0.0),
                         bool(res2.get("success")), is_to2, t2)
            res2["retried"] = True
            res2["first_timeout_s"] = tmo
            if is_to2:
                res2["timed_out"] = True
                res2["error"] = f"Timed out twice ({tmo}s, then {t2}s)"
                self.log.error("%s timed out again after %ds - marked TIMED OUT in the report",
                               plugin, t2)
                self._note_timeout(jd, plugin, tmo, t2)
            elif res2.get("success"):
                self.log.info("%s succeeded on retry (%.1fs)", plugin, res2.get("duration", 0))
            else:
                self.log.warning("%s failed on retry (%.1fs): %s", plugin,
                                 res2.get("duration", 0), str(res2.get("error", ""))[:200])
            res = res2
        if res.get("success"):
            self._clear_timeout(jd, plugin)   # a resumed run may succeed where an earlier one timed out
        return res

    def _clear_timeout(self, jd: Path, plugin: str) -> None:
        p = jd / "_timeouts.json"
        if not p.is_file():
            return
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            keep = [d for d in data if d.get("plugin") != plugin]
            if len(keep) != len(data):
                p.write_text(json.dumps(keep, indent=2), encoding="utf-8")
        except Exception:
            pass

    def _note_timeout(self, jd: Path, plugin: str, t1: int, t2: int,
                      status: str = "TIMED OUT") -> None:
        """Persist timed-out plugins so the report can flag them (one entry per plugin)."""
        p = jd / "_timeouts.json"
        try:
            data = json.loads(p.read_text(encoding="utf-8")) if p.is_file() else []
        except Exception:
            data = []
        data = [d for d in data if d.get("plugin") != plugin]
        data.append({"plugin": plugin, "first_timeout_s": t1, "retry_timeout_s": t2,
                     "status": status})
        try:
            p.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except OSError:
            pass

    def _run_vol3(self, image, plugin, jd, extra, start, tmo=None):
        name = plugin.replace(".", "_")
        out_path = jd / f"{name}.json"
        tmo = tmo or self.timeout
        cmd_parts = split_cmd(self.vol3_cmd) + ["-f", image]
        # Vol3 in-process threading is intentionally disabled.
        # Isolation testing confirmed the threads flag breaks Windows Vol3 plugins:
        # dlllist WITH the flag → rc=1 (unsatisfied kernel.layer_name);
        # dlllist WITHOUT the flag → rc=0, full output.
        # Linux/macOS were already excluded from threading for the same reason.
        cmd_parts += ["-r", "json", plugin]
        if extra:
            cmd_parts.extend(extra)
        cmd_str = " ".join(cmd_parts)
        self.log.debug("Command: %s", cmd_str)
        try:
            # errors="replace" guards against non-UTF-8 bytes in plugin output
            # (crashes the plugin under strict decoding, losing all its results).
            proc = _run_started(cmd_parts, tmo, self.log, plugin)
            dur = time.time() - start
            lines = [l for l in proc.stdout.splitlines() if not l.startswith("Progress:")]
            output = "\n".join(lines)
            # Always leave a VALID JSON file behind: a failed/empty plugin emits
            # nothing (or an error line) to stdout, which would otherwise be a
            # 0-byte/garbage .json that trips every json.load() downstream. Write
            # "[]" in that case so loaders read it as "no results" cleanly.
            _stripped = output.lstrip()
            out_path.write_text(output if _stripped[:1] in ("[", "{") else "[]",
                                encoding="utf-8")
            self.log.debug("Exit code: %d, Duration: %.1fs, Output: %s",
                           proc.returncode, dur, _size_str(len(output)))
            content = output.strip()
            # Distil stderr FIRST — it is the only place a silent new-kernel
            # struct drift shows up (rc=0, empty JSON, AttributeError on stderr).
            err_msg = _meaningful_stderr(proc.stderr) if proc.stderr else ""
            # Success decision (pure): non-zero rc / error banner => fail; on
            # Linux/macOS an rc=0-but-empty run that logged a systemic exception is
            # demoted from the old blanket "empty == success". See _vol3_success.
            ok = _vol3_success(proc.returncode, output, err_msg, self.os_type)
            if not ok and err_msg:
                self.log.warning("%s: %s", plugin, err_msg[:300])
            elif ok and _is_plugin_exception(err_msg):
                # Kept the result (it had rows) but the plugin logged a struct/
                # symbol exception — surface it so a new-kernel drift is not
                # silently discarded on an otherwise "successful" run.
                self.log.warning("%s: completed but logged an exception "
                                 "(results may be incomplete): %s",
                                 plugin, err_msg[:300])
            # Resume marker: a failed plugin leaves a <name>.json.error sidecar so
            # a later re-run re-executes it instead of trusting stale/partial
            # output (fixes resume cache-poisoning on silent failures). Removed on
            # success so a recovered plugin is not needlessly re-run.
            if not ok and not err_msg:
                # v2.4: never "FAILED: " with nothing after it
                err_msg = exit_reason(proc.returncode)
            _write_error_marker(out_path, ok, err_msg or f"exit {proc.returncode}")
            return {"success": ok, "plugin": plugin, "output_file": str(out_path),
                    "duration": dur, "returncode": proc.returncode,
                    "error": err_msg if not ok else ""}
        except subprocess.TimeoutExpired:
            dur = time.time() - start
            self.log.error("%s timed out after %ds", plugin, tmo)
            _write_error_marker(out_path, False, f"Timeout after {tmo}s")
            return {"success": False, "plugin": plugin, "output_file": str(out_path),
                    "duration": dur, "returncode": -1,
                    "error": f"Timeout after {tmo}s"}
        except Exception as exc:
            dur = time.time() - start
            self.log.error("%s exception: %s", plugin, exc)
            _write_error_marker(out_path, False, str(exc))
            return {"success": False, "plugin": plugin, "output_file": str(out_path),
                    "duration": dur, "returncode": -1, "error": str(exc)}

    def _run_vol2(self, image, plugin, jd, extra, start, tmo=None):
        tmo = tmo or self.timeout
        out_path = jd / f"{plugin}_vol2.json"
        cmd_parts = split_cmd(self.vol2_cmd) + ["-f", image]
        if self.profile:
            cmd_parts.append("--profile=" + self.profile)
        cmd_parts.append(plugin)
        if extra:
            cmd_parts.extend(extra)
        cmd_str = " ".join(cmd_parts)
        self.log.debug("Command: %s", cmd_str)
        try:
            # errors="replace": Vol2 plugins (e.g. driverscan) can emit raw
            # non-UTF-8 bytes from memory; strict decoding would crash the plugin
            # with a UnicodeDecodeError instead of returning its data.
            proc = _run_started(cmd_parts, tmo, self.log, plugin)
            dur = time.time() - start
            self.log.debug("Exit code: %d, Duration: %.1fs, Output: %d bytes",
                           proc.returncode, dur, len(proc.stdout))
            parsed = parse_vol2_table(proc.stdout, plugin)
            out_path.write_text(json.dumps(parsed, indent=2, default=str),
                                encoding="utf-8")
            # For Linux plugins, rc=0 with empty results is valid (e.g. linux_check_modules
            # returns nothing when no hidden modules are found). For Windows we require data.
            if self.os_type == "linux" and proc.returncode == 0:
                ok = True
            else:
                # Require rc=0 to avoid false positives where Vol2 exits non-zero
                # but parse_vol2_table still extracts partial/corrupt data.
                # rc=0 + a printed table header ("----" ruler) and no rows is a
                # genuine EMPTY result (e.g. no clipboard data), not a failure.
                header_only = (proc.returncode == 0 and not parsed and
                               re.search(r"^-{4,}(?:\s+-{2,})*\s*$", proc.stdout or "",
                                         re.M) is not None)
                ok = (proc.returncode == 0 and len(parsed) > 0) or header_only
                if header_only:
                    self.log.info("%s: ran OK, no rows (empty result)", plugin)
            if not ok and proc.stderr:
                self.log.warning("%s: %s", plugin, proc.stderr[:300].strip())
            _write_error_marker(out_path, ok, proc.stderr[:500] if proc.stderr
                                else exit_reason(proc.returncode))
            # A clean empty result leaves '[]'; mark it so resume does not take
            # it for an unfinished plugin and run it again.
            _write_empty_marker(out_path, ok and header_only if self.os_type != "linux"
                                else ok and not parsed)
            return {"success": ok, "plugin": plugin, "output_file": str(out_path),
                    "duration": dur, "returncode": proc.returncode,
                    "error": (proc.stderr[:500] or exit_reason(proc.returncode)) if not ok else ""}
        except subprocess.TimeoutExpired:
            dur = time.time() - start
            self.log.error("%s timed out after %ds", plugin, tmo)
            _write_error_marker(out_path, False, f"Timeout after {tmo}s")
            return {"success": False, "plugin": plugin, "output_file": str(out_path),
                    "duration": dur, "returncode": -1,
                    "error": f"Timeout after {tmo}s"}
        except Exception as exc:
            dur = time.time() - start
            self.log.error("%s exception: %s", plugin, exc)
            _write_error_marker(out_path, False, str(exc))
            return {"success": False, "plugin": plugin, "output_file": str(out_path),
                    "duration": dur, "returncode": -1, "error": str(exc)}

    def _probe_windows_info(self, image: str):
        """Probe windows.info.Info, progress-aware (no fixed timeout).

        Returns (rc, out, err). A fixed short timeout (the old _run_raw(...,45))
        is wrong for a large/cold image: building the kernel symbol table (PDB
        scan → ISF) on an 8.5GB image easily exceeds 45s, so the probe timed out,
        detection fell through to the weakest path, and the kernel symbol table
        was never established. run_vol_until_done waits on real progress instead,
        so this both detects Windows AND leaves the kernel symbols warm for the
        parallel plugin batch that follows.
        """
        cmd = split_cmd(self.vol3_cmd) + ["-f", image, "windows.info.Info"]
        return linux_identify.run_vol_until_done(cmd, self.log, stall_grace=120)

    def _run_raw(self, vol_cmd, image, plugin, timeout=60, extra=None):
        cmd = split_cmd(vol_cmd) + ["-f", image, plugin]
        if extra:
            cmd.extend(extra)
        try:
            with tempfile.TemporaryFile() as out_f, tempfile.TemporaryFile() as err_f:
                r = subprocess.run(cmd, stdout=out_f, stderr=err_f, timeout=timeout)
                out_f.seek(0)
                err_f.seek(0)
                out = out_f.read().decode("utf-8", errors="replace")
                err = err_f.read().decode("utf-8", errors="replace")
            return r.returncode, out, err
        except subprocess.TimeoutExpired:
            return -1, "", "Timeout"
        except Exception as exc:
            return -1, "", str(exc)

    def check_vol2_compatibility(self, output_dir: Path) -> bool:
        """Return True if Vol2 plugins should work (pre-Win10)."""
        if not self.vol2_cmd:
            return False
        jd = output_dir / "json"
        for pat in ("windows_info_Info", "windows_info", "info"):
            for f in jd.glob("*.json"):
                if pat.lower() in f.name.lower():
                    data = load_json_safe(f)
                    return self._chk_build(data)
        return True

    def _chk_build(self, data):
        if isinstance(data, list):
            for item in data:
                if not isinstance(item, dict):
                    continue
                var = item.get("Variable", item.get("variable", ""))
                val = item.get("Value", item.get("value", ""))
                if "NTBuildLab" in str(var):
                    try:
                        return int(str(val).split(".")[0]) < 10240
                    except (ValueError, IndexError):
                        pass
                if "NTMajorVersion" in str(var):
                    try:
                        return int(str(val)) < 10
                    except ValueError:
                        pass
        return True
