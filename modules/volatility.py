"""CresCent RAM Forensics Toolkit v4.0 - Volatility 2/3 Wrapper"""

import json
import logging
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from utils.json_converter import parse_vol2_table, load_json_safe
from modules import linux_identify

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
    # Windows: keep requiring real content (empty '[]' was already a failure).
    return len(content) > 10


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

    def _find_vol3(self):
        home = str(Path.home())
        for rp in self.V3_PATHS:
            p = rp.replace("{home}", home)
            if Path(p).is_file():
                # Resolve to an ABSOLUTE path so the command works even when a
                # plugin is run with a changed cwd (e.g. linux.pagecache.RecoverFs
                # writes its tarball to the current directory, so it is invoked
                # from the dump dir — a relative ../volatility3/vol.py would break).
                p = str(Path(p).resolve())
                if self._test_vol3(f"python3 {p}"):
                    self.vol3_cmd = f"python3 {p}"
                    self.log.info("Found Vol3: %s", self.vol3_cmd)
                    return
        for cmd in self.V3_CMDS:
            if shutil.which(cmd):
                self.vol3_cmd = cmd
                self.log.info("Found Vol3 command: %s", cmd)
                return

    def _find_vol2(self):
        home = str(Path.home())
        for rp in self.V2_PATHS:
            p = rp.replace("{home}", home)
            if Path(p).is_file():
                p = str(Path(p).resolve())  # absolute — survives cwd changes
                for py in ("python2", "python"):
                    if self._test_vol2(f"{py} {p}"):
                        self.vol2_cmd = f"{py} {p}"
                        self.log.info("Found Vol2: %s", self.vol2_cmd)
                        return
        for cmd in self.V2_CMDS:
            if shutil.which(cmd) and self._test_vol2(cmd):
                self.vol2_cmd = cmd
                self.log.info("Found Vol2 command: %s", cmd)
                return

    def _test_vol3(self, cmd):
        try:
            # 60s (not 15s): `vol.py -h` imports all of volatility3 and discovers
            # plugins, which can exceed 15s when the box is under load (e.g. right
            # after a heavy analysis run) — a slow-but-working Vol must not be
            # misreported as "not installed".
            r = subprocess.run(cmd.split() + ["-h"], capture_output=True,
                               timeout=60, text=True, errors="replace")
            return r.returncode == 0
        except Exception:
            return False

    def _test_vol2(self, cmd):
        try:
            r = subprocess.run(cmd.split() + ["--help"], capture_output=True,
                               timeout=60, text=True, errors="replace")
            return "--profile" in (r.stdout + r.stderr)
        except Exception:
            return False

    # -- Detection --
    def auto_detect(self, image: str) -> bool:
        """Auto-detect OS type and best Volatility engine.

        Detection chain:
          1. Vol3 banners.Banners (no symbols needed)
          2. Vol3 windows.info.Info (needs symbols)
          3. Vol2 imageinfo (profiles)
          4. Raw string scan for kernel signatures

        Supports both Windows and Linux images.
        """
        self.log.info("Auto-detecting OS and Volatility version...")

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
            cmd = self.vol3_cmd.split() + ["-f", image, "banners.Banners"]
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
                        "No working Linux symbols. Install the correct ISF via "
                        "linux_resolver or place Ubuntu16045.zip in Vol2 profiles.")
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
                if self.vol2_cmd and not self.profile:
                    self._detect_profile_vol2(image)
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
                if self.vol2_cmd and not self.profile:
                    self._detect_profile_vol2(image)
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

    def _fast_format_detect(self, image: str) -> str:
        """Cheap, high-confidence OS pre-check from the image header + first 16 MB."""
        return linux_identify.fast_format_detect(image, self.log)

    def _raw_os_detect(self, image: str) -> str:
        """Last resort: read first 10MB of image looking for OS signatures."""
        return linux_identify.raw_os_detect(image, self.log)

    def _detect_profile_vol2(self, image: str) -> bool:
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
                   extra_args: Optional[List[str]] = None) -> Dict[str, Any]:
        """Run a single Volatility plugin and save JSON output.

        Logs the full command, exit code, duration, output size, and any errors.
        """
        ver = version or self.vol_version
        jd = output_dir / "json"
        jd.mkdir(parents=True, exist_ok=True)
        tmo = self._plugin_timeout(plugin)
        if self._is_heavy(plugin):
            heavy = " (heavy — extended timeout)"
        else:
            heavy = ""
        self.log.info("Running %s ...%s", plugin, heavy)
        start = time.time()
        if ver == "vol3":
            return self._run_vol3(image, plugin, jd, extra_args, start, tmo)
        return self._run_vol2(image, plugin, jd, extra_args, start, tmo)

    def _run_vol3(self, image, plugin, jd, extra, start, tmo=None):
        name = plugin.replace(".", "_")
        out_path = jd / f"{name}.json"
        tmo = tmo or self.timeout
        cmd_parts = self.vol3_cmd.split() + ["-f", image]
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
            proc = subprocess.run(cmd_parts, capture_output=True, text=True,
                                  errors="replace", timeout=tmo)
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
        cmd_parts = self.vol2_cmd.split() + ["-f", image]
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
            proc = subprocess.run(cmd_parts, capture_output=True, text=True,
                                  errors="replace", timeout=tmo)
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
                ok = (proc.returncode == 0 and len(parsed) > 0)
            if not ok and proc.stderr:
                self.log.warning("%s: %s", plugin, proc.stderr[:300].strip())
            _write_error_marker(out_path, ok, proc.stderr[:500] if proc.stderr
                                else f"exit {proc.returncode}")
            return {"success": ok, "plugin": plugin, "output_file": str(out_path),
                    "duration": dur, "returncode": proc.returncode,
                    "error": proc.stderr[:500] if not ok else ""}
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
        cmd = self.vol3_cmd.split() + ["-f", image, "windows.info.Info"]
        return linux_identify.run_vol_until_done(cmd, self.log, stall_grace=120)

    def _run_raw(self, vol_cmd, image, plugin, timeout=60, extra=None):
        cmd = vol_cmd.split() + ["-f", image, plugin]
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
