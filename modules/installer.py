"""
CresCent RAM Forensics Toolkit v4.0 - Volatility Installer

Auto-downloads and configures Volatility 2 + 3 with ALL dependencies:
  - Volatility 3 (Python 3) + Windows/Linux/Mac symbol tables
  - Volatility 2 (Python 2) + pycryptodome + distorm3
  - yara-python, pefile (Vol3 optional deps)

Usage:
    from modules.installer import VolatilityInstaller
    inst = VolatilityInstaller(logger)
    inst.check_and_install()
"""

import hashlib
import logging
import os
import platform
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# Optional integrity pins for the Volatility symbol zips (H3 follow-up). These
# packs are refreshed upstream whenever new OS builds ship, so they are NOT pinned
# by default — a stale hash would reject a legitimate update. To LOCK a vetted
# version: run a symbol download, copy the `sha256=…` the installer logs into the
# matching entry below, and it is enforced on every later download (mismatch =>
# refused). Left empty = archive-format + structural-integrity check only, which
# still rejects a MITM/broken-mirror payload (an HTML error page, a truncated or
# corrupt zip) before it is ever extracted.
PINNED_SYMBOL_SHA256: Dict[str, str] = {
    # "windows": "<sha256 hex>",
    # "linux":   "<sha256 hex>",
    # "mac":     "<sha256 hex>",
}


def verify_symbol_zip(zip_path: Path,
                      expected_sha256: Optional[str] = None
                      ) -> Tuple[bool, str, str]:
    """Integrity-check a downloaded Volatility symbol zip BEFORE extraction.

    Returns ``(ok, sha256, reason)``. Checks, in order: (1) the file's magic is a
    real zip — rejects an HTML error page / redirect body / garbage from a broken
    or hostile mirror; (2) if a pin is supplied, the sha256 must match it; (3) the
    central directory + per-entry CRCs via ``zipfile.testzip()`` — rejects a
    truncated or corrupt download. Always returns the computed sha256 so an
    operator can pin a vetted version. Pure w.r.t. its file input; never raises.
    """
    try:
        with open(zip_path, "rb") as f:
            head = f.read(4)
    except Exception as e:
        return (False, "", f"unreadable: {e}")
    if head != b"PK\x03\x04":
        return (False, "", f"not a zip (magic {head.hex()}) — tampered/broken mirror")
    h = hashlib.sha256()
    try:
        with open(zip_path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
    except Exception as e:
        return (False, "", f"unreadable: {e}")
    digest = h.hexdigest()
    if expected_sha256 and digest.lower() != expected_sha256.lower():
        return (False, digest, "sha256 does not match the configured pin")
    try:
        with zipfile.ZipFile(zip_path) as z:
            bad = z.testzip()
        if bad is not None:
            return (False, digest, f"corrupt zip (bad CRC in {bad})")
    except zipfile.BadZipFile as e:
        return (False, digest, f"bad zip: {e}")
    return (True, digest, "ok")


class VolatilityInstaller:
    """Check, download, and install Volatility 2 + 3 with all dependencies."""

    # Default install location
    INSTALL_DIR = Path.home() / "Desktop"

    # Vol3 repo
    VOL3_REPO = "https://github.com/volatilityfoundation/volatility3.git"
    VOL3_DIR = "volatility3"

    # Vol2 repo
    VOL2_REPO = "https://github.com/volatilityfoundation/volatility.git"
    VOL2_DIR = "volatility"

    # Symbol table URLs
    SYMBOLS = {
        "windows": "https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip",
        "linux": "https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip",
        "mac": "https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip",
    }

    # Vol2 Python 2 dependencies (unlock hashdump, shellbags, shimcache, etc.)
    VOL2_DEPS = ["pycryptodome", "distorm3"]

    # Vol3 optional dependencies (python-evtx required for EVTX parsing)
    VOL3_DEPS = ["yara-python", "pefile", "capstone", "python-evtx"]

    def __init__(self, logger: logging.Logger,
                 install_dir: Optional[Path] = None):
        self.log = logger
        self.install_dir = Path(install_dir) if install_dir else self.INSTALL_DIR

    def full_status(self) -> Dict[str, any]:
        """Check everything and return a status dict."""
        status = {
            "python3": self._check_python3(),
            "python2": self._check_python2(),
            "vol3_installed": self._check_vol3_installed(),
            "vol3_path": self._find_vol3_path(),
            "vol2_installed": self._check_vol2_installed(),
            "vol2_path": self._find_vol2_path(),
            "vol3_symbols_windows": self._check_symbols("windows"),
            "vol3_symbols_linux": self._check_symbols("linux"),
            "vol3_symbols_mac": self._check_symbols("mac"),
            "vol2_pycryptodome": self._check_pip2_package("pycryptodome"),
            "vol2_distorm3": self._check_pip2_package("distorm3"),
            "vol3_yara": self._check_pip3_package("yara-python"),
            "vol3_pefile": self._check_pip3_package("pefile"),
            "git": bool(shutil.which("git")),
            "strings": bool(shutil.which("strings")),
            "yara": bool(shutil.which("yara")),
            # ISF build pipeline (Linux auto-symbol creation from debug packages)
            "dwarf2json": bool(self._find_dwarf2json()),
            "dpkg-deb": bool(shutil.which("dpkg-deb") or shutil.which("ar")),
            "xz": bool(shutil.which("xz")),
            "curl": bool(shutil.which("curl") or shutil.which("wget")),
            "rpm2cpio": bool(shutil.which("rpm2cpio")),  # RHEL/CentOS ISF path
            # CresCentC's bundled Vol3 plugin(s) present in the Vol3 install?
            "mac_pagecache_plugin": self._check_mac_pagecache_installed(),
        }
        return status

    def _check_mac_pagecache_installed(self) -> bool:
        """True if the bundled mac.pagecache plugin is present in the Vol3 install."""
        vp = self._find_vol3_path()
        if not vp:
            return False
        return (Path(vp).parent / "volatility3" / "framework" / "plugins"
                / "mac" / "pagecache.py").is_file()

    # ------------------------------------------------------------------
    # ISF build pipeline dependencies (dwarf2json + package extraction tools)
    # ------------------------------------------------------------------
    _BUNDLED_D2J = [
        Path(__file__).resolve().parent.parent / "_isf_build" / "dwarf2json",
        Path(__file__).resolve().parent.parent / "dwarf2json",
    ]

    # CresCentC's own Vol3 plugins (not in upstream Vol3), shipped in the repo and
    # copied into a freshly-cloned Vol3 on install so they survive a reinstall.
    # Layout under vol_plugins/ mirrors volatility3/framework/plugins/ (e.g.
    # vol_plugins/mac/pagecache.py -> <vol3>/volatility3/framework/plugins/mac/).
    _BUNDLED_PLUGINS_DIR = Path(__file__).resolve().parent.parent / "vol_plugins"

    def install_bundled_plugins(self, vol3_root: Optional[Path] = None) -> Dict[str, bool]:
        """Copy CresCentC's bundled Vol3 plugins into the Vol3 framework.

        Upstream Vol3 has no macOS page-cache file-content recoverer; CresCentC
        ships `mac.pagecache` in the repo (vol_plugins/mac/pagecache.py) and this
        drops it into the Vol3 install so a stock/fresh clone gains it. Idempotent
        — safe to re-run after any reinstall. Returns {relpath: ok}.
        """
        results: Dict[str, bool] = {}
        src_root = self._BUNDLED_PLUGINS_DIR
        if not src_root.is_dir():
            return results
        if vol3_root is None:
            vp = self._find_vol3_path()
            if not vp:
                self.log.warning("Vol3 not found — cannot install bundled plugins")
                return results
            vol3_root = Path(vp).parent
        dest_root = Path(vol3_root) / "volatility3" / "framework" / "plugins"
        if not dest_root.is_dir():
            self.log.warning("Vol3 plugins dir not found (%s) — skipping bundled plugins",
                             dest_root)
            return results
        for src in sorted(src_root.rglob("*.py")):
            rel = src.relative_to(src_root)
            dest = dest_root / rel
            try:
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(str(src), str(dest))
                results[str(rel)] = True
                self.log.info("Installed bundled Vol3 plugin: %s", dest)
            except Exception as e:
                results[str(rel)] = False
                self.log.error("Failed to install bundled plugin %s: %s", rel, e)
        return results

    # Idempotent source patches for bugs that live in Vol3 *framework* files
    # (not standalone plugins, so they can't be shipped via vol_plugins/).
    # Each entry: (relative path under <vol3>/volatility3/, buggy snippet,
    # fixed snippet). Applied only if the buggy snippet is still present, so a
    # reinstall of a newer upstream that already fixed it is a safe no-op.
    _FRAMEWORK_FIXES = [
        (
            "framework/symbols/mac/__init__.py",
            # BUGGY: `path` is left unbound when ftype is falsy/unknown ->
            # UnboundLocalError in mac.netstat / any fd walker.
            "                if ftype == \"VNODE\":\n"
            "                    vnode = f.f_fglob.fg_data.dereference().cast(\"vnode\")\n"
            "                    path = vnode.full_path()\n"
            "                elif ftype:\n"
            "                    path = f\"<{ftype.lower()}>\"\n"
            "\n"
            "                yield f, path, fd_num",
            # FIXED: always bind path; guard the VNODE deref against smear.
            "                # path must always be bound before the yield below; a falsy/\n"
            "                # unknown ftype used to leave it unset -> UnboundLocalError.\n"
            "                path = None\n"
            "                if ftype == \"VNODE\":\n"
            "                    try:\n"
            "                        vnode = f.f_fglob.fg_data.dereference().cast(\"vnode\")\n"
            "                        path = vnode.full_path()\n"
            "                    except exceptions.InvalidAddressException:\n"
            "                        path = None\n"
            "                elif ftype:\n"
            "                    path = f\"<{ftype.lower()}>\"\n"
            "\n"
            "                yield f, path, fd_num",
        ),
        (
            "framework/symbols/linux/utilities/tainting.py",
            # BUGGY: reads `taint_flag.module`, but kernel 6.19 dropped that
            # field from `struct taint_flag` ({c_true, c_false, desc}) -> every
            # module taint lookup raises AttributeError and kills linux.lsmod.
            # Anchored to the post-4.10 loop (the path 6.x kernels take); the
            # identical line in the pre-4.10 helper is never reached there and
            # must not be the one patched by replace(..., 1).
            "        for taint_bit, taint_flag in enumerate(\n"
            "            cls._get_kernel_taint_flags_list(context, kernel_module_name)\n"
            "        ):\n"
            "            if is_module and not taint_flag.module:\n"
            "                continue",
            # FIXED: tolerate a missing `module` field (newer kernels) — when it
            # is absent, treat the taint as module-relevant rather than crashing.
            "        for taint_bit, taint_flag in enumerate(\n"
            "            cls._get_kernel_taint_flags_list(context, kernel_module_name)\n"
            "        ):\n"
            "            # Kernel 6.19 removed `module` from struct taint_flag;\n"
            "            # default to True so the taint is shown instead of raising.\n"
            "            if is_module and not getattr(taint_flag, \"module\", True):\n"
            "                continue",
        ),
    ]

    def apply_framework_fixes(self, vol3_root: Optional[Path] = None) -> Dict[str, bool]:
        """Apply CresCentC's idempotent source patches to Vol3 framework files.

        Some Vol3 bugs live in shared framework modules rather than standalone
        plugins, so they can't ride along in vol_plugins/. We patch them in
        place after a clone. Each patch is guarded on the exact buggy text, so
        it applies at most once and is a no-op if upstream already fixed it or
        it's already patched. Returns {relpath: applied?}.
        """
        results: Dict[str, bool] = {}
        if vol3_root is None:
            vp = self._find_vol3_path()
            if not vp:
                return results
            vol3_root = Path(vp).parent
        base = Path(vol3_root) / "volatility3"
        for rel, buggy, fixed in self._FRAMEWORK_FIXES:
            target = base / rel
            try:
                if not target.is_file():
                    continue
                text = target.read_text()
                if fixed in text:
                    results[rel] = False  # already patched
                    continue
                if buggy not in text:
                    self.log.info("Framework fix skipped (pattern gone, likely "
                                  "upstream-fixed): %s", rel)
                    results[rel] = False
                    continue
                target.write_text(text.replace(buggy, fixed, 1))
                results[rel] = True
                self.log.info("Applied framework fix: %s", rel)
            except Exception as e:
                results[rel] = False
                self.log.error("Failed to apply framework fix %s: %s", rel, e)
        return results

    def _find_dwarf2json(self) -> str:
        """dwarf2json on PATH, else the binary bundled in the repo."""
        onpath = shutil.which("dwarf2json")
        if onpath:
            return onpath
        for cand in self._BUNDLED_D2J:
            if cand.is_file() and os.access(str(cand), os.X_OK):
                return str(cand)
        return ""

    def ensure_isf_build_tools(self, use_sudo: bool = True) -> Dict[str, bool]:
        """Guarantee the tools needed to build a Vol3 ISF from a kernel's debug
        package: dwarf2json, dpkg-deb (or ar), xz, curl. dwarf2json ships bundled
        in the repo; the rest come from apt if missing.

        Returns a per-tool availability dict.
        """
        results: Dict[str, bool] = {}

        # 1. dwarf2json — expose the bundled binary on PATH so every code path
        #    (including shutil.which callers) finds it.
        d2j = self._find_dwarf2json()
        if d2j and not shutil.which("dwarf2json"):
            for target in ("/usr/local/bin/dwarf2json",
                           str(Path.home() / ".local" / "bin" / "dwarf2json")):
                try:
                    Path(target).parent.mkdir(parents=True, exist_ok=True)
                    if use_sudo and target.startswith("/usr"):
                        subprocess.run(["sudo", "-n", "cp", d2j, target],
                                       capture_output=True, timeout=30)
                        subprocess.run(["sudo", "-n", "chmod", "+x", target],
                                       capture_output=True, timeout=15)
                    else:
                        shutil.copy2(d2j, target)
                        os.chmod(target, 0o755)
                    if Path(target).is_file():
                        self.log.info("dwarf2json installed to %s", target)
                        break
                except Exception as e:
                    self.log.debug("dwarf2json -> %s failed: %s", target, e)
        results["dwarf2json"] = bool(self._find_dwarf2json())

        # 2. apt packages for extraction/compression/download.
        apt_pkgs = {
            "dpkg-deb": "dpkg",          # dpkg-deb ships in dpkg (Debian ISF path)
            "ar": "binutils",
            "xz": "xz-utils",
            "curl": "curl",
            "rpm2cpio": "rpm",           # RHEL/CentOS debuginfo ISF path
            "cpio": "cpio",
        }
        missing = [pkg for tool, pkg in apt_pkgs.items()
                   if not shutil.which(tool)]
        if missing and shutil.which("apt-get"):
            self.log.info("Installing ISF-build deps via apt: %s", missing)
            try:
                cmd = (["sudo", "-n"] if use_sudo else []) + \
                    ["apt-get", "install", "-y"] + list(set(missing))
                subprocess.run(cmd, capture_output=True, timeout=300)
            except Exception as e:
                self.log.error("apt install failed: %s", e)

        results["dpkg-deb"] = bool(shutil.which("dpkg-deb") or shutil.which("ar"))
        results["xz"] = bool(shutil.which("xz"))
        results["curl"] = bool(shutil.which("curl") or shutil.which("wget"))
        for tool, ok in results.items():
            self.log.info("  ISF dep %s: %s", tool, "OK" if ok else "MISSING")
        return results

    def print_status(self) -> Dict:
        """Print a formatted status check."""
        status = self.full_status()
        print()
        print("   VOLATILITY INSTALLATION STATUS")
        print("   " + "=" * 50)
        print()

        # Python
        py3 = status["python3"]
        py2 = status["python2"]
        print(f"   Python 3:  {'OK (' + sys.version.split()[0] + ')' if py3 else 'MISSING'}")
        print(f"   Python 2:  {'OK' if py2 else 'MISSING (needed for Vol2)'}")
        print()

        # Vol3
        v3 = status["vol3_installed"]
        v3p = status["vol3_path"] or "not found"
        print(f"   Volatility 3:  {'OK' if v3 else 'NOT INSTALLED'}")
        if v3:
            print(f"     Path: {v3p}")
        ws = status["vol3_symbols_windows"]
        ls = status["vol3_symbols_linux"]
        ms = status["vol3_symbols_mac"]
        print(f"     Windows symbols: {'OK' if ws else 'MISSING'}")
        print(f"     Linux symbols:   {'OK' if ls else 'MISSING'}")
        print(f"     Mac symbols:     {'OK' if ms else 'MISSING'}")
        yr = status["vol3_yara"]
        pf = status["vol3_pefile"]
        print(f"     yara-python:     {'OK' if yr else 'MISSING (yarascan disabled)'}")
        print(f"     pefile:          {'OK' if pf else 'MISSING (netscan may fail)'}")
        print()

        # Vol2
        v2 = status["vol2_installed"]
        v2p = status["vol2_path"] or "not found"
        print(f"   Volatility 2:  {'OK' if v2 else 'NOT INSTALLED'}")
        if v2:
            print(f"     Path: {v2p}")
        pc = status["vol2_pycryptodome"]
        d3 = status["vol2_distorm3"]
        print(f"     pycryptodome:    {'OK' if pc else 'MISSING (hashdump, shellbags, shimcache disabled)'}")
        print(f"     distorm3:        {'OK' if d3 else 'MISSING (apihooks, ssdt disabled)'}")
        print()

        # Tools
        print(f"   git:       {'OK' if status['git'] else 'MISSING (needed for install)'}")
        print(f"   strings:   {'OK' if status['strings'] else 'MISSING (install binutils)'}")
        print(f"   yara:      {'OK' if status['yara'] else 'MISSING (optional)'}")
        print()

        # ISF build pipeline (Linux auto-symbol creation)
        print("   ISF build (Linux auto-symbols):")
        print(f"     dwarf2json:      {'OK' if status.get('dwarf2json') else 'MISSING (bundled in _isf_build/)'}")
        print(f"     dpkg-deb/ar:     {'OK' if status.get('dpkg-deb') else 'MISSING (install dpkg/binutils)'}")
        print(f"     xz:              {'OK' if status.get('xz') else 'MISSING (install xz-utils)'}")
        print(f"     curl/wget:       {'OK' if status.get('curl') else 'MISSING (install curl)'}")
        print()

        # CresCentC bundled Vol3 plugins (e.g. macOS page-cache file recovery)
        print("   Bundled Vol3 plugins:")
        print(f"     mac.pagecache:   {'OK (installed in Vol3)' if status.get('mac_pagecache_plugin') else 'NOT in Vol3 (run Install Vol3 to add it)'}")
        print()

        # Summary
        issues = []
        if not v3:
            issues.append("Volatility 3 not installed")
        if not v2:
            issues.append("Volatility 2 not installed")
        if v3 and not ws:
            issues.append("Vol3 Windows symbols missing")
        if v3 and not ls:
            issues.append("Vol3 Linux symbols missing")
        if v2 and not pc:
            issues.append("Vol2 pycryptodome missing (hashdump broken)")
        if v2 and not d3:
            issues.append("Vol2 distorm3 missing (apihooks broken)")

        if issues:
            print(f"   ISSUES ({len(issues)}):")
            for i in issues:
                print(f"     ! {i}")
        else:
            print("   ALL OK - Full capability!")

        print()
        return status

    # ------------------------------------------------------------------
    # Installation methods
    # ------------------------------------------------------------------

    def install_vol3(self) -> bool:
        """Clone and set up Volatility 3."""
        target = self.install_dir / self.VOL3_DIR
        if target.is_dir():
            self.log.info("Vol3 already exists at %s", target)
            self.install_bundled_plugins(target)   # ensure our plugins are present
            self.apply_framework_fixes(target)     # ensure framework patches applied
            return True

        if not shutil.which("git"):
            self.log.error("git not found. Install: sudo apt install git")
            return False

        self.log.info("Cloning Volatility 3 to %s...", target)
        try:
            subprocess.run(
                ["git", "clone", self.VOL3_REPO, str(target)],
                check=True, timeout=300)
            # Install requirements
            req = target / "requirements.txt"
            if req.exists():
                self.log.info("Installing Vol3 requirements...")
                subprocess.run(
                    [sys.executable, "-m", "pip", "install", "-r", str(req),
                     "--break-system-packages"],
                    capture_output=True, timeout=120)
            self.log.info("Volatility 3 installed at %s", target)
            # Drop CresCentC's bundled plugins (e.g. mac.pagecache) into the fresh
            # clone so macOS file-content recovery works out of the box.
            bp = self.install_bundled_plugins(target)
            if bp:
                self.log.info("Bundled Vol3 plugins installed: %s",
                              ", ".join(sorted(bp)))
            fx = self.apply_framework_fixes(target)
            if any(fx.values()):
                self.log.info("Applied Vol3 framework fixes: %s",
                              ", ".join(sorted(k for k, v in fx.items() if v)))
            return True
        except Exception as e:
            self.log.error("Vol3 install failed: %s", e)
            return False

    def install_vol2(self) -> bool:
        """Clone and set up Volatility 2."""
        target = self.install_dir / self.VOL2_DIR
        if target.is_dir():
            self.log.info("Vol2 already exists at %s", target)
            return True

        if not shutil.which("git"):
            self.log.error("git not found. Install: sudo apt install git")
            return False

        # Check Python 2
        if not self._check_python2():
            self.log.error("Python 2 not found. Install: sudo apt install python2")
            return False

        self.log.info("Cloning Volatility 2 to %s...", target)
        try:
            subprocess.run(
                ["git", "clone", self.VOL2_REPO, str(target)],
                check=True, timeout=300)
            self.log.info("Volatility 2 installed at %s", target)
            return True
        except Exception as e:
            self.log.error("Vol2 install failed: %s", e)
            return False

    def install_vol2_deps(self) -> Dict[str, bool]:
        """Install Vol2 Python 2 dependencies (pycryptodome, distorm3)."""
        results = {}
        py2 = self._find_python2()
        if not py2:
            self.log.error("Python 2 not found")
            return {"error": "no python2"}

        # First ensure pip2 exists
        if not self._check_pip2():
            self.log.info("Installing pip for Python 2...")
            import tempfile as _tf
            get_pip = str(Path(_tf.gettempdir()) / "get-pip.py")
            try:
                subprocess.run(
                    ["curl", "-sSL",
                     "https://bootstrap.pypa.io/pip/2.7/get-pip.py",
                     "-o", get_pip],
                    check=True, timeout=60)
                subprocess.run(
                    [py2, get_pip], capture_output=True, timeout=120)
            except Exception as e:
                self.log.error("pip2 install failed: %s", e)

        for dep in self.VOL2_DEPS:
            self.log.info("Installing %s for Python 2...", dep)
            try:
                proc = subprocess.run(
                    [py2, "-m", "pip", "install", dep,
                     "--break-system-packages"],
                    capture_output=True, text=True, timeout=120)
                ok = proc.returncode == 0
                if not ok:
                    # Try without --break-system-packages
                    proc = subprocess.run(
                        [py2, "-m", "pip", "install", dep],
                        capture_output=True, text=True, timeout=120)
                    ok = proc.returncode == 0
                results[dep] = ok
                if ok:
                    self.log.info("  %s: OK", dep)
                else:
                    self.log.error("  %s: FAILED - %s", dep,
                                   proc.stderr[:200] if proc.stderr else "")
            except Exception as e:
                results[dep] = False
                self.log.error("  %s: ERROR - %s", dep, e)

        return results

    def install_vol3_deps(self) -> Dict[str, bool]:
        """Install Vol3 optional dependencies (yara-python, pefile, capstone)."""
        results = {}
        for dep in self.VOL3_DEPS:
            self.log.info("Installing %s for Python 3...", dep)
            try:
                proc = subprocess.run(
                    [sys.executable, "-m", "pip", "install", dep,
                     "--break-system-packages"],
                    capture_output=True, text=True, timeout=120)
                ok = proc.returncode == 0
                results[dep] = ok
                self.log.info("  %s: %s", dep, "OK" if ok else "FAILED")
            except Exception as e:
                results[dep] = False
                self.log.error("  %s: ERROR - %s", dep, e)
        return results

    def download_symbols(self, os_types: Optional[List[str]] = None) -> Dict[str, bool]:
        """Download Vol3 symbol tables.

        Args:
            os_types: List of ["windows", "linux", "mac"]. None = all.
        """
        if os_types is None:
            os_types = ["windows", "linux"]

        vol3_path = self._find_vol3_path()
        if not vol3_path:
            self.log.error("Vol3 not found. Install Vol3 first.")
            return {}

        sym_dir = Path(vol3_path).parent / "volatility3" / "symbols"
        if not sym_dir.is_dir():
            sym_dir = Path(vol3_path).parent / "symbols"
        sym_dir.mkdir(parents=True, exist_ok=True)

        results = {}
        for os_type in os_types:
            url = self.SYMBOLS.get(os_type)
            if not url:
                continue
            zip_name = f"{os_type}.zip"
            zip_path = sym_dir / zip_name

            if self._check_symbols(os_type):
                self.log.info("%s symbols already present", os_type)
                results[os_type] = True
                continue

            self.log.info("Downloading %s symbols from %s...", os_type, url)
            try:
                # Use wget or curl
                if shutil.which("wget"):
                    subprocess.run(
                        ["wget", "-q", "--show-progress", "-O", str(zip_path), url],
                        check=True, timeout=600)
                elif shutil.which("curl"):
                    subprocess.run(
                        ["curl", "-L", "-o", str(zip_path), url],
                        check=True, timeout=600)
                else:
                    # Python fallback
                    import urllib.request
                    urllib.request.urlretrieve(url, str(zip_path))

                # Verify integrity BEFORE extracting: a MITM/broken mirror could
                # have served an HTML error page or a truncated/corrupt zip, and a
                # pinned sha256 (if configured) must match.
                if zip_path.exists():
                    ok, digest, reason = verify_symbol_zip(
                        zip_path, PINNED_SYMBOL_SHA256.get(os_type))
                    if not ok:
                        self.log.error(
                            "%s symbol zip failed integrity check: %s "
                            "(sha256=%s) — refusing to extract",
                            os_type, reason, (digest[:16] + "…") if digest else "?")
                        zip_path.unlink(missing_ok=True)
                        results[os_type] = False
                        continue
                    if PINNED_SYMBOL_SHA256.get(os_type):
                        self.log.info("%s symbol zip verified (sha256 matches pin)",
                                      os_type)
                    else:
                        self.log.info(
                            "%s symbol zip verified: sha256=%s… — add to "
                            "PINNED_SYMBOL_SHA256 to lock this version",
                            os_type, digest[:16])
                    self.log.info("Extracting %s...", zip_name)
                    subprocess.run(
                        ["unzip", "-o", "-q", str(zip_path), "-d", str(sym_dir)],
                        check=True, timeout=300)
                    results[os_type] = True
                    self.log.info("%s symbols installed to %s", os_type, sym_dir)
                else:
                    results[os_type] = False
                    self.log.error("Download failed for %s", os_type)

            except Exception as e:
                results[os_type] = False
                self.log.error("%s symbols download failed: %s", os_type, e)

        return results

    def install_all(self) -> Dict[str, bool]:
        """Install everything: Vol3, Vol2, all deps, all symbols, Go, dwarf2json."""
        results = {}

        # Vol3
        results["vol3"] = self.install_vol3()
        if results["vol3"]:
            r = self.install_vol3_deps()
            results.update({f"vol3_{k}": v for k, v in r.items()})
            s = self.download_symbols(["windows", "linux"])
            results.update({f"symbols_{k}": v for k, v in s.items()})

        # Vol2
        results["vol2"] = self.install_vol2()
        if results["vol2"]:
            r = self.install_vol2_deps()
            results.update({f"vol2_{k}": v for k, v in r.items()})

        # ISF build pipeline (dwarf2json + dpkg-deb/xz/curl) for Linux auto-symbols
        r = self.ensure_isf_build_tools()
        results.update({f"isf_{k}": v for k, v in r.items()})

        return results

    # ------------------------------------------------------------------
    # Check methods
    # ------------------------------------------------------------------

    def _check_python3(self) -> bool:
        return sys.version_info >= (3, 6)

    def _check_python2(self) -> bool:
        return bool(self._find_python2())

    def _find_python2(self) -> str:
        for cmd in ("python2", "python2.7"):
            if shutil.which(cmd):
                return cmd
        # Check if "python" is Python 2
        p = shutil.which("python")
        if p:
            try:
                r = subprocess.run([p, "--version"], capture_output=True,
                                   text=True, timeout=5)
                if "2.7" in (r.stdout + r.stderr):
                    return p
            except Exception:
                pass
        return ""

    def _check_pip2(self) -> bool:
        py2 = self._find_python2()
        if not py2:
            return False
        try:
            r = subprocess.run([py2, "-m", "pip", "--version"],
                               capture_output=True, timeout=10)
            return r.returncode == 0
        except Exception:
            return False

    def _check_vol3_installed(self) -> bool:
        return bool(self._find_vol3_path())

    def _check_vol2_installed(self) -> bool:
        return bool(self._find_vol2_path())

    def _find_vol3_path(self) -> str:
        home = str(Path.home())
        for p in [
            f"{home}/Desktop/volatility3/vol.py",
            f"{home}/volatility3/vol.py",
            "/opt/volatility3/vol.py",
            f"{home}/tools/volatility3/vol.py",
        ]:
            if Path(p).is_file():
                return p
        for cmd in ("vol", "vol3", "volatility3"):
            c = shutil.which(cmd)
            if c:
                return c
        return ""

    def _find_vol2_path(self) -> str:
        home = str(Path.home())
        for p in [
            f"{home}/Desktop/volatility/vol.py",
            f"{home}/volatility/vol.py",
            "/opt/volatility/vol.py",
            "/usr/share/volatility/vol.py",
            f"{home}/tools/volatility/vol.py",
        ]:
            if Path(p).is_file():
                return p
        for cmd in ("volatility", "vol2", "volatility2"):
            c = shutil.which(cmd)
            if c:
                return c
        return ""

    def _check_symbols(self, os_type: str) -> bool:
        """Check if symbol tables exist for the given OS."""
        vol3_path = self._find_vol3_path()
        if not vol3_path:
            return False
        vol3_dir = Path(vol3_path).parent
        for sym_dir in [
            vol3_dir / "volatility3" / "symbols",
            vol3_dir / "symbols",
        ]:
            if not sym_dir.is_dir():
                continue
            # Check for .json.xz or .json files or subdirectories
            if os_type == "windows":
                if list(sym_dir.glob("windows/**/*.json.xz")) or \
                   list(sym_dir.glob("windows/**/*.json")) or \
                   (sym_dir / "windows").is_dir():
                    return True
            elif os_type == "linux":
                if list(sym_dir.glob("linux/**/*.json.xz")) or \
                   list(sym_dir.glob("linux/**/*.json")) or \
                   (sym_dir / "linux").is_dir():
                    return True
            elif os_type == "mac":
                if list(sym_dir.glob("mac/**/*.json.xz")) or \
                   list(sym_dir.glob("mac/**/*.json")) or \
                   (sym_dir / "mac").is_dir():
                    return True
        return False

    def _check_pip2_package(self, package: str) -> bool:
        py2 = self._find_python2()
        if not py2:
            return False
        try:
            r = subprocess.run(
                [py2, "-c", f"import {package.replace('-', '_')}"],
                capture_output=True, timeout=10)
            return r.returncode == 0
        except Exception:
            return False

    def _check_pip3_package(self, package: str) -> bool:
        try:
            pkg = package.replace("-", "_")
            # Special case for yara-python
            if package == "yara-python":
                pkg = "yara"
            r = subprocess.run(
                [sys.executable, "-c", f"import {pkg}"],
                capture_output=True, timeout=10)
            return r.returncode == 0
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Linux Symbol Builder (removed — use CresCent Linux toolkit)
    # ------------------------------------------------------------------
