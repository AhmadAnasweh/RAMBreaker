#!/usr/bin/env python3
"""
CresCent v6.0 — macOS symbol resolver
Author: Ahmad Anasweh

linux_resolver.py — Linux image handler

When the toolkit detects a Linux memory image it calls this module instead
of exiting. It automatically resolves Volatility 3 symbols and launches a
basic interactive Linux analysis session.

Symbol source: Abyss-W4tcher/volatility3-symbols (community-maintained repo)
  https://github.com/Abyss-W4tcher/volatility3-symbols

Integration in crescent_toolkit.py:
    if vol.os_type in ("linux", "mac"):
        from modules.linux_resolver import resolve_symbols
        resolve_symbols(image, vol.os_type, output_dir=od)
"""

import gzip
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional, Tuple

# ── Constants ──────────────────────────────────────────────────────────────────

BANNERS_INDEX_URL = (
    "https://raw.githubusercontent.com/Abyss-W4tcher/"
    "volatility3-symbols/master/banners/banners_plain.json"
)
ABYSS_RAW_BASE = (
    "https://github.com/Abyss-W4tcher/volatility3-symbols/raw/master"
)

# Alternate hosts for the same repo. Used as automatic fallbacks if the
# primary URL above is unreachable (rate-limited, repo moved, GitHub outage).
# Tried in order until one responds with HTTP 200.
BANNERS_INDEX_URL_MIRRORS = [
    BANNERS_INDEX_URL,
    # cdn.jsdelivr.net serves GitHub repos with global caching; useful when
    # raw.githubusercontent.com is rate-limited (60 req/hr unauthenticated).
    "https://cdn.jsdelivr.net/gh/Abyss-W4tcher/volatility3-symbols@master/"
    "banners/banners_plain.json",
    # Codeload tarball-aware mirror
    "https://raw.githubusercontent.com/Abyss-W4tcher/"
    "volatility3-symbols/main/banners/banners_plain.json",
]
ABYSS_RAW_BASE_MIRRORS = [
    ABYSS_RAW_BASE,
    "https://cdn.jsdelivr.net/gh/Abyss-W4tcher/volatility3-symbols@master",
    "https://github.com/Abyss-W4tcher/volatility3-symbols/raw/main",
]
VOL3_PATHS = [
    Path.home() / "Desktop" / "volatility3",
    Path.home() / "volatility3",
    Path("/opt/volatility3"),
    Path.home() / "tools" / "volatility3",
]

# Linux plugins to offer in the interactive menu
LINUX_PLUGINS = [
    ("linux.pslist.PsList",           "Process list"),
    ("linux.pstree.PsTree",           "Process tree"),
    ("linux.psaux.PsAux",             "Processes with arguments"),
    ("linux.psscan.PsScan",           "Process scan (finds hidden)"),
    ("linux.bash.Bash",               "Bash history"),
    ("linux.sockstat.Sockstat",       "Network sockets"),
    ("linux.sockscan.Sockscan",       "Socket scan"),
    ("linux.lsof.Lsof",              "Open files"),
    ("linux.lsmod.Lsmod",            "Loaded kernel modules"),
    ("linux.envars.Envars",           "Environment variables"),
    ("linux.malfind.Malfind",         "Injected code / malfind"),
    ("linux.check_syscall.Check_syscall",   "Syscall table hooks"),
    ("linux.check_modules.Check_modules",   "Hidden kernel modules"),
    ("linux.check_idt.Check_idt",     "IDT hooks"),
    ("linux.check_afinfo.Check_afinfo",     "Network structure hooks"),
    ("linux.keyboard_notifiers.Keyboard_notifiers", "Keyboard notifiers"),
    ("linux.proc.Maps",               "Process memory maps"),
    ("linux.elfs.Elfs",              "ELF files in memory"),
    ("linux.mountinfo.MountInfo",     "Mount points"),
    ("linux.kmsg.Kmsg",              "Kernel messages (dmesg)"),
    ("linux.lsof.Lsof",              "Open file handles"),
    ("linux.library_list.LibraryList","Loaded shared libraries"),
    ("linux.capabilities.Capabilities","Process capabilities"),
]

# Colour helpers (mirrors toolkit ui.py style without importing it)
try:
    from utils.ui import G, Y, R, C, W, N, B, P, msg_ok, msg_warn, msg_fail, msg_info
except ImportError:
    G = Y = R = C = W = N = B = P = ""
    def msg_ok(m):   print(f"  [+] {m}")
    def msg_warn(m): print(f"  [!] {m}")
    def msg_fail(m): print(f"  [x] {m}")
    def msg_info(m): print(f"  [-] {m}")


# ══════════════════════════════════════════════════════════════════════════════
# Internal helpers
# ══════════════════════════════════════════════════════════════════════════════

def _find_vol3() -> Optional[Path]:
    for p in VOL3_PATHS:
        if (p / "vol.py").exists():
            return p
    return None


def _vol3_symbols_dir(vol3: Path, os_type: str = "linux") -> Path:
    sub = "mac" if os_type == "mac" else "linux"
    d = vol3 / "volatility3" / "symbols" / sub
    d.mkdir(parents=True, exist_ok=True)
    return d


def _symbols_already_work(vol3: Path, image: str, os_type: str = "linux") -> bool:
    """Return True if Vol3 has working symbols for this image.

    Uses a plugin that REQUIRES symbols (pslist) — banners.Banners succeeds
    even without any ISF installed and would always return True here.

    NOTE: stdout/stderr are redirected to temp files on disk (not pipes) to
    avoid the 64 KB pipe-buffer deadlock that happens when Vol3 emits hundreds
    of KB of progress output while we block in subprocess.run().
    """
    plugin = "mac.pslist.PsList" if os_type == "mac" else "linux.pslist.PsList"
    try:
        with tempfile.TemporaryFile() as out_f, tempfile.TemporaryFile() as err_f:
            r = subprocess.run(
                ["python3", str(vol3 / "vol.py"), "-f", image, plugin],
                stdout=out_f, stderr=err_f, timeout=120
            )
            err_f.seek(0)
            # Read only the first 32 KB — enough to catch error messages without
            # buffering the entire progress stream.
            err_txt = err_f.read(32768).decode("utf-8", errors="ignore")
            if r.returncode == 0 and "Unsatisfied requirement" not in err_txt:
                return True
            return False
    except subprocess.TimeoutExpired:
        # Timeout means Vol3 is actually processing data (symbols work, just slow).
        return True
    except Exception:
        return False


def _detect_kernel_via_vol3(vol3: Path, image: str) -> Tuple[Optional[str], Optional[str]]:
    """Use Vol3's banners.Banners plugin to extract the kernel banner.

    This is the preferred method — it understands the image format (VMware,
    LiME, raw) and uses its own scanner, so it always finds the banner
    regardless of physical offset.
    """
    try:
        with tempfile.TemporaryFile() as out_f, tempfile.TemporaryFile() as err_f:
            r = subprocess.run(
                ["python3", str(vol3 / "vol.py"), "-q",
                 "-f", image, "banners.Banners"],
                stdout=out_f, stderr=err_f, timeout=360
            )
            out_f.seek(0)
            output = out_f.read().decode("utf-8", errors="ignore")
        for line in output.splitlines():
            # Output format: <offset>\t<banner>  (2 columns, no image prefix)
            parts = line.split("\t", 1)
            banner = parts[-1].strip()
            m_linux = re.search(r'Linux version (\S+)', banner)
            if m_linux:
                return m_linux.group(1), banner
            m_darwin = re.search(r'Darwin Kernel Version (\S+)', banner)
            if m_darwin:
                return m_darwin.group(1).rstrip(":"), banner
    except (subprocess.TimeoutExpired, Exception):
        pass
    return None, None


def _detect_kernel(image: str, os_type: str = "linux",
                   vol3: Optional[Path] = None) -> Tuple[Optional[str], Optional[str]]:
    """Detect kernel version + banner.

    Strategy (in order):
      1. Vol3 banners.Banners plugin — format-aware, finds banner at any offset.
      2. dd|strings probe — 200 MB chunks at offsets covering the whole image.
         Probes every 400 MB so no region is missed even in a 4 GB file.
    """
    # --- Method 1: Vol3 banners.Banners (preferred) ---
    if vol3 is None:
        vol3 = _find_vol3()
    if vol3:
        ver, banner = _detect_kernel_via_vol3(vol3, image)
        if ver:
            return ver, banner
        msg_warn("banners.Banners found no kernel banner — falling back to strings scan")

    # --- Method 2: dd | strings chunk scan ---
    if not shutil.which("strings"):
        msg_warn("'strings' not found — install binutils")
        return None, None

    image_path = Path(image)
    if not image_path.exists():
        return None, None

    image_size_mb = image_path.stat().st_size // (1024 * 1024)

    def _scan_chunk(skip_mb: int, count_mb: int) -> Tuple[Optional[str], Optional[str]]:
        try:
            dd = subprocess.Popen(
                ["dd", f"if={image}", "bs=1M",
                 f"skip={skip_mb}", f"count={count_mb}"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
            )
            strings_proc = subprocess.Popen(
                ["strings"],
                stdin=dd.stdout, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
            )
            dd.stdout.close()
            out, _ = strings_proc.communicate(timeout=60)
            dd.wait()
            for line in out.decode("utf-8", errors="ignore").splitlines():
                if os_type == "mac":
                    if "Darwin Kernel Version" in line:
                        m = re.search(r'Darwin Kernel Version (\S+)', line)
                        if m:
                            return m.group(1).rstrip(":"), line.strip()
                else:
                    if "Linux version" in line and ("gcc" in line or "SMP" in line):
                        m = re.search(r'Linux version (\S+)', line)
                        if m:
                            return m.group(1), line.strip()
        except (subprocess.TimeoutExpired, Exception):
            pass
        return None, None

    # Probe every 200 MB with 200 MB chunks — no byte is ever skipped.
    chunk_mb = 200
    step_mb = 200
    skip = 0
    while skip < image_size_mb:
        actual_count = min(chunk_mb, image_size_mb - skip)
        ver, banner = _scan_chunk(skip, actual_count)
        if ver:
            return ver, banner
        skip += step_mb

    msg_warn("Could not find kernel banner in image")
    return None, None


def _detect_arch_from_banner(banner: str) -> str:
    """Detect CPU architecture from a kernel banner string.

    Returns one of: 'x64', 'x86', 'arm64', 'arm', 'unknown'.
    Checks both explicit arch tokens and Ubuntu/Debian build-host naming
    conventions (e.g. 'buildd@lcy01-amd64-024' → x64).
    """
    b = banner.lower()
    # 64-bit x86 indicators
    if "x86_64" in b or "amd64" in b:
        return "x64"
    # 32-bit x86 indicators
    if "i386" in b or "i686" in b or "i486" in b:
        return "x86"
    # ARM 64-bit
    if "aarch64" in b or "arm64" in b:
        return "arm64"
    # ARM 32-bit
    if "armv7" in b or "armv6" in b:
        return "arm"
    return "unknown"


def _remove_wrong_arch_isf(vol3: Path, kernel_ver: str, correct_arch: str,
                            os_type: str = "linux") -> None:
    """Delete any installed ISF for this kernel whose filename implies the wrong arch.

    This prevents _symbols_already_work() from remaining False due to a
    stale wrong-architecture ISF that confuses Vol3's layer detection.
    """
    # Use precise filename suffixes — avoids false positives like "x86_64" matching "_x86"
    wrong_keywords = {
        "x64":   ["_i386.", "_i686.", "_i386_"],
        "x86":   ["_amd64.", "_x86_64.", "_x64.", "_arm64.", "_aarch64."],
        "arm64": ["_i386.", "_i686.", "_amd64.", "_x86_64.", "_x64."],
        "arm":   ["_i386.", "_amd64.", "_x86_64.", "_x64.", "_arm64.", "_aarch64."],
    }.get(correct_arch, [])

    sym_dir = _vol3_symbols_dir(vol3, os_type)
    removed = []
    for isf in sym_dir.glob("*.json*"):
        name_l = isf.name.lower()
        if kernel_ver.split("-")[0] in name_l:  # same base kernel version
            if any(kw in name_l for kw in wrong_keywords):
                try:
                    isf.unlink()
                    removed.append(isf.name)
                except Exception:
                    pass
    if removed:
        msg_info(f"Removed wrong-arch ISF(s): {', '.join(removed)}")


def _download_banners_index() -> Optional[dict]:
    msg_info("Downloading banners index from Abyss-W4tcher repo (3 MB)...")
    last_err = None
    for url in BANNERS_INDEX_URL_MIRRORS:
        try:
            req = urllib.request.urlopen(url, timeout=30)
            data = json.loads(req.read().decode("utf-8"))
            if url != BANNERS_INDEX_URL_MIRRORS[0]:
                msg_info(f"  (used mirror: {url.split('/')[2]})")
            return data
        except Exception as e:
            last_err = e
            msg_warn(f"  Mirror {url.split('/')[2]} failed: {e}")
            continue
    msg_warn(f"All banner-index mirrors failed; last error: {last_err}")
    return None


def _find_isf(banners: dict, full_banner: str, kernel_ver: str,
              arch: str = "unknown") -> Optional[str]:
    """Return the repo-relative ISF path that best matches this kernel + arch.

    Selection order:
    1. Exact banner match (the banner string is unique per build).
    2. ISF-path architecture match on kernel version candidates — the ISF
       path (e.g. 'Ubuntu/amd64/...') is the authoritative source of arch
       info; the banner KEY is NOT reliable because i386 kernels are often
       built on amd64 machines, so "amd64" can appear in the banner of an
       i386 ISF.
    3. Any partial match (fallback when arch is unknown).
    """
    # 1 — exact banner match
    if full_banner in banners:
        paths = banners[full_banner]
        return paths[0] if isinstance(paths, list) else paths

    # Collect all candidates whose key contains the kernel version
    candidates = []
    for key, paths in banners.items():
        if kernel_ver in key:
            isf = paths[0] if isinstance(paths, list) else paths
            candidates.append((key, isf))

    if not candidates:
        return None

    if len(candidates) == 1:
        msg_warn(f"Partial match: {candidates[0][0][:80]}")
        return candidates[0][1]

    # Map our arch labels to keywords found in the ISF PATH (not banner key)
    isf_arch_positive = {
        "x64":   ["amd64", "x86_64", "_x64"],
        "x86":   ["/i386/", "_i386", "/i686/", "_i686"],
        "arm64": ["aarch64", "arm64"],
        "arm":   ["armv7", "armv6", "/arm/"],
    }
    isf_arch_negative = {
        "x64":   ["/i386/", "_i386", "/i686/", "_i686", "aarch64", "_arm"],
        "x86":   ["amd64", "x86_64", "_x64", "aarch64", "arm64"],
        "arm64": ["/i386/", "_i386", "amd64", "x86_64"],
        "arm":   ["/i386/", "amd64", "x86_64", "aarch64", "arm64"],
    }

    # 2 — architecture match on ISF path (authoritative — banner key is unreliable)
    pos_kws = isf_arch_positive.get(arch, [])
    neg_kws = isf_arch_negative.get(arch, [])
    if pos_kws:
        for key, isf in candidates:
            isf_l = isf.lower()
            has_pos = any(kw in isf_l for kw in pos_kws)
            has_neg = any(kw in isf_l for kw in neg_kws)
            if has_pos and not has_neg:
                msg_info(f"ISF arch match ({arch}): {isf}")
                return isf
        # Looser: positive without negative check
        for key, isf in candidates:
            isf_l = isf.lower()
            if any(kw in isf_l for kw in pos_kws):
                msg_warn(f"ISF arch partial match ({arch}): {isf}")
                return isf

    # 3 — fallback: return first candidate
    msg_warn(f"Partial match (no arch filter): {candidates[0][0][:80]}")
    return candidates[0][1]


def _download_isf(isf_rel: str, dest_dir: Path) -> Optional[Path]:
    dest = dest_dir / Path(isf_rel).name
    msg_info(f"Downloading: {Path(isf_rel).name}")

    def progress(count, block, total):
        if total > 0:
            pct = min(int(count * block * 100 / total), 100)
            print(f"\r  [-] Progress: {pct}%", end="", flush=True)

    last_err = None
    for base in ABYSS_RAW_BASE_MIRRORS:
        url = f"{base}/{isf_rel}"
        try:
            urllib.request.urlretrieve(url, str(dest), reporthook=progress)
            print()
            size_mb = dest.stat().st_size / 1024 / 1024
            host = url.split("/")[2]
            if base != ABYSS_RAW_BASE_MIRRORS[0]:
                msg_ok(f"Downloaded {dest.name} ({size_mb:.1f} MB) via mirror {host}")
            else:
                msg_ok(f"Downloaded {dest.name} ({size_mb:.1f} MB)")
            return dest
        except Exception as e:
            last_err = e
            print()
            msg_warn(f"  Mirror {url.split('/')[2]} failed: {e}")
            # Clean up partial file if any
            try:
                if dest.exists():
                    dest.unlink()
            except Exception:
                pass
            continue
    msg_fail(f"All ISF mirrors failed; last error: {last_err}")
    return None


def _patch_isf_banner(isf: Path, actual_banner: str, dest_dir: Path) -> Optional[Path]:
    """Rewrite the linux_banner constant in an ISF to match the actual image banner.

    When Vol3 scans an image it finds the exact banner string, then looks it up
    in a dict of {banner_bytes → isf_path}.  If the ISF was built from a kernel
    with the same source but a different build host (e.g. Debian vs Kali), the
    banner won't match.  This patches the ISF in-place so Vol3 can find it.

    Returns the path to the patched ISF, or None on failure.
    """
    import base64
    import lzma

    try:
        with lzma.open(str(isf)) as f:
            data = json.loads(f.read())
    except Exception as e:
        msg_warn(f"Cannot read ISF for patching: {e}")
        return None

    syms = data.get("symbols", {})
    lb = syms.get("linux_banner", {})
    if not lb:
        msg_warn("ISF has no linux_banner symbol — skipping banner patch")
        return None

    old_b64 = lb.get("constant_data", "")
    try:
        old_banner = base64.b64decode(old_b64).decode("utf-8", errors="replace").strip()
    except Exception:
        old_banner = ""

    if old_banner == actual_banner.strip():
        msg_info("ISF banner already matches — no patch needed")
        return isf  # no change needed

    # Encode the actual banner with a trailing newline (kernel adds \0 which
    # becomes \n when decoded as text — keep consistent with kernel behaviour)
    new_bytes = (actual_banner.strip() + "\n").encode("utf-8")
    lb["constant_data"] = base64.b64encode(new_bytes).decode("ascii")
    syms["linux_banner"] = lb
    data["symbols"] = syms

    # Write patched ISF with a name that makes the Kali/custom origin clear
    base_stem = isf.stem.replace(".json", "")  # strip inner .json if present
    patched_name = f"{base_stem}_patched.json.xz"
    patched_path = dest_dir / patched_name
    try:
        with lzma.open(str(patched_path), "wt", encoding="utf-8") as f:
            json.dump(data, f)
        size_mb = patched_path.stat().st_size / 1024 / 1024
        msg_ok(f"Banner patched: {old_banner[:60]!r} → {actual_banner[:60]!r}")
        msg_ok(f"Patched ISF: {patched_name} ({size_mb:.1f} MB)")
        return patched_path
    except Exception as e:
        msg_fail(f"Failed to write patched ISF: {e}")
        return None


def _install_isf(isf: Path, vol3: Path, os_type: str = "linux") -> bool:
    dest = _vol3_symbols_dir(vol3, os_type) / isf.name
    try:
        shutil.copy2(str(isf), str(dest))
        msg_ok(f"Installed → {dest}")
        return True
    except Exception as e:
        msg_fail(f"Install failed: {e}")
        return False


def _try_local_isf_build(image: str, kernel_ver: str, vol3: Path,
                          os_type: str = "linux") -> bool:
    """Try to build an ISF from local dwarf/System.map files near the image.

    Looks for a directory alongside the image that contains:
      - module.dwarf  (DWARF type info from linux-image-*-dbgsym package)
      - boot/System.map-<kernel>  (exported kernel symbols)

    Requires 'dwarf2json' to be on PATH.  Returns True if the ISF was
    successfully built and installed.
    """
    if not shutil.which("dwarf2json"):
        return False

    image_dir = Path(image).parent
    # Search for a ddeb/dwarf source dir alongside the image
    candidates = list(image_dir.glob("*/module.dwarf")) + \
                 list(image_dir.glob("module.dwarf"))

    for dwarf_file in candidates:
        source_dir = dwarf_file.parent
        # Look for a System.map that matches the kernel version
        sysmap = None
        for sm in source_dir.rglob(f"System.map-{kernel_ver}"):
            sysmap = sm
            break
        if not sysmap:
            for sm in source_dir.rglob("System.map*"):
                sysmap = sm
                break

        msg_info(f"Found local DWARF source: {source_dir.name}")
        if sysmap:
            msg_info(f"System.map: {sysmap.name}")

        out_name = f"local_{kernel_ver}_x64.json"
        out_path = Path(tempfile.mkdtemp(prefix="rambreaker_isf_")) / out_name

        cmd = ["dwarf2json", "linux", "--dwarf", str(dwarf_file)]
        if sysmap:
            cmd += ["--system-map", str(sysmap)]

        try:
            msg_info("Building ISF with dwarf2json (this may take a few minutes)...")
            result = subprocess.run(
                cmd, capture_output=True, timeout=300
            )
            if result.returncode == 0 and result.stdout:
                out_path.write_bytes(result.stdout)
                size_mb = out_path.stat().st_size / 1024 / 1024
                msg_ok(f"ISF built ({size_mb:.1f} MB)")
                ok = _install_isf(out_path, vol3, os_type)
                out_path.unlink(missing_ok=True)
                return ok
            else:
                msg_warn(f"dwarf2json failed: {result.stderr[:200].decode(errors='ignore')}")
        except subprocess.TimeoutExpired:
            msg_warn("dwarf2json timed out")
        except Exception as exc:
            msg_warn(f"dwarf2json error: {exc}")

    return False


def _run_plugin(vol3: Path, image: str, plugin: str, output_dir: Optional[Path] = None):
    """Run a single Vol3 Linux plugin and print output."""
    cmd = ["python3", str(vol3 / "vol.py"), "-f", image, plugin]
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)
        safe  = plugin.replace(".", "_")
        outf  = output_dir / f"{safe}.txt"
        cmd  += ["--output-dir", str(output_dir)]
    print()
    print(f"  {'─' * 62}")
    print(f"  Running: {plugin}")
    print(f"  {'─' * 62}")
    try:
        proc = subprocess.run(cmd, text=True, timeout=300)
        if output_dir:
            msg_ok(f"Saved → {outf}")
    except subprocess.TimeoutExpired:
        msg_warn(f"{plugin} timed out (>5 min)")
    except KeyboardInterrupt:
        print()
        msg_warn("Interrupted")


# ══════════════════════════════════════════════════════════════════════════════
# Symbol resolution — main function called by toolkit
# ══════════════════════════════════════════════════════════════════════════════

def resolve_symbols(image: str, os_type: str = "linux",
                    output_dir: Optional[Path] = None) -> bool:
    """
    Attempt to auto-resolve Vol3 symbols (Linux or macOS) for this image.
    Returns True if symbols are now working, False otherwise.

    Resolution order:
      1. Check if symbols already work (correct arch ISF already installed).
      2. Detect kernel version + architecture from the image.
      3. Remove any stale wrong-architecture ISF that would block Vol3.
      4. Download the matching ISF from Abyss-W4tcher/volatility3-symbols.
      5. Fall back to building from local DWARF files (if dwarf2json available).

    If output_dir is provided, writes json/linux_kernel.json with the detected
    kernel version so downstream tools (system_info, HTML report) can read it.
    """
    vol3 = _find_vol3()
    if not vol3:
        msg_fail("Volatility 3 not found — cannot resolve symbols")
        return False

    os_label = "macOS" if os_type == "mac" else "Linux"

    # Detect kernel version + architecture from the image
    msg_info(f"Detecting {os_label} kernel version from image...")
    kernel_ver, full_banner = _detect_kernel(image, os_type, vol3=vol3)
    if kernel_ver:
        msg_ok(f"Kernel: {kernel_ver}")

    arch = _detect_arch_from_banner(full_banner or "")
    if arch != "unknown":
        msg_info(f"Architecture: {arch}")

    # Persist kernel version for system_info / HTML report
    if output_dir and kernel_ver:
        try:
            jd = Path(output_dir) / "json"
            jd.mkdir(parents=True, exist_ok=True)
            (jd / "linux_kernel.json").write_text(
                json.dumps({"kernel_version": kernel_ver,
                            "banner": full_banner or "",
                            "os_type": os_type,
                            "arch": arch}, indent=2),
                encoding="utf-8")
        except Exception:
            pass

    # Remove any wrong-architecture ISF for this kernel before testing
    if kernel_ver and arch != "unknown":
        _remove_wrong_arch_isf(vol3, kernel_ver, arch, os_type)

    # Already working? Skip download.
    if _symbols_already_work(vol3, image, os_type):
        msg_ok("Symbols already working for this image")
        return True

    if not kernel_ver:
        msg_fail("Could not detect kernel version from image")
        return False

    if os_type == "mac":
        msg_warn("Note: macOS symbols >11.0 in the community repo may be incomplete")

    # --- Attempt 1: download from community repo ---
    msg_info("Downloading symbols from github.com/Abyss-W4tcher/volatility3-symbols...")

    banners = _download_banners_index()
    if banners:
        isf_rel = _find_isf(banners, full_banner or "", kernel_ver, arch)
        if isf_rel:
            msg_ok(f"Found in repo: {isf_rel}")
            tmp = Path(tempfile.mkdtemp(prefix="rambreaker_sym_"))
            isf_file = _download_isf(isf_rel, tmp)
            if isf_file:
                ok = _install_isf(isf_file, vol3, os_type)
                if ok and _symbols_already_work(vol3, image, os_type):
                    shutil.rmtree(str(tmp), ignore_errors=True)
                    msg_ok("Symbol verification passed!")
                    return True
                if ok and full_banner:
                    # Verification failed — likely a build-host mismatch (e.g. Debian
                    # ISF used for a Kali kernel with same source but different banner).
                    # Patch the ISF banner so Vol3 can match it to this image.
                    msg_warn("Exact banner mismatch — attempting banner patch...")
                    sym_dir = _vol3_symbols_dir(vol3, os_type)
                    installed = sym_dir / isf_file.name
                    patched = _patch_isf_banner(installed, full_banner, sym_dir)
                    if patched and _symbols_already_work(vol3, image, os_type):
                        shutil.rmtree(str(tmp), ignore_errors=True)
                        msg_ok("Symbol verification passed (banner-patched ISF)!")
                        return True
                    if patched:
                        msg_warn("Banner-patched ISF installed but verification failed")
                shutil.rmtree(str(tmp), ignore_errors=True)
                if ok:
                    msg_warn("ISF installed but verification failed — trying local build fallback")
            else:
                shutil.rmtree(str(tmp), ignore_errors=True)
        else:
            msg_warn(f"Kernel {kernel_ver} ({arch}) not found in Abyss-W4tcher repo")
    else:
        msg_warn("Could not reach Abyss-W4tcher repo — trying local build fallback")

    # --- Attempt 2: build from local DWARF files (if dwarf2json available) ---
    if os_type != "mac":
        msg_info("Trying local DWARF symbol build...")
        if _try_local_isf_build(image, kernel_ver, vol3, os_type):
            if _symbols_already_work(vol3, image, os_type):
                msg_ok("Symbol verification passed (local build)!")
                return True
            msg_warn("Local ISF installed but verification still failed")
        else:
            msg_info("Local DWARF build skipped (dwarf2json not found or no source files)")

    # --- All attempts failed ---
    if os_type != "mac":
        _print_manual_steps(kernel_ver, full_banner or "", arch)
    else:
        msg_info("For macOS, generate KDK symbols manually — see:")
        msg_info("  https://volatility3.readthedocs.io/en/latest/symbol-tables.html")
    return False


def _print_manual_steps(kernel_ver: str, banner: str, arch: str = "x64"):
    """Print ddeb download and build instructions when all auto-resolution fails."""
    m = re.match(r'(\d+\.\d+\.\d+)-(\d+)', kernel_ver)
    if not m:
        return
    base  = m.group(1)
    major = ".".join(base.split(".")[:2])
    deb_arch = "amd64" if arch == "x64" else arch

    print()
    print(f"  {'─' * 62}")
    print(f"  MANUAL SYMBOL BUILD REQUIRED")
    print(f"  {'─' * 62}")
    msg_info("Kernel not in community repo — build from ddeb package:")
    print()
    print(f"  1. Browse the pool:")
    print(f"     http://ddebs.ubuntu.com/pool/main/l/linux-hwe-{major}/")
    print(f"     http://ddebs.ubuntu.com/pool/main/l/linux/")
    print()
    print(f"  2. Download: linux-image-unsigned-{kernel_ver}-dbgsym_*_{deb_arch}.ddeb")
    print()
    print(f"  3. Build symbols:")
    print(f"     python3 rambreaker_linux_auto.py --build <file.ddeb> --image <image>")
    print()
