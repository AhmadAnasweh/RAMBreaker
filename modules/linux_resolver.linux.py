#!/usr/bin/env python3
"""
CresCent v6.0 — Linux symbol resolver
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

from modules import linux_identify

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
    # Progress-aware run: a wrong/absent ISF makes pslist exit fast (either
    # "Unsatisfied requirement" or rc 0 with an empty table), while a correct ISF
    # on a slow box / huge image legitimately takes minutes (cache build + scan).
    # The old fixed 120 s timeout couldn't tell those apart and aborted valid
    # runs; waiting on real progress does. A genuine hang is still caught by the
    # runner's stall detector.
    cmd = ["python3", str(vol3 / "vol.py"), "-q", "-f", image, plugin]
    rc, out_txt, err_txt = linux_identify.run_vol_until_done(cmd)
    if rc != 0 or "Unsatisfied requirement" in err_txt:
        return False
    # A zero exit code is NOT enough: with the wrong/absent ISF pslist can still
    # exit 0 while walking zero processes. Require actual rows — any process table
    # has a header (no digits) plus many digit-bearing rows (PID/PPID columns).
    data_rows = [ln for ln in out_txt.splitlines()
                 if ln.strip() and any(c.isdigit() for c in ln)]
    if len(data_rows) >= 2:
        return True
    # pslist found nothing. That can mean a bad ISF — OR a correct ISF on a VMware
    # .vmem saved without its .vmss/.vmsn companion, where Vol3 maps memory flat
    # and the init_task linked-list walk can't translate addresses. Confirm with a
    # scan-based plugin before declaring the symbols broken.
    return _scan_finds_processes(vol3, image, os_type)


def _scan_finds_processes(vol3: Path, image: str, os_type: str = "linux") -> bool:
    """Scan-based confirmation that the ISF works when the list-walk plugin is empty.

    linux.pslist/pstree/psaux walk the init_task linked list through the kernel's
    virtual->physical page tables. A VMware .vmem captured WITHOUT its companion
    .vmss/.vmsn makes Vol3 map memory flat, so that translation is wrong and the
    walk yields nothing even though the ISF is correct. linux.psscan signature-
    scans physical memory directly (no page-table walk) and still finds
    task_structs — proving the ISF is right. macOS has no equivalent scan plugin,
    so this applies to Linux only.
    """
    if os_type == "mac":
        return False
    cmd = ["python3", str(vol3 / "vol.py"), "-q", "-f", image,
           "linux.psscan.PsScan"]
    rc, out, err = linux_identify.run_vol_until_done(cmd)
    if rc != 0 or "Unsatisfied" in err:
        return False
    rows = [ln for ln in out.splitlines()
            if ln.strip() and any(c.isdigit() for c in ln)]
    return len(rows) >= 2


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

    Requires 'dwarf2json' (PATH or the copy bundled in _isf_build/).  Returns
    True if the ISF was successfully built and installed.
    """
    try:
        from modules.dbgsym_builder import find_dwarf2json
        d2j = find_dwarf2json()
    except Exception:
        d2j = shutil.which("dwarf2json")
    if not d2j:
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

        cmd = [d2j, "linux", "--dwarf", str(dwarf_file)]
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
                if ok:
                    _refresh_isf_cache_after_install(vol3, image)
                return ok
            else:
                msg_warn(f"dwarf2json failed: {result.stderr[:200].decode(errors='ignore')}")
        except subprocess.TimeoutExpired:
            msg_warn("dwarf2json timed out")
        except Exception as exc:
            msg_warn(f"dwarf2json error: {exc}")

    return False


def _distro_from_banner(banner: str) -> str:
    """Best-effort distro label from a Linux kernel banner string.

    Mint/Ubuntu kernels carry '(Ubuntu ...)' in the banner; Debian carries
    '(Debian ...)'; Kali carries 'kali'. The dbgsym download pipeline is served
    by ddebs.ubuntu.com / the Ubuntu primary archive, so anything Ubuntu-family
    resolves; others are attempted best-effort (Ubuntu path) and usually no-op.
    """
    b = (banner or "").lower()
    if "kali" in b:
        return "Kali"
    if "debian" in b:
        return "Debian"
    # RHEL family (CentOS/RHEL/Fedora/Alma/Rocky) — kernel release carries .elN /
    # .fcN. Their debug symbols ship as debuginfo RPMs (vault/koji), NOT ddebs, so
    # the ddebs pipeline cannot serve them.
    if re.search(r'\.el\d|\.fc\d|red hat|centos|almalinux|rocky', b):
        return "RHEL"
    if "suse" in b:
        return "SUSE"
    # Ubuntu covers Mint / Pop!_OS / Elementary / stock Ubuntu (all Ubuntu-based)
    return "Ubuntu"


def _refresh_isf_cache_after_install(vol3: Path, image: str) -> None:
    """After installing a freshly-built ISF, register it in Vol3's identifier
    cache so automagic can match it. Without this the just-added ISF is absent
    from the committed cache and pslist verification fails with 'Unsatisfied
    requirement' even though the ISF is correct on disk.

    Fast path (#1): Vol3's own incremental `SqliteCache.update()` — processes
    ONLY the new file (~1 s). This avoids the double full re-index (#3): we no
    longer clear the whole cache (which turned all ~3000 store files back into
    "new" and cost minutes). Falls back to the clear+rewarm sledgehammer only if
    the incremental update fails, so correctness is never sacrificed for speed."""
    try:
        if linux_identify.add_new_isf_to_cache(vol3):
            return
        msg_warn("Incremental cache update unavailable — falling back to full "
                 "cache rebuild (slower).")
        linux_identify.clear_isf_cache()
        linux_identify.warm_isf_cache(f"python3 {vol3 / 'vol.py'}", image,
                                      force=True)
    except Exception as exc:
        msg_warn(f"ISF cache refresh failed (non-fatal): {exc}")


def _try_dbgsym_download_build(image: str, kernel_ver: str, banner: str,
                              arch: str, vol3: Path,
                              os_type: str = "linux") -> bool:
    """Download the kernel's OFFICIAL debug package and build+install an ISF.

    Last-resort automatic path used when (a) no prebuilt ISF exists in the
    community repo and (b) no local DWARF source sits alongside the image:
    fetch the -dbgsym .ddeb from the distro's official archive
    (ddebs.ubuntu.com / Launchpad), extract vmlinux, run dwarf2json, and install
    the ISF into the Vol3 symbol store. Ubuntu-family only; a miss (e.g. a kernel
    whose dbgsym was pruned upstream) returns False so the caller can continue
    with reduced, symbol-independent results.
    """
    if os_type == "mac":
        return False
    try:
        from modules import dbgsym_builder
        from modules import workspace
    except Exception as exc:
        msg_warn(f"dbgsym builder unavailable: {exc}")
        return False
    if not dbgsym_builder.find_dwarf2json():
        msg_info("dwarf2json not available — skipping debug-package ISF build")
        return False

    distro = _distro_from_banner(banner)
    workspace.setup()  # ensure scratch/ddeb cache on the big disk, not /tmp

    # RHEL family (CentOS/RHEL/Alma/Rocky/Fedora): debug symbols are debuginfo
    # RPMs from debuginfo.centos.org / Alma / Rocky / koji — build via that path.
    if distro == "RHEL":
        rpm_arch = dbgsym_builder.rhel_rpm_arch(arch or "x86_64")
        msg_info(f"No prebuilt ISF — fetching RHEL/CentOS debuginfo RPM for "
                 f"kernel {kernel_ver} ({rpm_arch}) and building the ISF locally "
                 "(downloads a few hundred MB)...")
        try:
            isf = dbgsym_builder.build_isf_from_rhel_debuginfo(
                kernel_ver, arch=rpm_arch, install=True, distro="CentOS",
                keep_rpm=workspace.DDEB_CACHE_DIR,
                dest_dir=workspace.ISF_BUILD_DIR)
        except Exception as exc:
            msg_warn(f"RHEL debuginfo ISF build failed: {exc}")
            return False
        if isf:
            msg_ok(f"Built & installed ISF from RHEL debuginfo RPM: "
                   f"{Path(isf).name}")
            _refresh_isf_cache_after_install(vol3, image)
            return True
        msg_warn("Could not obtain/build an ISF from RHEL debuginfo "
                 "(the debuginfo RPM may be unavailable for this build).")
        return False

    if distro == "SUSE":
        msg_warn("SUSE debug symbols are not auto-buildable here — "
                 "continuing with reduced, symbol-independent results.")
        return False

    # Debian-family (.deb): ddebs.ubuntu.com / Launchpad.
    deb_arch = dbgsym_builder.normalize_arch(arch or "x64")
    msg_info(f"No prebuilt ISF found — fetching {distro} debug package for "
             f"kernel {kernel_ver} ({deb_arch}) and building the ISF locally "
             "(this downloads ~1 GB and can take several minutes)...")
    try:
        isf = dbgsym_builder.build_isf_from_dbgsym(
            kernel_ver, arch=deb_arch, install=True, distro=distro,
            keep_ddeb=workspace.DDEB_CACHE_DIR,
            dest_dir=workspace.ISF_BUILD_DIR)
    except Exception as exc:
        msg_warn(f"Debug-package ISF build failed: {exc}")
        return False
    if isf:
        msg_ok(f"Built & installed ISF from official debug package: "
               f"{Path(isf).name}")
        _refresh_isf_cache_after_install(vol3, image)
        return True
    msg_warn("Could not obtain/build an ISF from the debug package "
             "(the matching dbgsym may have been pruned upstream for this "
             "kernel).")
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

def _scan_all_banners(image: str, os_type: str = "linux",
                      max_distinct: int = 200) -> list:
    """Stream `strings` over the image and collect kernel banners.

    A RAM dump contains many stale 'Linux version ...' strings (apt package
    indexes, docs, container images) in addition to the running kernel's banner.
    We must collect them ALL and let verification decide which is real — picking
    the first by byte offset (the old behaviour) reliably grabs the wrong one.

    Stops early once `max_distinct` banners are seen: that many already means the
    image is a banner cache where content heuristics can't help, so there's no
    point scanning the rest of a multi-GB file.

    Returns a list of (version, banner) in first-seen (offset) order, de-duped.
    """
    import re as _re
    if not shutil.which("strings"):
        return []
    # Strict genuine-boot-banner shapes only — drops source-code fragments and
    # partial strings, keeping real banners like:
    #   Linux version X (builder@host) (gcc ...) #N SMP/PREEMPT ... date
    linux_strict = _re.compile(
        r'^Linux version (\S+) \(.+@.+\).*#\d+.*(SMP|PREEMPT)')
    seen = {}  # banner -> version (dict preserves offset order, de-dupes)
    try:
        proc = subprocess.Popen(
            ["strings", "-n", "12", image],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, errors="ignore")
        for line in proc.stdout:
            line = line.strip()
            if os_type == "mac":
                if "Darwin Kernel Version" in line:
                    m = _re.search(r'Darwin Kernel Version (\S+)', line)
                    if m:
                        seen.setdefault(line, m.group(1).rstrip(":"))
            else:
                m = linux_strict.match(line)
                if m:
                    seen.setdefault(line, m.group(1))
            if len(seen) >= max_distinct:
                break
        try:
            proc.stdout.close()
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            pass
    except Exception:
        pass
    return [(v, b) for b, v in seen.items()]


def _rank_banner_candidates(cands: list) -> list:
    """Order candidates so the real running kernel is tried first.

    Heuristic: stale banners from apt 'Packages' indexes appear as a big cluster
    of many builds sharing the same major.minor (e.g. 20+ Ubuntu 4.15.0-* in a
    row). The running kernel is usually NOT part of such a cluster, so we sort by
    ascending same-major cluster size. Verification is still ground truth — this
    only minimises how many ISFs we download before the right one validates.
    """
    import re as _re
    from collections import Counter

    def majmin(ver: str) -> str:
        m = _re.match(r'(\d+\.\d+)', ver)
        return m.group(1) if m else ver

    cluster = Counter(majmin(v) for v, _ in cands)
    # Stable sort keeps offset order within equal cluster sizes.
    return sorted(cands, key=lambda vb: cluster[majmin(vb[0])])


def _verify_works_strict(vol3: Path, image: str, os_type: str = "linux",
                         timeout: int = 240) -> bool:
    """Strict symbol check: pslist must succeed AND list real processes.

    Unlike _symbols_already_work (which treats a timeout as success to avoid
    aborting a genuinely-slow run), this is used to DISCRIMINATE between
    candidate ISFs, so it must only return True on a confirmed match:
      - rc == 0, no 'Unsatisfied requirement', and at least one data row.
    A timeout returns False (we cannot confirm this candidate matched).
    """
    plugin = "mac.pslist.PsList" if os_type == "mac" else "linux.pslist.PsList"
    # `timeout` is kept for signature compatibility but is no longer a hard cap:
    # we wait on real progress so a genuinely-slow-but-valid candidate ISF is not
    # mistaken for a non-matching one (the failure that made a correct ISF look
    # broken on this box). A wrong ISF still fails fast (rc!=0 / empty table).
    cmd = ["python3", str(vol3 / "vol.py"), "-q", "-f", image, plugin]
    rc, out, err = linux_identify.run_vol_until_done(cmd)
    if rc != 0 or "Unsatisfied" in err:
        return False
    rows = [l for l in out.splitlines() if l.strip()]
    if len(rows) >= 2:  # header + at least one process
        return True
    # Empty list-walk but a clean run: this candidate ISF may still be the right
    # one on a metadata-less VMware .vmem. Confirm via the scan-based plugin.
    return _scan_finds_processes(vol3, image, os_type)


def _write_kernel_json(output_dir, kernel_ver, banner, os_type, arch):
    """Persist detected kernel info for system_info / HTML report."""
    if not output_dir:
        return
    try:
        jd = Path(output_dir) / "json"
        jd.mkdir(parents=True, exist_ok=True)
        (jd / "linux_kernel.json").write_text(json.dumps({
            "kernel_version": kernel_ver, "banner": banner or "",
            "os_type": os_type, "arch": arch or ""}, indent=2),
            encoding="utf-8")
    except Exception:
        pass


def _persist_kernel_if_missing(image: str, os_type: str, vol3: Optional[Path],
                               output_dir) -> None:
    """Fill json/linux_kernel.json on the 'symbols already work' fast path.

    Every OTHER exit of resolve_symbols writes this file, but the already-working
    early return skips the whole banner pipeline — so downstream consumers
    (system_info, HTML report, crash_report's target.kernel/distro) lose the
    kernel/distro. This does a best-effort recovery: only when the file is absent,
    reuse the same fast strings-based banner scan + ranking the resolver trusts
    elsewhere and persist the top candidate. Guarded + wrapped so it can never
    slow (skips when already present) or break a working run."""
    if not output_dir:
        return
    try:
        if (Path(output_dir) / "json" / "linux_kernel.json").exists():
            return
        cands = _scan_all_banners(image, os_type)
        if cands:
            kv, banner = _rank_banner_candidates(cands)[0]
        else:
            kv, banner = _detect_kernel(image, os_type, vol3=vol3)
        if kv:
            _write_kernel_json(output_dir, kv, banner, os_type,
                               _detect_arch_from_banner(banner or ""))
    except Exception:
        pass


def resolve_symbols(image: str, os_type: str = "linux",
                    output_dir: Optional[Path] = None) -> bool:
    """
    Attempt to auto-resolve Vol3 symbols (Linux or macOS) for this image.
    Returns True if symbols are now working, False otherwise.

    Resolution order:
      1. Skip if symbols already work (correct ISF already installed).
      2. Collect ALL kernel banners in the image (not just the first by offset).
      3. Rank candidates (stale apt-index clusters last) and, for each, download
         its ISF and verify it actually validates against the dump — the first
         that does is the real running kernel. This is immune to the many stale
         'Linux version' strings a RAM image contains.
      4. Fall back to a local DWARF build for the top candidate.

    If output_dir is provided, writes json/linux_kernel.json for downstream tools.
    """
    vol3 = _find_vol3()
    if not vol3:
        msg_fail("Volatility 3 not found — cannot resolve symbols")
        return False

    os_label = "macOS" if os_type == "mac" else "Linux"

    # Build Vol3's ISF identifier cache once, single-threaded, before the verify
    # probes below (each runs pslist). On the fast-detect LiME path detection
    # returns without ever touching banners, so the cache can still be cold here;
    # warming it now keeps the verify steps fast and stops the later parallel
    # plugin jobs from racing on a half-built cache.
    linux_identify.warm_isf_cache(f"python3 {vol3 / 'vol.py'}", image)

    # 0. Already working? (a correct ISF may be installed from a prior run)
    if _symbols_already_work(vol3, image, os_type):
        msg_ok("Symbols already working for this image")
        # This fast path skips the banner pipeline, so persist kernel/distro for
        # downstream tools (system_info, crash_report) if not already on disk.
        _persist_kernel_if_missing(image, os_type, vol3, output_dir)
        return True

    # 1. Collect every candidate kernel banner (fast strings scan over the whole
    #    image). banners.Banners is intentionally NOT used here — it scans the
    #    full address space and can take many minutes / time out on LiME dumps.
    msg_info(f"Scanning image for {os_label} kernel banners...")
    candidates = _scan_all_banners(image, os_type)
    if not candidates:
        # Last resort: the format-aware single-banner detector.
        kv, fb = _detect_kernel(image, os_type, vol3=vol3)
        if kv:
            candidates = [(kv, fb or "")]
    if not candidates:
        msg_fail("Could not find any kernel banner in image")
        return False

    candidates = _rank_banner_candidates(candidates)

    # An image stuffed with kernel banners (a package/banner cache or a banner
    # database in page cache) defeats every content-based heuristic — every
    # entry looks like a genuine boot banner, so we cannot tell which is the
    # RUNNING kernel without brute-forcing thousands of ISFs. Bail fast with
    # clear guidance instead of grinding through wrong downloads.
    BANNER_DB_THRESHOLD = 25
    if len(candidates) > BANNER_DB_THRESHOLD:
        msg_warn(f"Image contains {len(candidates)} distinct kernel banners "
                 "(looks like a package/banner cache).")
        msg_warn("Auto-detection cannot tell which is the running kernel here.")
        msg_info("Re-run and pick the build manually if you know it:")
        msg_info("   Settings → Known OS → Linux → type the build "
                 "(e.g. 'kali 6.12.13'),")
        msg_info("   or at the OS prompt choose Linux and enter the build name.")
        # Still attempt a local DWARF build (free if dwarf2json + sources exist).
        if os_type != "mac" and _try_local_isf_build(
                image, candidates[0][0], vol3, os_type):
            if _verify_works_strict(vol3, image, os_type):
                msg_ok("Symbol verification passed (local build)!")
                _write_kernel_json(output_dir, candidates[0][0],
                                   candidates[0][1], os_type,
                                   _detect_arch_from_banner(candidates[0][1]))
                return True
        return False

    if len(candidates) > 1:
        msg_info(f"Found {len(candidates)} distinct kernel banners — "
                 "verifying which one matches this image:")
        for v, _ in candidates[:8]:
            msg_info(f"    candidate: {v}")

    if os_type == "mac":
        msg_warn("Note: macOS symbols >11.0 in the community repo may be incomplete")

    banners_index = _download_banners_index()
    if not banners_index:
        msg_warn("Could not reach symbol repo — trying local build fallback")

    # Scale the verification timeout with image size (the banner may sit late in
    # the image, so Vol3's scan needs time to reach it).
    try:
        gb = Path(image).stat().st_size / (1024 ** 3)
        verify_to = int(min(600, max(180, gb * 120)))
    except Exception:
        verify_to = 240

    MAX_TRY = 8
    tried = 0
    for kernel_ver, full_banner in candidates:
        if tried >= MAX_TRY or not banners_index:
            break
        arch = _detect_arch_from_banner(full_banner or "")
        if kernel_ver and arch != "unknown":
            _remove_wrong_arch_isf(vol3, kernel_ver, arch, os_type)
        isf_rel = _find_isf(banners_index, full_banner or "", kernel_ver, arch)
        if not isf_rel:
            continue  # no prebuilt ISF for this candidate — skip quietly
        tried += 1
        msg_info(f"[{tried}] Trying {kernel_ver} ({arch or '?'}) — {Path(isf_rel).name}")
        tmp = Path(tempfile.mkdtemp(prefix="rambreaker_sym_"))
        isf_file = _download_isf(isf_rel, tmp)
        if not isf_file:
            shutil.rmtree(str(tmp), ignore_errors=True)
            continue
        ok = _install_isf(isf_file, vol3, os_type)
        installed = _vol3_symbols_dir(vol3, os_type) / isf_file.name
        if ok and _verify_works_strict(vol3, image, os_type, verify_to):
            shutil.rmtree(str(tmp), ignore_errors=True)
            msg_ok(f"Symbol verification passed — kernel {kernel_ver}")
            _write_kernel_json(output_dir, kernel_ver, full_banner, os_type, arch)
            return True
        # Exact match failed — try a banner patch (build-host mismatch, e.g. a
        # Debian ISF for a Kali kernel built from the same source).
        if ok and full_banner:
            patched = _patch_isf_banner(
                installed, full_banner, _vol3_symbols_dir(vol3, os_type))
            if patched and _verify_works_strict(vol3, image, os_type, verify_to):
                shutil.rmtree(str(tmp), ignore_errors=True)
                msg_ok(f"Symbol verification passed (banner-patched) — kernel {kernel_ver}")
                _write_kernel_json(output_dir, kernel_ver, full_banner, os_type, arch)
                return True
        # Didn't validate — remove this ISF so it can't confuse Vol3's automagic.
        try:
            if installed.exists():
                installed.unlink()
        except Exception:
            pass
        shutil.rmtree(str(tmp), ignore_errors=True)
        msg_warn(f"{kernel_ver} did not match this image — trying next candidate")

    # --- Fallback 1: build from local DWARF files for the top candidate ---
    top_ver, top_banner = candidates[0]
    top_arch = _detect_arch_from_banner(top_banner or "")
    if os_type != "mac":
        msg_info("Trying local DWARF symbol build...")
        if _try_local_isf_build(image, top_ver, vol3, os_type):
            if _verify_works_strict(vol3, image, os_type, verify_to):
                msg_ok("Symbol verification passed (local build)!")
                _write_kernel_json(output_dir, top_ver, top_banner, os_type, top_arch)
                return True
            msg_warn("Local ISF installed but verification still failed")
        else:
            msg_info("Local DWARF build skipped (dwarf2json not found or no source files)")

    # --- Fallback 2: download the OFFICIAL debug package & build the ISF ---
    # Try the ranked candidates (most-likely running kernel first) so a genuine
    # match wins even when the very top guess is a stale banner. Bounded so a
    # banner-cache image doesn't trigger many multi-GB downloads.
    if os_type != "mac":
        for dl_ver, dl_banner in candidates[:3]:
            dl_arch = _detect_arch_from_banner(dl_banner or "")
            if _try_dbgsym_download_build(image, dl_ver, dl_banner or top_banner,
                                          dl_arch, vol3, os_type):
                if _verify_works_strict(vol3, image, os_type, verify_to):
                    msg_ok("Symbol verification passed (official debug-package build)!")
                    _write_kernel_json(output_dir, dl_ver, dl_banner, os_type, dl_arch)
                    return True
                msg_warn(f"Debug-package ISF for {dl_ver} installed but "
                         "verification failed — trying next candidate")

    # --- All attempts failed: record best guess + print manual steps ---
    _write_kernel_json(output_dir, top_ver, top_banner, os_type, top_arch)
    if os_type != "mac":
        _print_manual_steps(top_ver, top_banner or "", top_arch)
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
