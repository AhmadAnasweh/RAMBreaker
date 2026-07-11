#!/usr/bin/env python3
"""CresCent v6.0 — Linux image identification

Standalone home for everything that decides "is this a Linux (or macOS)
memory image, and which Volatility 2 profile / Volatility 3 ISF does it
need?".  Previously this logic lived inside VolatilityWrapper; it now lives
here so it can be reasoned about, tested, and reused on its own.

VolatilityWrapper.auto_detect() delegates to the functions below, so the
toolkit's behaviour in auto-detect mode is unchanged.

Two groups of functions:

  Detection (no network)
    fast_format_detect(image)          -- header + 16 MB sniff (LiME/banner)
    raw_os_detect(image)               -- 10 MB last-resort string scan
    extract_linux_banner(out)          -- pull banner from banners.Banners
    has_vol3_linux_isf(banner, paths)  -- is a matching Vol3 ISF installed?
    detect_linux_profile_vol2_list(..) -- find a working Vol2 Linux profile
    detect_linux_profile_vol2(..)      -- Vol2 profile via linux_banner

  Symbol-table catalogue (network — the Abyss-W4tcher repo)
    fetch_available_symbol_names()     -- download the banner index (names only)
    search_symbol_catalogue(cat, term) -- filter the catalogue by a search term

The module can also be run directly to identify an image:

    python3 modules/linux_identify.py -i memory.lime
    python3 modules/linux_identify.py --search "5.4.0-42"
"""

import base64
import json
import logging
import lzma
import os
import re
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path
from typing import List, Optional, Tuple

# Default Vol3 install locations — mirrors VolatilityWrapper.V3_PATHS so the ISF
# lookup works whether called from the wrapper or standalone.
V3_PATHS = [
    "./vol.py", "../vol.py", "./volatility3/vol.py", "../volatility3/vol.py",
    "{home}/volatility3/vol.py", "{home}/Desktop/volatility3/vol.py",
    "{home}/tools/volatility3/vol.py", "/opt/volatility3/vol.py",
]


def _log(logger: Optional[logging.Logger]):
    """Return the given logger or a no-op module logger."""
    return logger if logger is not None else logging.getLogger("linux_identify")


# ══════════════════════════════════════════════════════════════════════════════
# Vol3 execution helpers — progress-aware (no fixed wall-clock timeouts)
# ══════════════════════════════════════════════════════════════════════════════

def _vol3_cache_dir() -> str:
    """Vol3's on-disk cache directory (honours XDG_CACHE_HOME like Vol3 does)."""
    base = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    return os.path.join(base, "volatility3")


def isf_cache_is_warm(logger: Optional[logging.Logger] = None) -> bool:
    """True if Vol3's ISF identifier cache is already built and committed.

    The first Vol3 plugin run on a fresh cache must index every installed ISF
    ("Updating caches for N files…") — minutes of work on a box with the full
    Windows symbol pack. Vol3 commits that index to a SQLite DB in one
    transaction, so a populated `cache` table means the expensive build is done
    and later runs reuse it; an empty (or missing) table means the next run pays
    the full cost. We use this to decide whether a one-time warm-up is needed.
    """
    db = os.path.join(_vol3_cache_dir(), "identifier.cache")
    if not os.path.exists(db):
        return False
    try:
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=5)
        try:
            n = con.execute("SELECT count(*) FROM cache").fetchone()[0]
        finally:
            con.close()
        return n > 0
    except Exception as e:
        _log(logger).debug("isf_cache_is_warm check failed: %s", e)
        return False


def clear_isf_cache(logger: Optional[logging.Logger] = None) -> None:
    """Invalidate Vol3's ISF identifier cache so the next run re-indexes ALL ISFs.

    Vol3 builds a banner->ISF index once and then trusts it; a NEW ISF installed
    after that index is committed is NOT picked up, so automagic reports
    "Unsatisfied requirement" even though the matching ISF is on disk. Call this
    right after installing a freshly-built ISF, then re-warm, so the new file is
    indexed before symbol verification.
    """
    d = _vol3_cache_dir()
    for name in ("identifier.cache", "identifier.cache-journal",
                 "identifier.cache-wal", "identifier.cache-shm",
                 "valid_isf.hashcache"):
        try:
            os.unlink(os.path.join(d, name))
        except OSError:
            pass
    _log(logger).info("Cleared Vol3 ISF identifier cache (will re-index on next run)")


def list_installed_isfs(os_type: Optional[str] = None,
                        logger: Optional[logging.Logger] = None) -> "list":
    """Return the ISF files currently installed in the Vol3 symbol store.

    Looks in <vol3>/volatility3/symbols/{linux,mac}/ for .json / .json.xz files.
    Used by the interactive "use your own ISF" picker to offer already-installed
    symbol tables (the same way RAM dumps are auto-listed). os_type=None returns
    both linux and mac.
    """
    try:
        resolver = _load_resolver()
        vol3 = resolver._find_vol3()
    except Exception:
        vol3 = None
    out = []
    if not vol3:
        return out
    subs = (["linux", "mac"] if os_type is None
            else ["mac" if os_type == "mac" else "linux"])
    for sub in subs:
        d = Path(vol3) / "volatility3" / "symbols" / sub
        if d.is_dir():
            for p in sorted(d.iterdir()):
                if p.is_file() and p.name.endswith((".json", ".json.xz")):
                    out.append(p)
    return out


def install_local_isf(local_path, os_type: str = "linux",
                      logger: Optional[logging.Logger] = None) -> bool:
    """Install a USER-PROVIDED ISF file (already on disk) into the Vol3 symbol
    store and register it in the identifier cache (incremental, ~1s).

    Accepts .json or .json.xz. Validates the file parses and looks like a
    Volatility 3 ISF (has 'symbols' + 'metadata') before installing, so a wrong
    file is rejected with a clear message instead of silently doing nothing.
    If the chosen file is ALREADY in the store, it's just (re)registered.
    """
    import shutil
    log = _log(logger)
    p = Path(str(local_path)).expanduser()
    if not p.is_file():
        log.warning("ISF file not found: %s", p)
        return False
    if not p.name.endswith((".json", ".json.xz")):
        log.warning("Not an ISF file (expected .json or .json.xz): %s", p.name)
        return False
    try:
        if p.name.endswith(".xz"):
            with lzma.open(str(p)) as f:
                d = json.load(f)
        else:
            with open(str(p), "rb") as f:
                d = json.load(f)
        if not (isinstance(d, dict) and "symbols" in d and "metadata" in d):
            log.warning("File is not a valid Volatility 3 ISF "
                        "(missing 'symbols'/'metadata'): %s", p.name)
            return False
    except Exception as e:
        log.warning("ISF failed to parse (%s): %s", p.name, e)
        return False
    try:
        resolver = _load_resolver()
        vol3 = resolver._find_vol3()
        if not vol3:
            log.warning("Volatility 3 not found — cannot install ISF")
            return False
        sub = "mac" if os_type == "mac" else "linux"
        dest_dir = Path(vol3) / "volatility3" / "symbols" / sub
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / p.name
        if p.resolve() != dest.resolve():
            shutil.copy2(str(p), str(dest))
        log.info("Installed user ISF → %s", dest)
        add_new_isf_to_cache(vol3, logger)  # incremental cache register
        return True
    except Exception as e:
        log.warning("Failed to install user ISF: %s", e)
        return False


def add_new_isf_to_cache(vol3_dir, logger: Optional[logging.Logger] = None) -> bool:
    """Incrementally register newly-installed ISF(s) in Vol3's identifier cache.

    Uses Vol3's OWN `SqliteCache.update()`, which processes only NEW/changed
    files (it diffs on-disk locations against the cache) — ~1 s for one new ISF,
    versus minutes to fully clear + re-index a large symbol store. This is the
    correct way to make a freshly-built ISF visible to automagic without the
    sledgehammer of clearing the whole cache.

    `vol3_dir` is the directory containing the `volatility3` package (i.e. the
    dir that holds vol.py). Returns True on success. No external tools — only the
    already-required Volatility 3 Python package.
    """
    log = _log(logger)
    code = (
        "import os,sys;"
        f"sys.path.insert(0, {str(vol3_dir)!r});"
        "from volatility3 import framework;"
        "from volatility3.framework import constants;"
        "framework.require_interface_version(2,0,0);"
        "from volatility3.framework.automagic import symbol_cache;"
        "cf=os.path.join(constants.CACHE_PATH, constants.IDENTIFIERS_FILENAME);"
        "symbol_cache.SqliteCache(cf).update()"
    )
    try:
        r = subprocess.run(["python3", "-c", code], timeout=900,
                           capture_output=True, text=True, errors="replace")
        if r.returncode == 0:
            log.info("Incrementally registered new ISF(s) in Vol3 cache (~1s)")
            return True
        log.warning("Incremental ISF cache update failed (rc=%d): %s",
                    r.returncode, (r.stderr or "")[:200])
        return False
    except Exception as e:
        log.warning("Incremental ISF cache update error: %s", e)
        return False


def run_vol_until_done(cmd, logger: Optional[logging.Logger] = None,
                       stall_grace: int = 180, hard_ceiling: int = 3000,
                       poll: int = 4) -> Tuple[int, str, str]:
    """Run a Vol3 command, waiting on REAL progress instead of a fixed timeout.

    Vol3 streams a progress bar to stderr while it builds its ISF cache and scans
    the image. A single wall-clock timeout is wrong in both directions: too short
    for a slow box / huge image (kills a valid run mid-build, so the cache never
    commits and every future run repeats the cost), too long for a fast one.

    Instead we let the process run as long as it keeps emitting output (i.e. is
    making progress), and only abort if it goes completely silent for
    `stall_grace` seconds (a genuine hang / deadlock) or blows past
    `hard_ceiling` seconds (an absolute safety net). This adapts to the machine
    and the image rather than guessing.

    Returns (returncode, stdout_text, stderr_text); returncode is -1 on abort.
    """
    log = _log(logger)
    fd_o, out_path = tempfile.mkstemp(prefix="vol_out_")
    fd_e, err_path = tempfile.mkstemp(prefix="vol_err_")
    os.close(fd_o)
    os.close(fd_e)
    rc = -1
    try:
        with open(out_path, "wb") as of, open(err_path, "wb") as ef:
            proc = subprocess.Popen(cmd, stdout=of, stderr=ef)
            start = time.time()
            last_size = -1
            last_change = start
            while True:
                rc = proc.poll()
                if rc is not None:
                    break
                now = time.time()
                size = os.path.getsize(out_path) + os.path.getsize(err_path)
                if size != last_size:
                    last_size = size
                    last_change = now
                if now - last_change > stall_grace:
                    log.warning("Vol3 silent for %ds — aborting (stall).", stall_grace)
                    proc.kill()
                    proc.wait()
                    rc = -1
                    break
                if now - start > hard_ceiling:
                    log.warning("Vol3 exceeded %ds safety ceiling — aborting.",
                                hard_ceiling)
                    proc.kill()
                    proc.wait()
                    rc = -1
                    break
                time.sleep(poll)
        with open(out_path, "r", errors="ignore") as f:
            out = f.read()
        with open(err_path, "r", errors="ignore") as f:
            err = f.read()
        return rc, out, err
    except Exception as e:
        log.debug("run_vol_until_done error: %s", e)
        return -1, "", str(e)
    finally:
        for pth in (out_path, err_path):
            try:
                os.unlink(pth)
            except OSError:
                pass


def warm_isf_cache(vol3_cmd: str, image: str,
                   logger: Optional[logging.Logger] = None,
                   force: bool = False) -> bool:
    """Build Vol3's ISF identifier cache once, up front, if it isn't already warm.

    Runs a single `banners.Banners` (needs no symbols) through the progress-aware
    runner so the cache actually finishes building and commits — warming it for
    the OS-detection banner read, the symbol-resolution verify step, and every
    parallel plugin job that follows (which would otherwise each race on, and
    corrupt, a half-built cache). Returns True if the cache is warm afterwards.
    """
    log = _log(logger)
    if not force and isf_cache_is_warm(logger):
        log.info("Vol3 symbol cache already warm — skipping rebuild")
        return True
    log.info("Warming Vol3 symbol cache (one-time; this run pays it, later runs "
             "reuse it)...")
    # NB: do NOT pass -q. Vol3 streams a progress bar to stderr while it indexes
    # every installed ISF; that stream is exactly what keeps run_vol_until_done's
    # stall-detector fed. With -q the indexing of a large symbol store (thousands
    # of ISFs) is silent, so the run is wrongly aborted as a "stall" and the cache
    # never commits. We also widen the silence grace since decompressing thousands
    # of .xz ISFs to read their banners can pause output for a while.
    cmd = vol3_cmd.split() + ["-f", image, "banners.Banners"]
    run_vol_until_done(cmd, logger, stall_grace=600)
    warm = isf_cache_is_warm(logger)
    log.info("Vol3 symbol cache warm: %s", warm)
    return warm


_WIN_INFO_MARKERS = ("NTBuildLab", "Is64Bit", "NTMajorVersion", "KernelBase")


def windows_symbols_ready(vol3_cmd: str, image: str,
                          logger: Optional[logging.Logger] = None,
                          stall_grace: int = 120) -> Tuple[bool, str, str]:
    """Run `windows.info.Info` once, progress-aware, and report whether Vol3 can
    build this image's kernel symbol table. Returns (ok, stdout, stderr).

    `ok` is True when the output carries a real kernel field (NTBuildLab / Is64Bit
    / NTMajorVersion), meaning the per-image kernel symbol table was constructed
    and is now cached under ~/.cache/volatility3. Uses `run_vol_until_done` (waits
    on real progress, NO fixed timeout) so a large image's first cold PDB scan is
    not killed early — the mistake the old fixed 45s `_run_raw` probe made.
    """
    cmd = vol3_cmd.split() + ["-f", image, "windows.info.Info"]
    rc, out, err = run_vol_until_done(cmd, logger, stall_grace=stall_grace)
    ok = any(k in (out + err) for k in _WIN_INFO_MARKERS)
    return ok, out, err


def warm_windows_kernel_symbols(vol3_cmd: str, image: str,
                                logger: Optional[logging.Logger] = None,
                                retries: int = 2) -> bool:
    """Serially establish (and cache) the Windows kernel symbol table BEFORE the
    parallel plugin batch, so concurrent plugins don't race to build it.

    Vol3 builds the per-image Windows kernel symbol table (kernel-base scan → PDB
    → ISF) the first time any symbol-dependent plugin runs. That construction is
    NOT concurrency-safe on a cold image: when the first parallel batch
    (info / pslist / psscan / pstree) all trigger it at once they race, and all of
    them fail the `kernel.symbol_table_name` requirement while whichever wins
    writes the cache. Everything launched afterwards is a cache hit. Running
    windows.info.Info exactly ONCE, alone, up front turns every later plugin into
    that cache hit — no first-batch failures.

    Progress-aware (no fixed timeout) so it adapts to image size. Idempotent and
    cheap on a warm cache (kernel ISF is already built → fast re-scan). Returns
    True once the kernel symbol table is confirmed established. Never raises: on
    failure it logs and returns False, leaving the run to proceed (the parallel
    batch will then attempt the build itself, as before).
    """
    log = _log(logger)
    for attempt in range(1, max(1, retries) + 1):
        ok, out, err = windows_symbols_ready(vol3_cmd, image, logger)
        if ok:
            log.info("Windows kernel symbol table established (serial warm-up) "
                     "— parallel plugins will reuse the cache")
            return True
        combined = (out + err)
        if "Unsatisfied" in combined or "symbol" in combined.lower():
            # Symbols genuinely missing for this build (e.g. windows.zip absent /
            # incompatible PDB). Retrying won't help — bail so the caller's
            # existing symbol-download fallback can take over.
            log.warning("Kernel-symbol warm-up: Vol3 reports missing/incompatible "
                        "Windows symbols — skipping serial warm (attempt %d/%d)",
                        attempt, retries)
            return False
        log.warning("Kernel-symbol warm-up attempt %d/%d did not confirm — retrying",
                    attempt, retries)
    log.warning("Could not pre-establish Windows kernel symbols; the parallel "
                "batch may see first-run races (a serial retry will recover them)")
    return False


# ══════════════════════════════════════════════════════════════════════════════
# Detection (no network)
# ══════════════════════════════════════════════════════════════════════════════

def fast_format_detect(image: str, logger: Optional[logging.Logger] = None) -> str:
    """Cheap, high-confidence OS pre-check from the image header + first 16 MB.

    Returns 'linux', 'mac', or '' (unknown). Only returns a non-empty result on
    a STRONG signal, so callers can safely skip the slow detection chain:
      - LiME format magic (0x4C694D45, stored little-endian as b'EMiL') → Linux.
      - An actual 'Darwin Kernel Version' / 'xnu-' string → macOS.
      - The kernel banner prefix 'linux version ' → Linux.
    Windows is intentionally never returned here (it needs profile detection),
    so Windows images fall through to the full banners/imageinfo chain.
    """
    log = _log(logger)
    try:
        with open(image, "rb") as f:
            head = f.read(8)
            f.seek(0)
            chunk = f.read(16 * 1024 * 1024)
    except Exception as e:
        log.debug("Fast format detect error: %s", e)
        return ""
    # LiME memory-dump header magic — unambiguous Linux signal.
    if head[:4] == b"EMiL":
        log.info("LiME format detected (header magic) — Linux image")
        return "linux"
    # Search the RAW bytes (ASCII case-folded), NOT a decode(errors="ignore")
    # string: stripping non-ASCII bytes collapses unrelated binary into a
    # contiguous run where short needles spuriously appear (a 4 GB Ubuntu .vmem
    # was misdetected as macOS because random bytes spelled "xnu-" after the
    # non-ASCII separators were dropped). bytes.lower() only folds ASCII A–Z and
    # leaves other bytes in place, so adjacency reflects the real layout.
    low = chunk.lower()
    # "xnu-" alone is far too short to be safe — require a trailing digit, which
    # real XNU banners always have (e.g. "xnu-8020.140.41~1/RELEASE_ARM64").
    if b"darwin kernel version" in low or re.search(rb"xnu-\d", low):
        log.info("Darwin/XNU banner found — macOS image")
        return "mac"
    if b"linux version " in low:
        log.info("Linux kernel banner found — Linux image")
        return "linux"
    return ""


def raw_os_detect(image: str, logger: Optional[logging.Logger] = None) -> str:
    """Last resort: read first 10MB of image looking for OS signatures.

    Returns 'mac', 'linux', 'windows', or '' (unknown).
    """
    log = _log(logger)
    try:
        with open(image, "rb") as f:
            chunk = f.read(10 * 1024 * 1024)  # First 10MB
        # Search RAW bytes (ASCII case-folded), NOT decode(errors="ignore"):
        # dropping non-ASCII bytes glues unrelated binary into one contiguous
        # run where short needles match by pure chance — a 4 GB Ubuntu .vmem
        # was misdetected as macOS because random bytes spelled "xnu-" after the
        # non-ASCII separators were deleted. bytes.lower() folds only ASCII A–Z
        # and keeps every other byte in place, so adjacency is real.
        low = chunk.lower()
        # macOS — only STRONG, specific signatures. Bare "xnu-" is too short
        # (require a trailing digit, as in real banners like "xnu-8020.140.41"),
        # and "mac os x" / "com.apple" are dropped: they appear in browser
        # caches, plists and user-agent strings on Linux too.
        if b"darwin kernel version" in low or re.search(rb"xnu-\d", low):
            return "mac"
        linux_sigs = (b"linux version", b"ubuntu", b"debian", b"centos",
                      b"red hat", b"fedora", b"kali", b"gnu/linux",
                      b"linux-image", b"vmlinuz", b"ext4-fs")
        if any(sig in low for sig in linux_sigs):
            return "linux"
        # Windows signatures (check several)
        win_sigs = (b"windows", b"ntoskrnl", b"hal.dll", rb"\\systemroot",
                    rb"\\windows\\system32", b"ntdll.dll", b"kernel32.dll")
        win_count = sum(1 for sig in win_sigs if sig in low)
        if win_count >= 2:
            return "windows"
    except Exception as e:
        log.debug("Raw OS detect error: %s", e)
    return ""


def extract_linux_banner(banners_out: str) -> Optional[str]:
    """Extract the first Linux version banner string from banners.Banners output."""
    for line in banners_out.splitlines():
        if "\t" in line and "Linux version" in line:
            return line.split("\t", 1)[1].strip()
    for line in banners_out.splitlines():
        if "Linux version" in line:
            return line.strip()
    return None


def has_vol3_linux_isf(banner: str, v3_paths: Optional[List[str]] = None,
                       logger: Optional[logging.Logger] = None) -> bool:
    """Return True if any installed Vol3 ISF has a linux_banner matching banner."""
    log = _log(logger)
    v3_paths = v3_paths if v3_paths is not None else V3_PATHS
    home = str(Path.home())
    # Build the list of linux symbols directories to check
    sym_dirs: List[Path] = []
    for rp in v3_paths:
        p = Path(rp.replace("{home}", home))
        if p.is_file():
            # vol.py sits at the repo root; the installed ISFs live in
            # <repo>/volatility3/symbols/linux for a cloned checkout. Also try
            # <repo>/symbols/linux for a flatter (pip/site-package) layout.
            for candidate in (p.parent / "volatility3" / "symbols" / "linux",
                              p.parent / "symbols" / "linux"):
                if candidate.is_dir() and candidate not in sym_dirs:
                    sym_dirs.append(candidate)
    sym_dirs.append(Path(home) / ".cache" / "volatility3" / "symbols" / "linux")

    banner_clean = banner.rstrip("\x00\n ")
    for sym_dir in sym_dirs:
        if not sym_dir.is_dir():
            continue
        for isf in sym_dir.iterdir():
            if not (isf.suffix in (".xz", ".json")
                    or isf.name.endswith(".json.xz")):
                continue
            try:
                if isf.name.endswith(".xz"):
                    with lzma.open(str(isf), "rt", encoding="utf-8",
                                   errors="ignore") as fh:
                        data = json.load(fh)
                else:
                    with isf.open(encoding="utf-8", errors="ignore") as fh:
                        data = json.load(fh)
                cd = data.get("symbols", {}).get(
                    "linux_banner", {}).get("constant_data", "")
                if cd:
                    isf_banner = base64.b64decode(cd).decode(
                        "ascii", errors="replace").rstrip("\x00\n ")
                    if banner_clean == isf_banner:
                        log.info("Vol3 ISF match found: %s", isf.name)
                        return True
            except Exception:
                continue
    return False


def detect_linux_profile_vol2_list(vol2_cmd: str, image: str,
                                   logger: Optional[logging.Logger] = None
                                   ) -> Optional[str]:
    """Find a working Vol2 Linux profile from installed profiles.

    Lists available Linux profiles via --info, then verifies the first
    matching one by running linux_banner against the image.

    Returns the profile name, or None if no Linux profile is installed.
    """
    log = _log(logger)
    if not vol2_cmd:
        return None
    try:
        r = subprocess.run(
            vol2_cmd.split() + ["--info"],
            capture_output=True, text=True, timeout=30
        )
        profiles: List[str] = []
        for line in (r.stdout + r.stderr).splitlines():
            tok = line.strip().split()
            if not tok:
                continue
            name = tok[0]
            if name.startswith("Linux") and any(
                    x in name for x in ("x64", "x86", "arm", "aarch")):
                profiles.append(name)
    except Exception as exc:
        log.debug("Vol2 --info failed: %s", exc)
        return None

    if not profiles:
        return None

    # Single profile — use it directly
    if len(profiles) == 1:
        log.info("Vol2 Linux profile (only one installed): %s", profiles[0])
        return profiles[0]

    # Multiple profiles — verify each against the image
    for prof in profiles:
        try:
            r = subprocess.run(
                vol2_cmd.split() + [
                    "-f", image, f"--profile={prof}", "linux_banner"],
                capture_output=True, text=True, timeout=30
            )
            if r.returncode == 0 and "Linux version" in r.stdout:
                log.info("Vol2 Linux profile verified: %s", prof)
                return prof
        except Exception:
            continue

    # No profile verified but we have candidates — use first
    log.warning("Using first available Vol2 Linux profile: %s", profiles[0])
    return profiles[0]


def detect_linux_profile_vol2(vol2_cmd: str, image: str, run_raw,
                              logger: Optional[logging.Logger] = None
                              ) -> Optional[str]:
    """Try to detect a Vol2 Linux profile using linux_banner + profile matching.

    `run_raw(vol_cmd, image, plugin, timeout)` is the wrapper's raw runner
    (returns (rc, out, err)); passed in so we reuse its temp-file plumbing.

    Returns the profile name, or None.
    """
    log = _log(logger)
    if not vol2_cmd:
        return None
    try:
        rc, out, err = run_raw(vol2_cmd, image, "linux_banner", 60)
        banner = (out + err).strip()
        if not banner:
            return None
        rc2, out2, err2 = run_raw(vol2_cmd, image, "--info", 30)
        linux_profiles = []
        for line in (out2 + err2).splitlines():
            l = line.strip()
            if l.startswith("Linux") and ("x64" in l or "x86" in l):
                linux_profiles.append(l.split()[0])
        if linux_profiles:
            log.info("Vol2 Linux profile: %s", linux_profiles[0])
            return linux_profiles[0]
    except Exception as e:
        log.debug("Linux profile detection error: %s", e)
    return None


def looks_linux(image: str, logger: Optional[logging.Logger] = None) -> str:
    """Convenience: combine the two offline scans into one OS guess.

    Returns 'linux', 'mac', 'windows', or '' (unknown). Used by standalone CLI.
    """
    fast = fast_format_detect(image, logger)
    if fast:
        return fast
    return raw_os_detect(image, logger)


# ══════════════════════════════════════════════════════════════════════════════
# Symbol-table catalogue (network — Abyss-W4tcher/volatility3-symbols)
# ══════════════════════════════════════════════════════════════════════════════

def _load_resolver():
    """Load the linux_resolver.linux module to reuse its repo helpers."""
    import importlib.util
    path = Path(__file__).parent / "linux_resolver.linux.py"
    spec = importlib.util.spec_from_file_location("linux_resolver.linux", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# Catalogue of available symbol-table names is bundled with the tool so the
# picker works instantly and offline. Refresh it from the Installer.
BUNDLED_CATALOGUE = Path(__file__).parent.parent / "data" / "linux_symbol_catalogue.json.xz"


def _load_bundled_catalogue() -> Optional[dict]:
    """Load the catalogue shipped with the tool (compressed), or None."""
    if not BUNDLED_CATALOGUE.is_file():
        return None
    try:
        with lzma.open(str(BUNDLED_CATALOGUE), "rt", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def fetch_available_symbol_names(logger: Optional[logging.Logger] = None,
                                 force_update: bool = False) -> Optional[dict]:
    """Return the catalogue of available symbol-table NAMES — no ISF download.

    Loads the copy bundled with the tool first (instant, offline). Only reaches
    out to the Abyss-W4tcher repo when the bundle is missing or force_update is
    set. Returns {banner_string: isf_repo_path}, or None if unavailable.
    """
    log = _log(logger)
    if not force_update:
        cached = _load_bundled_catalogue()
        if cached:
            log.info("Loaded %d symbol-table names from bundled catalogue",
                     len(cached))
            return cached
    try:
        resolver = _load_resolver()
        return resolver._download_banners_index()
    except Exception as e:
        log.warning("Could not fetch symbol catalogue: %s", e)
        return None


def update_symbol_catalogue(logger: Optional[logging.Logger] = None) -> int:
    """Re-download the catalogue from the repo and refresh the bundled copy.

    Returns the number of builds saved, or 0 on failure.
    """
    log = _log(logger)
    cat = fetch_available_symbol_names(logger, force_update=True)
    if not cat:
        return 0
    try:
        BUNDLED_CATALOGUE.parent.mkdir(parents=True, exist_ok=True)
        with lzma.open(str(BUNDLED_CATALOGUE), "wt", encoding="utf-8") as f:
            json.dump(cat, f)
        log.info("Saved %d builds → %s", len(cat), BUNDLED_CATALOGUE)
        return len(cat)
    except Exception as e:
        log.warning("Could not save catalogue: %s", e)
        return 0


def kernel_version_from_isf(isf_rel: str) -> str:
    """Best-effort kernel version extracted from an ISF repo path/filename.

    e.g. 'Ubuntu/amd64/5.4.0-42-generic.json.xz' → '5.4.0-42-generic'.
    Returns '' if no version-looking token is found. Used to populate report
    metadata cheaply when the operator picked the table by hand (no image scan).
    """
    import re
    name = Path(isf_rel).name
    for suffix in (".json.xz", ".json", ".xz"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    m = re.search(r'\d+\.\d+\.\d+[\w.\-]*', name)
    return m.group(0) if m else name


def install_symbol_by_path(isf_rel: str, os_type: str = "linux",
                           logger: Optional[logging.Logger] = None) -> bool:
    """Download and install a specific ISF (by its repo-relative path).

    Used when the operator already knows which symbol table they need and
    picked it from the catalogue. Returns True on successful install.
    """
    import tempfile
    import shutil
    log = _log(logger)
    try:
        resolver = _load_resolver()
        vol3 = resolver._find_vol3()
        if not vol3:
            log.warning("Volatility 3 not found — cannot install symbol table")
            return False
        tmp = Path(tempfile.mkdtemp(prefix="crescent_sym_"))
        try:
            isf_file = resolver._download_isf(isf_rel, tmp)
            if not isf_file:
                return False
            return resolver._install_isf(isf_file, vol3, os_type)
        finally:
            shutil.rmtree(str(tmp), ignore_errors=True)
    except Exception as e:
        log.warning("Symbol install failed: %s", e)
        return False


def search_symbol_catalogue(catalogue: dict, term: str,
                            limit: int = 40) -> List[Tuple[str, str]]:
    """Filter the banner catalogue by a free-text term.

    Token-based AND match (case-insensitive): every whitespace-separated word in
    `term` must appear somewhere in the banner string or the ISF repo path. So
    'kali 6.12' matches builds containing both 'kali' and '6.12' (in any order),
    'ubuntu 20.04', '5.4.0-42', 'amd64' all work too. Returns a list of
    (banner, isf_repo_path) tuples, capped at `limit`.
    """
    tokens = (term or "").lower().split()
    out: List[Tuple[str, str]] = []
    if not catalogue:
        return out
    for banner, paths in catalogue.items():
        isf = paths[0] if isinstance(paths, list) else paths
        hay = f"{banner}\n{isf}".lower()
        if all(tok in hay for tok in tokens):
            out.append((banner, isf))
            if len(out) >= limit:
                break
    return out


# ══════════════════════════════════════════════════════════════════════════════
# Standalone CLI
# ══════════════════════════════════════════════════════════════════════════════

def _main(argv=None):
    import argparse
    logging.basicConfig(level=logging.INFO, format="  [%(levelname)s] %(message)s")
    p = argparse.ArgumentParser(
        description="Identify a Linux/macOS memory image and browse symbol tables.")
    p.add_argument("-i", "--image", help="Memory image to identify")
    p.add_argument("--search", metavar="TERM",
                   help="Search the symbol-table catalogue for TERM (e.g. 5.4.0-42)")
    p.add_argument("--list-symbols", action="store_true",
                   help="List available symbol-table names (first 40)")
    args = p.parse_args(argv)

    if args.image:
        os_guess = looks_linux(args.image)
        print(f"OS guess: {os_guess or 'unknown'}")

    if args.search or args.list_symbols:
        cat = fetch_available_symbol_names()
        if not cat:
            print("Could not reach the symbol-table repository.")
            return 1
        matches = search_symbol_catalogue(cat, args.search or "")
        print(f"\n{len(matches)} match(es) (of {len(cat)} total builds):\n")
        for banner, isf in matches:
            print(f"  {isf}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
