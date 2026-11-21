"""Host-platform helpers (Windows port).

Everything here is about the HOST the toolkit runs on, never the target
image. Keep it dependency-free: it is imported very early.
"""

import ctypes
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Sequence

IS_WINDOWS = os.name == "nt"


def split_cmd(cmd) -> List[str]:
    """Turn a stored command (str or list) into argv.

    Command strings are built with join_cmd(), so paths containing spaces
    are quoted; a plain str.split() would break them apart.
    """
    if cmd is None:
        return []
    if isinstance(cmd, (list, tuple)):
        return list(cmd)
    if IS_WINDOWS:
        parts = shlex.split(cmd, posix=False)
        return [p[1:-1] if len(p) >= 2 and p[0] == p[-1] == '"' else p
                for p in parts]
    return shlex.split(cmd)


def join_cmd(argv: Sequence[str]) -> str:
    """Inverse of split_cmd: a display/storage string with safe quoting."""
    if IS_WINDOWS:
        return subprocess.list2cmdline([str(a) for a in argv])
    return " ".join(shlex.quote(str(a)) for a in argv)


def python3_exe() -> str:
    """Interpreter for running Python-3 helpers (vol.py, -c snippets).

    Never the bare name 'python3': on Windows that is usually the Microsoft
    Store stub. Frozen builds point at the bundled runtime via env.
    """
    env = os.environ.get("RAMBREAKER_PY3")
    if env and Path(env).is_file():
        return env
    if getattr(sys, "frozen", False):
        base = Path(sys.executable).resolve().parent
        for c in (base / "runtime" / "py3" / "python.exe",
                  base / "runtime" / "py3" / "Scripts" / "python.exe"):
            if c.is_file():
                return str(c)
    return sys.executable


def python2_candidates() -> List[str]:
    """Python 2.7 interpreters to try for Volatility 2 (first existing wins)."""
    out: List[str] = []
    env = os.environ.get("RAMBREAKER_PY2")
    if env:
        out.append(env)
    for base in runtime_dirs():
        out.append(str(base / "py27" / ("python.exe" if IS_WINDOWS else "bin/python")))
    if IS_WINDOWS:
        out += [r"C:\Python27\python.exe"]
    out += ["python2", "python2.7"]
    return out


def runtime_dirs() -> List[Path]:
    """Candidate 'runtime' folders (bundled toolchain) in priority order."""
    dirs: List[Path] = []
    env = os.environ.get("RAMBREAKER_RUNTIME")
    if env:
        dirs.append(Path(env))
    if getattr(sys, "frozen", False):
        dirs.append(Path(sys.executable).resolve().parent / "runtime")
    here = Path(__file__).resolve().parent.parent      # src/
    dirs += [here / "runtime", here.parent / "runtime"]
    seen, uniq = set(), []
    for d in dirs:
        k = str(d).lower()
        if k not in seen:
            seen.add(k)
            uniq.append(d)
    return uniq


def app_root() -> Path:
    """Folder holding output/, logs/, cache/, config/, sigma_rules/.

    Frozen: the folder of RAMBreaker.exe. Source checkout: the project root
    (parent of src/) when a runtime/ sits there, else src/ itself.
    """
    env = os.environ.get("RAMBREAKER_HOME")
    if env:
        return Path(env)
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    src = Path(__file__).resolve().parent.parent
    if (src.parent / "runtime").is_dir():
        return src.parent
    return src


def bundled_vol3_cache() -> Optional[Path]:
    """Private Vol3 cache beside the app (only when a bundled runtime exists)."""
    if any((d / "volatility3" / "vol.py").is_file() for d in runtime_dirs()):
        return app_root() / "cache" / "vol3"
    return None


def bundled_symbol_dirs() -> List[Path]:
    """Extra Vol3 symbol dirs: runtime/symbols and cache/symbols if present."""
    out = []
    for d in runtime_dirs():
        if (d / "symbols").is_dir():
            out.append(d / "symbols")
    c = app_root() / "cache" / "symbols"
    if c.is_dir():
        out.append(c)
    return out


def vol2_profile_dir() -> Path:
    """Folder of user/bundled Vol2 profile zips (Linux/Mac), beside the app."""
    return app_root() / "cache" / "vol2_profiles"


def vol2_addrspace_dir() -> Path:
    """RAMBreaker's own Vol2 address spaces (app/vol2_addrspaces): the VMware
    .vmem memory-map address space (modules/vmem_gap.py)."""
    return Path(__file__).resolve().parent.parent / "vol2_addrspaces"


def vol2_global_args() -> List[str]:
    """--plugins=<dirs> (os.pathsep-separated): RAMBreaker's address spaces,
    plus the profile dir when it holds profile zips (Vol2 walks plugin dirs
    for Linux/Mac profile zips)."""
    dirs = []
    a = vol2_addrspace_dir()
    if a.is_dir():
        dirs.append(str(a))
    d = vol2_profile_dir()
    try:
        if d.is_dir() and any(p.suffix.lower() == ".zip" for p in d.iterdir()):
            dirs.append(str(d))
    except OSError:
        pass
    return [f"--plugins={os.pathsep.join(dirs)}"] if dirs else []


def vmem_map_dir() -> Path:
    """Where guest memory maps of VMware .vmem files without .vmss/.vmsn are
    kept (modules/vmem_gap.py). Exported as RB_VMEM_MAP_DIR so the Vol3 layer
    and the Vol2 address space in every child process find them."""
    d = vol3_cache_dir() / "vmem_maps"
    os.environ["RB_VMEM_MAP_DIR"] = str(d)
    return d


def install_vol2_profile(zip_path) -> Optional[str]:
    """Copy a Vol2 profile zip into the profile dir; return the Vol2 profile
    name it will register as (Linux<stem><arch>), or None if invalid."""
    import shutil
    import zipfile
    zp = Path(zip_path)
    try:
        with zipfile.ZipFile(zp) as z:
            names = z.namelist()
            if not any(n.endswith("module.dwarf") for n in names) or \
                    not any("system.map" in n.lower() for n in names):
                return None
            sm = next(n for n in names if "system.map" in n.lower())
            arch = "x64" if any(t in sm for t in ("amd64", "x86_64")) else "x86"
            if "686" in sm or "i386" in sm:
                arch = "x86"
    except Exception:
        return None
    d = vol2_profile_dir()
    d.mkdir(parents=True, exist_ok=True)
    dst = d / zp.name
    if not dst.exists():
        shutil.copy2(zp, dst)
    return "Linux" + zp.stem.replace(".", "_").replace("-", "_") + arch


def relocate_vol3_cache() -> None:
    """Make a pre-built Vol3 identifier cache follow the install folder.

    The cache stores absolute symbol-file locations; when the program folder
    is moved/copied (e.g. the shipped build), rewrite the old prefix instead
    of letting Vol3 re-index ~3000 symbol files (8+ minutes).
    """
    cache = bundled_vol3_cache()
    if cache is None:
        return
    db = cache / "identifier.cache"
    marker = cache / "root.txt"
    new = str(app_root())
    try:
        old = marker.read_text(encoding="utf-8").strip() if marker.is_file() else ""
    except OSError:
        old = ""
    if not db.is_file():
        try:
            cache.mkdir(parents=True, exist_ok=True)
            marker.write_text(new, encoding="utf-8")
        except OSError:
            pass
        return
    if old and old.lower() != new.lower():
        try:
            import sqlite3
            con = sqlite3.connect(str(db))
            for a, b in ((old, new), (old.replace("\\", "/"), new.replace("\\", "/"))):
                con.execute("UPDATE OR IGNORE cache SET location = replace(location, ?, ?)", (a, b))
            con.commit()
            con.close()
        except Exception:
            return
    if old.lower() != new.lower() or not old:
        try:
            marker.write_text(new, encoding="utf-8")
        except OSError:
            pass


def vol3_global_args() -> List[str]:
    """Global vol.py args: bundled symbol dirs + private cache path."""
    args: List[str] = []
    syms = bundled_symbol_dirs()
    if syms:
        args += ["-s", ";".join(str(s) for s in syms)]
    cache = bundled_vol3_cache()
    if cache is not None:
        cache.mkdir(parents=True, exist_ok=True)
        os.environ.setdefault("RAMBREAKER_VOL3_CACHE", str(cache))
        args += ["--cache-path", str(cache)]
    return args


def vol3_argv(vol_py) -> List[str]:
    """argv prefix to run a given vol.py with the right interpreter + args."""
    return [python3_exe(), str(vol_py)] + vol3_global_args()


def vol3_cache_dir() -> Path:
    """Volatility 3 cache directory as Vol3 itself computes it."""
    env = os.environ.get("RAMBREAKER_VOL3_CACHE")
    if env:
        return Path(env)
    b = bundled_vol3_cache()
    if b is not None:
        return b
    try:
        from volatility3.framework import constants  # type: ignore
        return Path(constants.CACHE_PATH)
    except Exception:
        pass
    if IS_WINDOWS:
        return Path(os.environ.get("APPDATA", str(Path.home()))) / "volatility3"
    return Path(os.environ.get("XDG_CACHE_HOME",
                               str(Path.home() / ".cache"))) / "volatility3"


def available_ram_gb() -> Optional[float]:
    """Currently available physical RAM in GiB (None if unknown)."""
    if IS_WINDOWS:
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [("dwLength", ctypes.c_ulong),
                        ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong),
                        ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong),
                        ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong),
                        ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
        st = MEMORYSTATUSEX()
        st.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        try:
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st)):
                return st.ullAvailPhys / (1024 ** 3)
        except Exception:
            return None
        return None
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) / (1024 ** 2)
    except OSError:
        pass
    return None


def storage_is_rotational(path) -> Optional[bool]:
    """True if the volume holding `path` has a seek penalty (spinning HDD),
    False for SSD/NVMe, None if unknown. Windows: IOCTL_STORAGE_QUERY_PROPERTY /
    StorageDeviceSeekPenaltyProperty on the volume (no admin rights needed).
    Linux: /sys/block/<dev>/queue/rotational is not resolved here -> None."""
    if not IS_WINDOWS:
        return None
    try:
        import struct
        from ctypes import wintypes
        drive = os.path.splitdrive(os.path.abspath(str(path)))[0]
        if len(drive) != 2 or drive[1] != ":":
            return None                                    # UNC/network path: unknown
        k32 = ctypes.windll.kernel32
        k32.CreateFileW.restype = wintypes.HANDLE
        k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                    ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                    wintypes.HANDLE]
        k32.DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p,
                                        wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                                        ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
        h = k32.CreateFileW("\\\\.\\" + drive, 0, 3, None, 3, 0, None)  # no access, share R/W
        if not h or h == wintypes.HANDLE(-1).value:
            return None
        try:
            q = ctypes.create_string_buffer(struct.pack("<IIB3x", 7, 0, 0))  # SeekPenalty, Standard
            out = ctypes.create_string_buffer(12)
            n = wintypes.DWORD()
            if not k32.DeviceIoControl(h, 0x2D1400, q, 12, out, 12, ctypes.byref(n), None):
                return None
            _ver, _size, penalty = struct.unpack("<IIB3x", out.raw)
            return bool(penalty)
        finally:
            k32.CloseHandle(h)
    except Exception:
        return None


def io_limited_jobs(image: str, jobs: int, log=None) -> int:
    """Cap parallel Volatility jobs when the dump sits on a spinning disk.

    Each job reads the image independently. On an HDD, parallel readers turn
    sequential scans into head seeks (measured: 4 jobs on a 35 GB dump on a
    7200 rpm drive -> disk 100% busy at ~1 MB/s; psscan/handles/ldrmodules
    > 16 min each). If the dump cannot stay in the page cache (bigger than free
    RAM) run 1 job; a dump that fits is served from cache after the first pass,
    so it keeps its jobs. SSD/NVMe and unknown: unchanged."""
    if jobs <= 1 or storage_is_rotational(image) is not True:
        return jobs
    try:
        size_gb = os.path.getsize(image) / (1024 ** 3)
    except OSError:
        return jobs
    avail = available_ram_gb() or 0.0
    new = 1 if size_gb > avail else jobs
    if new < jobs and log is not None:
        log.info("Dump is on a spinning hard disk (%.1f GB, %.1f GB RAM free): running %d "
                 "plugin(s) at a time instead of %d - parallel readers would make the disk "
                 "seek constantly and every plugin much slower. Tip: copy the dump to an SSD.",
                 size_gb, avail, new, jobs)
    return new


def open_path(path) -> bool:
    """Open a file/folder with the OS default handler."""
    try:
        if IS_WINDOWS:
            os.startfile(str(path))  # type: ignore[attr-defined]
            return True
        opener = "open" if sys.platform == "darwin" else "xdg-open"
        subprocess.Popen([opener, str(path)], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False


def setup_console() -> None:
    """UTF-8 stdio + ANSI (VT) processing on Windows consoles."""
    for stream in (sys.stdout, sys.stderr):
        try:
            if stream is not None and hasattr(stream, "reconfigure"):
                stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if IS_WINDOWS:
        try:
            k32 = ctypes.windll.kernel32
            for handle_id in (-11, -12):
                h = k32.GetStdHandle(handle_id)
                mode = ctypes.c_ulong()
                if k32.GetConsoleMode(h, ctypes.byref(mode)):
                    k32.SetConsoleMode(h, mode.value | 0x0004)
        except Exception:
            pass


def hide_child_windows() -> None:
    """When run from the GUI (RAMBREAKER_NO_WINDOW=1), give every subprocess
    CREATE_NO_WINDOW so Volatility/tool consoles never flash up. One central
    patch instead of touching ~100 subprocess call sites."""
    if not IS_WINDOWS or os.environ.get("RAMBREAKER_NO_WINDOW") != "1":
        return
    if getattr(subprocess.Popen, "_rb_patched", False):
        return
    orig = subprocess.Popen.__init__

    def _init(self, *a, **kw):
        kw["creationflags"] = (kw.get("creationflags") or 0) | 0x08000000
        orig(self, *a, **kw)
    subprocess.Popen.__init__ = _init
    subprocess.Popen._rb_patched = True


def no_window_flags() -> int:
    """creationflags that stop child consoles flashing up under the GUI."""
    return 0x08000000 if IS_WINDOWS else 0   # CREATE_NO_WINDOW
