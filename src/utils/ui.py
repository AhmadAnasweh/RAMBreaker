"""CresCent RAM Forensics Toolkit v5.0 - UI Helpers (ASCII-only)"""

import os
import sys
from pathlib import Path
from typing import List, Optional

VERSION = "6.2"

# sys.stdout is None in multiprocessing workers under pythonw.exe (GUI child);
# calling .isatty() on it crashed every worker at import (BrokenProcessPool).
if sys.stdout is not None and sys.stdout.isatty():
    R = "\033[0;31m"; G = "\033[0;32m"; Y = "\033[1;33m"; B = "\033[0;34m"
    P = "\033[0;35m"; C = "\033[0;36m"; W = "\033[1;37m"; N = "\033[0m"
else:
    R = G = Y = B = P = C = W = N = ""

LINE_W = 68

def banner():
    return f"""{C}
                        بسم الله الرحمن الرحيم
+=====================================================================+
|      ____      _    __  __ ____                 _                   |
|     |  _ \\    / \\  |  \\/  | __ ) _ __ ___  __ _| | _____ _ __       |
|     | |_) |  / _ \\ | |\\/| |  _ \\| '__/ _ \\/ _` | |/ / _ \\ '__|      |
|     |  _ <  / ___ \\| |  | | |_) | | |  __/ (_| |   <  __/ |         |
|     |_| \\_\\/_/   \\_\\_|  |_|____/|_|  \\___|\\__,_|_|\\_\\___|_|         |
|                                                                     |
|                     RAM Forensics Toolkit  v{VERSION}                     |
|                          by Ahmad Anasweh                           |
+=====================================================================+{N}
"""

def print_line():
    print(f"{B}   {'=' * LINE_W}{N}")

_STEP = None


def msg_info(t):
    print(f"   {B}[i]{N} {t}")
    # GUI: "Step k/N: Doing X..." lines become stage events
    global _STEP
    try:
        import re as _re
        from modules import progress as _pg
        if _pg.enabled():
            m = _re.match(r"Step (\d+)/(\d+): (.+?)\.*$", str(t))
            if m:
                if _STEP:
                    _pg.stage(_STEP, "done")
                _STEP = m.group(3)
                _pg.emit("stage", name=_STEP, state="start",
                         index=int(m.group(1)), of=int(m.group(2)))
    except Exception:
        pass

def msg_ok(t):
    print(f"   {G}[+]{N} {t}")

def msg_fail(t):
    print(f"   {R}[x]{N} {t}")

def msg_warn(t):
    print(f"   {Y}[!]{N} {t}")

def progress_line(current, total, label=""):
    pct = int(current / total * 100) if total else 0
    bl = 30
    filled = int(bl * current / total) if total else 0
    bar = "#" * filled + "-" * (bl - filled)
    suf = f" {label}" if label else ""
    sys.stdout.write(f"\r   [{bar}] {current}/{total} ({pct}%){suf}  ")
    sys.stdout.flush()
    if current >= total:
        sys.stdout.write("\n"); sys.stdout.flush()

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

_EOF_STREAK = 0


def stdin_interactive() -> bool:
    """True only when a person can type at stdin. On Windows isatty() is also
    True for the NUL device (a character device), so ask the console API."""
    try:
        if not sys.stdin or not sys.stdin.isatty():
            return False
        if os.name == "nt":
            import ctypes
            import msvcrt
            h = msvcrt.get_osfhandle(sys.stdin.fileno())
            mode = ctypes.c_uint32()
            return bool(ctypes.windll.kernel32.GetConsoleMode(h, ctypes.byref(mode)))
        return True
    except Exception:
        return False


def prompt(text, default=""):
    """Read a line. A closed stdin (no terminal: script, pipe, GUI child)
    returns the default once or twice, but 3 EOFs in a row mean nobody can
    answer: exit instead of letting a menu redraw forever (that once wrote
    8 GB of menu text to a log)."""
    global _EOF_STREAK
    suffix = f" [{default}]" if default else ""
    try:
        val = input(f"   {text}{suffix}: ").strip()
    except KeyboardInterrupt:
        print(); return default
    except EOFError:
        print()
        _EOF_STREAK += 1
        if _EOF_STREAK >= 3:
            import sys
            print("   [x] No interactive input available (stdin is closed) - this is an "
                  "interactive menu. Run it from a terminal or use a non-interactive "
                  "command (e.g. 'full', 'report'). Exiting.", file=sys.stderr)
            sys.exit(2)
        return default
    _EOF_STREAK = 0
    return val if val else default

def prompt_choice(options, title="Select"):
    print(); print(f"   {W}{title}{N}"); print()
    for i, opt in enumerate(options, 1):
        print(f"   {W}[{i}]{N} {opt}")
    print()
    raw = prompt(f"Select [1-{len(options)}]")
    try:
        idx = int(raw) - 1
        if 0 <= idx < len(options): return idx
    except (ValueError, TypeError): pass
    return -1

def find_memory_images(search_dirs=None):
    if search_dirs is None:
        home = Path.home()
        sdp = [Path("."), Path(".."), home / "Desktop", home / "Downloads"]
    else:
        sdp = [Path(d) for d in search_dirs]
    exts = {".dmp", ".raw", ".mem", ".vmem", ".img", ".bin", ".lime"}
    seen, images = set(), []
    for d in sdp:
        if not d.is_dir(): continue
        try:
            for entry in d.rglob("*"):
                if entry.suffix.lower() not in exts or not entry.is_file(): continue
                res = entry.resolve()
                if res in seen: continue
                seen.add(res)
                try:
                    if res.stat().st_size >= 10_000_000: images.append(res)
                except OSError: continue
        except PermissionError: continue
    images.sort(key=lambda p: p.name.lower())
    return images

def format_size(size_bytes):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(size_bytes) < 1024.0: return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} PB"

def format_duration(seconds):
    if seconds < 60: return f"{seconds:.1f}s"
    m = int(seconds // 60); s = int(seconds % 60)
    if m < 60: return f"{m}m {s}s"
    h = m // 60; m2 = m % 60
    return f"{h}h {m2}m {s}s"

def parse_selection(sel_str, max_val):
    """Parse '1,3-5,8' into zero-based indices."""
    indices = []
    for part in sel_str.replace(" ", "").split(","):
        if "-" in part and not part.startswith("-"):
            try:
                a, b = part.split("-", 1)
                s, e = int(a), int(b)
                if 1 <= s <= e <= max_val: indices.extend(range(s - 1, e))
            except ValueError: continue
        else:
            try:
                n = int(part)
                if 1 <= n <= max_val: indices.append(n - 1)
            except ValueError: continue
    seen, result = set(), []
    for i in indices:
        if i not in seen: seen.add(i); result.append(i)
    return result
