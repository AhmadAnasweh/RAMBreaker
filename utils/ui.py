"""CresCent RAM Forensics Toolkit v5.0 - UI Helpers (ASCII-only)"""

import os
import sys
from pathlib import Path
from typing import List, Optional

VERSION = "6.1"

if sys.stdout.isatty():
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

def msg_info(t):
    print(f"   {B}[i]{N} {t}")

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

def prompt(text, default=""):
    suffix = f" [{default}]" if default else ""
    try:
        val = input(f"   {text}{suffix}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print(); return default
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
