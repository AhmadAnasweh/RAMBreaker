"""Per-user encrypted storage of API keys (VirusTotal, abuse.ch) on Windows.

Keys are encrypted with DPAPI (CryptProtectData, current-user scope): only the same
Windows account on the same PC can decrypt them, so copying the RAMBreaker folder to
another machine does not copy usable keys. Stored in <app>/config/secrets.dat.
Never written to logs, reports or the command line. Off Windows: not stored.
"""

import base64
import ctypes
import json
import os
import sys
from ctypes import wintypes
from pathlib import Path
from typing import Dict, Optional

from modules import platform_compat

_ENTROPY = b"RAMBreaker-TI-v2.2"


class _BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _blob(b: bytes) -> _BLOB:
    buf = ctypes.create_string_buffer(b, len(b))
    return _BLOB(len(b), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))


def _crypt(data: bytes, protect: bool) -> bytes:
    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
    src, ent, out = _blob(data), _blob(_ENTROPY), _BLOB()
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    ok = (fn(ctypes.byref(src), None, ctypes.byref(ent), None, None, 0x1, ctypes.byref(out)) if protect
          else fn(ctypes.byref(src), None, ctypes.byref(ent), None, None, 0x1, ctypes.byref(out)))
    if not ok:
        raise OSError(ctypes.get_last_error() or "DPAPI call failed")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(out.pbData)


def available() -> bool:
    return sys.platform == "win32"


def _path() -> Path:
    return platform_compat.app_root() / "config" / "secrets.dat"


def _load() -> Dict[str, str]:
    try:
        raw = _path().read_text(encoding="ascii").strip()
        return json.loads(_crypt(base64.b64decode(raw), False).decode("utf-8"))
    except Exception:
        return {}


def get(name: str) -> str:
    if not available():
        return ""
    return _load().get(name, "")


def put(name: str, value: Optional[str]) -> bool:
    """Save (or with value None/'' forget) one key. Returns True on success."""
    if not available():
        return False
    d = _load()
    if value:
        d[name] = value.strip()
    else:
        d.pop(name, None)
    p = _path()
    p.parent.mkdir(parents=True, exist_ok=True)
    if not d:
        try:
            p.unlink()
        except FileNotFoundError:
            pass
        return True
    enc = base64.b64encode(_crypt(json.dumps(d).encode("utf-8"), True)).decode("ascii")
    tmp = p.with_suffix(".tmp")
    tmp.write_text(enc, encoding="ascii")
    os.replace(tmp, p)
    return True
