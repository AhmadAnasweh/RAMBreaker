"""Case index (RAMBreaker v2): what can be extracted from a finished case.

Pure Python, no Volatility calls: reads the plugin JSON a run already wrote
(json/) and returns plain row dicts for the GUI Extraction workspace and the
extraction-job runner (modules/extract_jobs.py):

  file_list(case)        files that can be dumped   (filescan / pagecache.Files /
                         mac list_files / Vol2 linux_find_file -L)
  process_list(case)     processes + suspicious flags + injection hits
  region_list(case, pid) memory regions (VADs / VMAs) of one process,
                         with the same injection rule the VAD dumper uses
"""

import importlib.util
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_MOD_DIR = Path(__file__).resolve().parent
_JSON_CACHE: Dict[Tuple[str, float], Any] = {}


# ----------------------------------------------------------------- helpers
def load_json(p: Path) -> Any:
    """json.load with a small (path, mtime) cache: the GUI asks repeatedly."""
    try:
        key = (str(p), p.stat().st_mtime)
    except OSError:
        return None
    if key in _JSON_CACHE:
        return _JSON_CACHE[key]
    try:
        data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        data = None
    if len(_JSON_CACHE) > 12:
        _JSON_CACHE.clear()
    _JSON_CACHE[key] = data
    return data


def _rows(p: Optional[Path]) -> List[Dict[str, Any]]:
    if p is None:
        return []
    d = load_json(p)
    out: List[Dict[str, Any]] = []

    def walk(rows):
        for r in rows or []:
            if isinstance(r, dict):
                out.append(r)
                kids = r.get("__children")
                if kids:
                    walk(kids)
    if isinstance(d, list):
        walk(d)
    return out


def _gv(item: Dict[str, Any], *keys, default=None):
    for k in keys:
        if k in item and item[k] not in (None, ""):
            return item[k]
    low = {str(k).lower(): k for k in item}
    for k in keys:
        lk = str(k).lower()
        if lk in low and item[low[lk]] not in (None, ""):
            return item[low[lk]]
    return default


def _int(v) -> Optional[int]:
    if v is None or v == "":
        return None
    if isinstance(v, int):
        return v
    try:
        s = str(v).strip()
        return int(s, 16) if s.lower().startswith("0x") else int(s)
    except ValueError:
        return None


def hx(v) -> str:
    i = _int(v)
    return hex(i) if i is not None else ""


def _find(jd: Path, *stems: str) -> Optional[Path]:
    """First json/<stem>*.json that exists, is not an error stub and has rows."""
    if not jd.is_dir():
        return None
    for stem in stems:
        for p in sorted(jd.glob(stem + "*.json")):
            if p.stem.startswith("_") or p.stat().st_size < 3:
                continue
            return p
    return None


def _load_os_mod(base: str, os_type: str):
    name = f"{base}.{os_type if os_type in ('linux', 'mac') else 'windows'}"
    path = _MOD_DIR / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ----------------------------------------------------------------- summary
def read_summary(case: Path) -> Dict[str, str]:
    """Image path, target OS, engine (vol2/vol3) and Vol2 profile of a case."""
    case = Path(case)
    info = {"image": "", "os": "", "engine": "", "profile": ""}
    s = case / "SUMMARY.txt"
    if s.is_file():
        for line in s.read_text(encoding="utf-8", errors="ignore").splitlines():
            k, _, v = line.partition(":")
            k, v = k.strip().lower(), v.strip()
            if k == "image" and not info["image"]:
                info["image"] = v
            elif k == "os":
                info["os"] = v.lower()
            elif k == "volatility":
                info["engine"] = "vol2" if "vol2" in v.lower() else ("vol3" if "vol3" in v.lower() else "")
            elif k == "profile" and v and v.upper() != "N/A":
                info["profile"] = v
    if not info["os"]:
        jd = case / "json"
        names = " ".join(p.name for p in jd.glob("*.json")) if jd.is_dir() else ""
        info["os"] = ("linux" if "linux_" in names else "mac" if "mac_" in names
                      else "windows")
    if not info["engine"]:
        jd = case / "json"
        info["engine"] = "vol2" if jd.is_dir() and any(jd.glob("*_vol2.json")) and \
            not any(jd.glob(f"{info['os']}_*.json")) else "vol3"
    return info


def locate_image(case: Path, hint: str = "") -> str:
    """The dump for this case: the SUMMARY path if it still exists, else ''."""
    for c in (hint, read_summary(case).get("image", "")):
        if c and Path(c).is_file():
            return str(Path(c))
    return ""


# ------------------------------------------------------------------- files
def file_list(case: Path) -> Tuple[str, List[Dict[str, Any]]]:
    """(source description, rows). Row keys: name, path, kind, offset, inode,
    inode_addr, size, cached_pages, dumpable, note."""
    case = Path(case)
    jd = case / "json"
    info = read_summary(case)
    os_type = info["os"]
    rows: List[Dict[str, Any]] = []
    if os_type == "windows":
        p = _find(jd, "windows_filescan", "filescan")
        for r in _rows(p):
            path = str(_gv(r, "Name", "FileName", default="") or "")
            off = _gv(r, "Offset", "Offset(P)", "offset")
            if not path or off is None:
                continue
            rows.append({"name": path.replace("/", "\\").rsplit("\\", 1)[-1], "path": path,
                         "offset": hx(off), "dumpable": True})
        return (f"windows.filescan ({p.name})" if p else ""), rows
    if os_type == "linux":
        p = _find(jd, "linux_pagecache_Files")
        if p:
            for r in _rows(p):
                ftype = str(_gv(r, "FileType", "Type", default="") or "")
                if ftype and ftype != "REG":
                    continue
                path = str(_gv(r, "FilePath", "File Path", "Path", default="") or "")
                if not path:
                    continue
                pages = _int(_gv(r, "CachedPages", "InodePages", default=0)) or 0
                rows.append({"name": path.rsplit("/", 1)[-1], "path": path,
                             "inode": str(_gv(r, "InodeNum", default="") or ""),
                             "inode_addr": hx(_gv(r, "InodeAddr")),
                             "size": _int(_gv(r, "InodeSize", default=0)) or 0,
                             "cached_pages": pages,
                             "dumpable": pages > 0,
                             "note": "" if pages else "no pages cached in RAM"})
            return f"linux.pagecache.Files ({p.name})", rows
        p = _find(jd, "linux_find_file_vol2")
        if p:
            for r in _rows(p):
                path = str(r.get("path") or "")
                rows.append({"name": path.rsplit("/", 1)[-1], "path": path,
                             "inode": str(r.get("inode") or ""),
                             "inode_addr": str(r.get("inode_addr") or ""),
                             "dumpable": bool(r.get("inode_addr"))})
            return f"Volatility 2 linux_find_file -L ({p.name})", rows
        return "", rows
    if os_type == "mac":
        p = _find(jd, "mac_list_files")
        for r in _rows(p):
            path = str(_gv(r, "File Path", "Path", default="") or "")
            if not path or "..namedfork" in path:
                continue
            rows.append({"name": path.rsplit("/", 1)[-1], "path": path,
                         "offset": hx(_gv(r, "Address", "Offset")), "dumpable": True})
        return (f"mac.list_files ({p.name})" if p else ""), rows
    return "", rows


def extensions(rows: List[Dict[str, Any]], top: int = 40) -> List[Tuple[str, int]]:
    c: Dict[str, int] = {}
    for r in rows:
        n = r.get("name", "")
        e = ("." + n.rsplit(".", 1)[-1].lower()) if "." in n.strip(".") else "(none)"
        if len(e) > 12:
            e = "(other)"
        c[e] = c.get(e, 0) + 1
    return sorted(c.items(), key=lambda x: -x[1])[:top]


# --------------------------------------------------------------- processes
def process_list(case: Path) -> List[Dict[str, Any]]:
    """Row keys: pid, ppid, name, cmdline, flags (list of str)."""
    case = Path(case)
    info = read_summary(case)
    os_type = info["os"]
    rows: List[Dict[str, Any]] = []
    try:
        import logging
        mod = _load_os_mod("process_dumper", os_type)
        pd = mod.ProcessDumper(None, logging.getLogger("caseindex"))
        pd.load_processes(case)
        pd.detect_suspicious()
        for p in pd.processes:
            rows.append({"pid": str(p.get("pid", "")), "ppid": str(p.get("ppid", "")),
                         "name": p.get("name", ""), "cmdline": p.get("cmdline", ""),
                         "flags": list(p.get("flags") or [])})
    except Exception:
        rows = []
    if not rows:                                # Vol2 / unusual keys: plain pslist
        jd = case / "json"
        seen = set()
        for r in _rows(_find(jd, f"{os_type}_pslist", "pslist", f"{os_type}_psscan",
                             "linux_pslist_vol2", "mac_pslist")):
            pid = str(_gv(r, "PID", "Pid", "pid", default="") or "")
            if not pid or pid in seen:
                continue
            seen.add(pid)
            rows.append({"pid": pid, "ppid": str(_gv(r, "PPID", "PPid", "ppid", default="") or ""),
                         "name": str(_gv(r, "ImageFileName", "COMM", "Name", "Process", default="") or ""),
                         "cmdline": "", "flags": []})
    inj = load_json(case / "json" / "injection_correlation.json")
    if isinstance(inj, dict):
        by_pid: Dict[str, List[str]] = {}
        for f in inj.get("findings", []) or []:
            pid = str(f.get("pid", ""))
            conf = str(f.get("confidence", ""))
            if pid and conf in ("HIGH", "MEDIUM"):
                by_pid.setdefault(pid, []).append(conf)
        for r in rows:
            c = by_pid.get(r["pid"])
            if c:
                r["flags"].append(f"Injection: {c.count('HIGH')} HIGH, {c.count('MEDIUM')} MEDIUM")
    rows.sort(key=lambda r: (_int(r["pid"]) or 0))
    return rows


# ----------------------------------------------------------------- regions
def regions_file(case: Path, pid: str) -> Path:
    """Where an on-demand region listing for one PID is stored."""
    return Path(case) / "extracted" / "_regions" / f"pid_{pid}.json"


def region_source(case: Path) -> Optional[Path]:
    jd = Path(case) / "json"
    return _find(jd, "windows_vadinfo", "linux_proc_Maps", "mac_proc_maps",
                 "linux_proc_maps_vol2", "vadinfo_vol2")


def region_list(case: Path, pid: str) -> Tuple[bool, List[Dict[str, Any]]]:
    """(known, rows). known=False means the case has no region data for this
    PID yet (run a 'list regions' job). Row keys: start, end, size, protection,
    tag, file, injection."""
    case = Path(case)
    info = read_summary(case)
    os_type = info["os"]
    pid = str(pid)
    src = None
    own = regions_file(case, pid)
    if own.is_file():
        src = own
    else:
        src = region_source(case)
    raw = [r for r in _rows(src)
           if str(_gv(r, "PID", "Pid", "pid", default="")) == pid]
    if not raw and src is not own:
        return False, []
    try:
        inj_rule = _load_os_mod("vad_dumper", os_type)._is_injection
    except Exception:
        inj_rule = lambda *_a: None
    rows = []
    for r in raw:
        st = _int(_gv(r, "Start VPN", "Start", "start"))
        en = _int(_gv(r, "End VPN", "End", "end"))
        if st is None:
            continue
        prot = str(_gv(r, "Protection", "Flags", "protection", default="") or "")
        fn = _gv(r, "File", "File Path", "Map Name", "file")
        fn = str(fn) if fn not in (None, "", "N/A") else ""
        if fn.lower() in ("none", "null", "disabled"):
            fn = ""
        file_backed = bool(fn) and not fn.startswith("[") and fn != "sub_map"
        rows.append({"start": hex(st), "end": hex(en) if en is not None else "",
                     "size": (en - st + (1 if os_type == "windows" else 0)) if en is not None else 0,
                     "protection": prot,
                     "tag": str(_gv(r, "Tag", "PrivateMemory", default="") or ""),
                     "file": fn,
                     "injection": inj_rule(prot, file_backed) or ""})
    return True, rows


def fmt_size(n: int) -> str:
    n = int(n or 0)
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024.0
    return str(n)


_SAFE = re.compile(r"[^\w.\-]+")


def safe_name(s: str, n: int = 80) -> str:
    """File-system-safe name; keeps a leading dot (.bash_history, .ssh)."""
    out = _SAFE.sub("_", s or "").strip("_ ").rstrip(".")
    return (out if out not in ("", ".", "..") else "item")[:n]
