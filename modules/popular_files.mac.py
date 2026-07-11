"""CresCent RAM Forensics Toolkit v6.0 - Popular Locations File Browser (macOS)

Scans mac.list_files / lsof JSON and categorizes files in macOS user-interest directories.

Output JSON goes to  iocs/json/popular_files.json, TXT goes to  iocs/popular_files.txt.
"""

import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from utils.json_converter import load_json_by_pattern


def _gv(item, *keys):
    for k in keys:
        if k in item:
            return item[k]
    lower_map = {str(k).lower(): k for k in item}
    for k in keys:
        if str(k).lower() in lower_map:
            return item[lower_map[str(k).lower()]]
    return None


# ── Windows location buckets ─────────────────────────────────────────────────
_WIN_BUCKETS: List[Tuple[str, str]] = [
    ("Desktop",       "/desktop/"),
    ("Downloads",     "/downloads/"),
    ("Documents",     "/documents/"),
    ("Music",         "/music/"),
    ("Videos",        "/videos/"),
    ("Pictures",      "/pictures/"),
    ("AppData",       "/appdata/"),
    ("Windows Temp",  "/windows/temp/"),
    ("Temp",          "/temp/"),
    ("Recent",        "/recent/"),
    ("Startup",       "/startup/"),
    ("System32",      "/system32/"),
    ("SysWOW64",      "/syswow64/"),
    ("Recycle Bin",   "/$recycle.bin/"),
    ("Users Root",    "/users/"),
]

# ── Linux location buckets ────────────────────────────────────────────────────
_LIN_BUCKETS: List[Tuple[str, str]] = [
    ("Desktop",       "/desktop/"),
    ("Downloads",     "/downloads/"),
    ("Documents",     "/documents/"),
    ("Music",         "/music/"),
    ("Videos",        "/videos/"),
    ("Pictures",      "/pictures/"),
    ("var/tmp",       "/var/tmp/"),
    ("tmp",           "/tmp/"),
    ("root home",     "/root/"),
    ("home",          "/home/"),
    ("etc",           "/etc/"),
    ("var/log",       "/var/log/"),
    ("var/spool",     "/var/spool/"),
    ("usr/bin",       "/usr/bin/"),
    ("bin / sbin",    "/bin/"),
    ("proc",          "/proc/"),
]

# ── macOS location buckets ────────────────────────────────────────────────────
_MAC_BUCKETS: List[Tuple[str, str]] = [
    ("Desktop",            "/desktop/"),
    ("Downloads",          "/downloads/"),
    ("Documents",          "/documents/"),
    ("Music",              "/music/"),
    ("Movies",             "/movies/"),
    ("Pictures",           "/pictures/"),
    ("Applications",       "/applications/"),
    ("LaunchAgents",       "/launchagents/"),
    ("LaunchDaemons",      "/launchdaemons/"),
    ("Library",            "/library/"),
    ("private/var/tmp",    "/private/var/tmp/"),
    ("private/tmp",        "/private/tmp/"),
    ("var/tmp",            "/var/tmp/"),
    ("tmp",                "/tmp/"),
    ("Users Root",         "/users/"),
    ("System",             "/system/"),
    ("usr/local",          "/usr/local/"),
    ("usr/bin",            "/usr/bin/"),
    ("etc",                "/etc/"),
]

_EXEC_EXTS = {
    ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".hta", ".scr", ".com", ".msi", ".jar", ".sh", ".py", ".pl",
    ".rb", ".elf", ".so", ".dylib", ".app", ".pkg", ".dmg",
}
_DOC_EXTS = {
    ".doc", ".docx", ".xls", ".xlsx", ".pdf", ".ppt", ".pptx",
    ".txt", ".csv", ".msg", ".eml", ".odt", ".ods",
}
_ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"}

_SUSPICIOUS_PATH_PATTERNS_WIN = [
    (r"/users/.+/appdata/local/temp/.+\.(exe|dll|ps1|bat|vbs|js)",
     "Executable in user Temp"),
    (r"/windows/temp/.+\.(exe|dll|ps1|bat|vbs|js)",
     "Executable in Windows Temp"),
    (r"/perflogs/",           "File in PerfLogs (unusual)"),
    (r"/windows/system32/spool/", "File in print spooler path"),
    (r"/\$recycle\.bin/",    "File in Recycle Bin"),
    (r"/appdata/roaming/.+\.(exe|dll|scr)", "Executable in AppData Roaming"),
    (r"[/\\]\.[a-zA-Z]\w+[/\\]", "File inside hidden directory"),
]
_SUSPICIOUS_PATH_PATTERNS_LIN = [
    (r"/var/tmp/.+\.(sh|py|pl|elf)", "Script/executable in /var/tmp"),
    (r"/tmp/.+\.(sh|py|pl|elf)",     "Script/executable in /tmp"),
    (r"/root/\.",                     "Hidden file in /root"),
    (r"/home/.+/\.[a-z].+\.(sh|py|pl|elf)", "Executable in hidden home subdir"),
    (r"[/\\]\.[a-zA-Z]\w+[/\\]",     "File inside hidden directory"),
]
_SUSPICIOUS_PATH_PATTERNS_MAC = [
    (r"/users/.+/library/launchagents/.+\.plist",
     "LaunchAgent plist in user Library"),
    (r"/library/launchagents/.+\.plist",
     "System-level LaunchAgent plist"),
    (r"/library/launchdaemons/.+\.plist",
     "LaunchDaemon plist"),
    (r"/(tmp|private/tmp|private/var/tmp)/.+\.(sh|py|pl|dylib|app)",
     "Script/executable in temp directory"),
    (r"/users/.+/downloads/.+\.(app|pkg|dmg)",
     "Installer/app in Downloads"),
    (r"[/\\]\.[a-zA-Z]\w+[/\\]",
     "File inside hidden directory"),
]


# ── Noise / default system filenames to suppress ─────────────────────────────
_NOISE_FILENAMES: frozenset = frozenset({
    "desktop.ini", "thumbs.db", ".ds_store", ".localized",
    "ntuser.ini", "autorun.inf", "folder.ico", "index.dat",
})

_NOISE_RE = re.compile(
    r"^(\$|<unknown|<unsupported)"       # NTFS metadata / kernel artifacts
    r"|^\d+$"                            # pure-number fragments from proc_maps
    r"|^#\d+"                            # #42 (deleted) lsof entries
    r"|ntuser\.dat"                      # user registry and transaction files
    r"|\.regtrans-ms$"
    r"|\.tm\.blf$"
    r"|tmcontainer\d+"
    r"|\.txr\.\d+"
    r"|^\.spotlight"
    r"|^\.fseventsd"
    r"|^\.trashes"
    r"|\$i30:"                           # NTFS index streams
    r"|\$data"
    , re.IGNORECASE
)

_NOISE_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")  # control characters in filename


def _is_noise_file(filename: str) -> bool:
    """Return True if filename is a well-known system/default file to suppress."""
    if not filename:
        return True
    if _NOISE_CHAR_RE.search(filename):  # control chars (garbled memory artifacts)
        return True
    name_lower = filename.lower()
    if name_lower in _NOISE_FILENAMES:
        return True
    return bool(_NOISE_RE.search(name_lower))


def _basename(path: str) -> str:
    """Extract filename from both Windows backslash and Unix forward-slash paths."""
    return path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]


def _classify_ext(filename: str) -> str:
    suffix = Path(filename).suffix.lower()
    if suffix in _EXEC_EXTS:
        return "executable"
    if suffix in _DOC_EXTS:
        return "document"
    if suffix in _ARCHIVE_EXTS:
        return "archive"
    return "other"


def _detect_os(all_files: List[Dict], json_dir: Optional[Path] = None) -> str:
    """Heuristic OS detection from path patterns; falls back to JSON filename prefixes."""
    win_score = sum(1 for f in all_files if
                    "\\" in f["path"] or
                    any(k in f["path"].lower() for k in
                        ("c:\\", "windows\\", "system32", "program files")))
    mac_score = sum(1 for f in all_files if
                    any(k in f["path"] for k in
                        ("/Users/", "/Applications/", "/Library/",
                         "/private/", "/System/Library")))
    lin_score = sum(1 for f in all_files if
                    f["path"].startswith("/") and
                    any(k in f["path"] for k in
                        ("/home/", "/etc/", "/usr/", "/proc/",
                         "/var/log/", "/opt/")))
    total = win_score + mac_score + lin_score
    if total == 0 and json_dir and json_dir.is_dir():
        # Fall back to actual Vol plugin output filenames.
        # Use core plugin stems (e.g. mac_pslist, linux_pslist) to avoid false
        # positives from metadata files like linux_kernel.json that appear even
        # in MAC extractions.
        names = " ".join(p.name for p in json_dir.iterdir())
        if any(x in names for x in ("mac_pslist", "mac_pstree", "mac_psaux",
                                     "mac_bash", "mac_netstat")):
            return "mac"
        if any(x in names for x in ("linux_pslist", "linux_pstree", "linux_psaux",
                                     "linux_bash", "linux_lsmod")):
            return "linux"
        if any(x in names for x in ("windows_pslist", "windows_pstree",
                                     "windows_svcscan", "windows_cmdline")):
            return "windows"
        # Vol2 fallback: Windows-only plugin names confirm the OS
        if any(x in names for x in ("hivelist_vol2", "hashdump_vol2",
                                     "svcscan_vol2", "cmdline_vol2")):
            return "windows"
        if any(x in names for x in ("linux_pslist_vol2", "linux_pstree_vol2",
                                     "linux_psaux_vol2", "linux_lsmod_vol2")):
            return "linux"
        return "unknown"
    if win_score >= lin_score and win_score >= mac_score:
        return "windows"
    if mac_score > lin_score:
        return "mac"
    return "linux"


def _check_suspicious(path_norm: str, os_type: str) -> Optional[str]:
    patterns = {
        "windows": _SUSPICIOUS_PATH_PATTERNS_WIN,
        "linux":   _SUSPICIOUS_PATH_PATTERNS_LIN,
        "mac":     _SUSPICIOUS_PATH_PATTERNS_MAC,
    }.get(os_type, _SUSPICIOUS_PATH_PATTERNS_LIN)
    for pattern, reason in patterns:
        if re.search(pattern, path_norm, re.IGNORECASE):
            return reason
    return None


class PopularFilesScanner:
    """Categorize file entries by user-facing directory location (Win/Linux/macOS)."""

    def __init__(self, logger: logging.Logger):
        self.log = logger

    def scan(self, output_dir: Path) -> Dict[str, Any]:
        jd = output_dir / "json"
        if not jd.is_dir():
            self.log.error("No json/ directory: %s", jd)
            return {}

        all_files = self._collect_all_files(jd)
        self.log.info("Popular files scan: %d total file entries", len(all_files))

        os_type = _detect_os(all_files, jd)
        buckets_def = {"windows": _WIN_BUCKETS,
                       "linux":   _LIN_BUCKETS,
                       "mac":     _MAC_BUCKETS}.get(os_type, _LIN_BUCKETS)

        bucketed: Dict[str, List[Dict]] = {name: [] for name, _ in buckets_def}
        bucketed["Other / Uncategorized"] = []
        suspicious: List[Dict] = []
        executables_in_user_dirs: List[Dict] = []

        user_bucket_names = {
            "windows": {"Desktop", "Downloads", "Documents", "Temp",
                        "AppData", "Windows Temp", "Users Root"},
            "linux":   {"Desktop", "Downloads", "Documents", "tmp",
                        "var/tmp", "root home", "home"},
            "mac":     {"Desktop", "Downloads", "Documents", "Music",
                        "Movies", "Pictures", "tmp", "private/tmp",
                        "private/var/tmp", "Users Root"},
        }[os_type]

        for fentry in all_files:
            path = fentry["path"]
            path_norm = path.replace("\\", "/").lower()
            matched = False
            for bucket_name, pattern in buckets_def:
                if pattern in path_norm:
                    bucketed[bucket_name].append(fentry)
                    matched = True
                    break
            if not matched:
                bucketed["Other / Uncategorized"].append(fentry)

            sus_reason = _check_suspicious(path_norm, os_type)
            if sus_reason:
                suspicious.append({**fentry, "reason": sus_reason})

            ext_class = _classify_ext(path)
            if ext_class == "executable":
                for bucket_name, pattern in buckets_def:
                    if bucket_name in user_bucket_names and pattern in path_norm:
                        executables_in_user_dirs.append(fentry)
                        break

        bucket_summary: Dict[str, Any] = {}
        for name, items in bucketed.items():
            if not items:
                continue
            by_ext: Dict[str, int] = {}
            by_name: Dict[str, int] = {}
            for f in items:
                ext = Path(f["path"]).suffix.lower() or "(no ext)"
                by_ext[ext] = by_ext.get(ext, 0) + 1
                fname = f["filename"]
                if not _is_noise_file(fname):
                    by_name[fname] = by_name.get(fname, 0) + 1
            # Top filenames: sort by frequency desc, then alpha; cap at 50
            top_names = [n for n, _ in sorted(by_name.items(),
                                              key=lambda x: (-x[1], x[0].lower()))[:50]]
            # Filtered file list (noise removed) for the HTML expanded view
            clean_files = [f for f in items if not _is_noise_file(f["filename"])]
            bucket_summary[name] = {
                "count": len(items),
                "clean_count": len(clean_files),
                "top_extensions": dict(sorted(by_ext.items(), key=lambda x: -x[1])[:15]),
                "top_filenames": top_names,
                "files": clean_files[:200],
            }

        self.log.info("Popular files: %d suspicious, %d executables in user dirs",
                      len(suspicious), len(executables_in_user_dirs))
        return {
            "total_files_scanned": len(all_files),
            "os_heuristic": os_type,
            "buckets": bucket_summary,
            "suspicious_paths": suspicious[:500],
            "executables_in_user_dirs": executables_in_user_dirs[:200],
            "total_findings": len(suspicious) + len(executables_in_user_dirs),
        }

    def _collect_all_files(self, jd: Path) -> List[Dict]:
        entries: List[Dict] = []
        seen: set = set()

        def _add(path: str, offset: str = "", source: str = "filescan"):
            path = path.strip()
            if not path or path in seen:
                return
            seen.add(path)
            fname = _basename(path)
            entries.append({
                "path": path,
                "filename": fname,
                "ext_class": _classify_ext(path),
                "offset": offset,
                "source": source,
            })

        for entry in load_json_by_pattern(jd, "filescan"):
            path = str(_gv(entry, "Name", "FileName", "File", "name", "Path", "path") or "")
            offset = str(_gv(entry, "Offset", "offset", "Address") or "")
            if path:
                _add(path, offset, "filescan")

        for entry in load_json_by_pattern(jd, "enumerate_files"):
            path = str(_gv(entry, "Name", "FileName", "File", "name", "Path", "path", "raw") or "")
            if path:
                _add(path, "", "enumerate_files")

        for entry in load_json_by_pattern(jd, "lsof"):
            path = str(_gv(entry, "Name", "name", "FILE", "Path") or "")
            if path and not path.startswith(("socket:", "pipe:", "anon_inode")):
                _add(path, "", "lsof")

        # macOS mac.list_files / list_files plugin
        for pattern in ("list_files", "mac_list_files"):
            for entry in load_json_by_pattern(jd, pattern):
                path = str(_gv(entry, "File Path", "Name", "Path", "File", "name",
                               "path", "FileName", "Full Path") or "")
                if path:
                    _add(path, "", pattern)

        for entry in load_json_by_pattern(jd, "mftscan"):
            path = str(_gv(entry, "Name", "FileName", "File", "name",
                           "Full Path", "FullPath") or "")
            if path:
                _add(path, "", "mftscan")

        # macOS proc_maps / proc.Maps
        for pattern in ("proc_maps", "proc.Maps"):
            for entry in load_json_by_pattern(jd, pattern):
                path = str(_gv(entry, "Map Name", "File", "Path", "MappedFile",
                               "name", "mapped_file", "Mapped File") or "")
                if path and path.startswith("/"):
                    _add(path, "", pattern)

        return entries

    def write_report(self, output_dir: Path, results: Dict) -> Path:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        iocs_dir = output_dir / "iocs"
        iocs_dir.mkdir(parents=True, exist_ok=True)
        txt_path = iocs_dir / "popular_files.txt"

        json_dir = iocs_dir / "json"
        json_dir.mkdir(parents=True, exist_ok=True)
        json_path = json_dir / "popular_files.json"

        os_label = results.get("os_heuristic", "unknown").upper()

        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("  POPULAR LOCATIONS FILE REPORT\n")
            f.write(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"  OS: {os_label}  |  Files scanned: {results['total_files_scanned']}\n")
            f.write("=" * 80 + "\n\n")

            sus = results.get("suspicious_paths", [])
            f.write(f"{'=' * 80}\n  SUSPICIOUS FILE LOCATIONS ({len(sus)})\n{'=' * 80}\n\n")
            if sus:
                for entry in sus[:100]:
                    f.write(f"  [{entry.get('reason', '')}]\n")
                    f.write(f"    {entry.get('path', '')}\n")
                if len(sus) > 100:
                    f.write(f"\n  ... and {len(sus) - 100} more (see JSON)\n")
            else:
                f.write("  None found.\n")
            f.write("\n")

            execs = results.get("executables_in_user_dirs", [])
            f.write(f"{'=' * 80}\n  EXECUTABLES IN USER DIRECTORIES ({len(execs)})\n{'=' * 80}\n\n")
            if execs:
                for entry in execs[:100]:
                    f.write(f"  {entry.get('path', '')}\n")
                if len(execs) > 100:
                    f.write(f"\n  ... and {len(execs) - 100} more (see JSON)\n")
            else:
                f.write("  None found.\n")
            f.write("\n")

            f.write(f"{'=' * 80}\n  FILES BY LOCATION\n{'=' * 80}\n\n")
            for bucket_name, bdata in sorted(
                    results.get("buckets", {}).items(), key=lambda x: -x[1]["count"]):
                count = bdata["count"]
                f.write(f"  [{bucket_name}]  {count} file(s)\n")
                exts = bdata.get("top_extensions", {})
                if exts:
                    ext_str = "  ".join(f"{e}:{c}" for e, c in list(exts.items())[:8])
                    f.write(f"    Extensions: {ext_str}\n")
                for fentry in bdata.get("files", [])[:20]:
                    f.write(f"    {fentry.get('path', '')[:120]}\n")
                if count > 20:
                    f.write(f"    ... and {count - 20} more (see JSON)\n")
                f.write("\n")

            f.write(f"{'=' * 80}\n  SUMMARY\n{'=' * 80}\n\n")
            f.write(f"  Total files scanned:         {results['total_files_scanned']}\n")
            f.write(f"  Suspicious path hits:        {len(sus)}\n")
            f.write(f"  Executables in user dirs:    {len(execs)}\n")
            f.write(f"  Location buckets with files: {len(results.get('buckets', {}))}\n\n")
            f.write("=" * 80 + "\n  END\n" + "=" * 80 + "\n")

        json_out = {
            "total_files_scanned": results["total_files_scanned"],
            "os_heuristic": results.get("os_heuristic"),
            "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "suspicious_paths": results.get("suspicious_paths", []),
            "executables_in_user_dirs": results.get("executables_in_user_dirs", []),
            "bucket_summary": {
                name: {
                    "count": bdata["count"],
                    "top_extensions": bdata.get("top_extensions", {}),
                    "files": bdata.get("files", []),
                }
                for name, bdata in results.get("buckets", {}).items()
            },
            "total_findings": results.get("total_findings", 0),
        }
        json_path.write_text(json.dumps(json_out, indent=2, default=str), encoding="utf-8")
        self.log.info("Popular files report: %s  JSON: %s", txt_path, json_path)
        return txt_path
