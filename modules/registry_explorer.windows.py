"""
CresCent RAM Forensics Toolkit v4.0 - Registry Explorer

Interactive browser for registry data from hivelist, printkey, userassist,
shellbags, shimcache, and svcscan Volatility output.

Displays results in a MemProcFS-style hierarchical tree:
  HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run
    └─ ValueName  [REG_SZ]  = C:\\Windows\\system32\\something.exe

Also exports a structured JSON tree for the HTML report.
"""

import json
import logging
import re
from collections import defaultdict
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
        lk = str(k).lower()
        if lk in lower_map:
            return item[lower_map[lk]]
    return None


# ── Persistence keys ─────────────────────────────────────────────────────────
PERSISTENCE_KEYS = [
    r"Microsoft\Windows\CurrentVersion\Run",
    r"Microsoft\Windows\CurrentVersion\RunOnce",
    r"Microsoft\Windows\CurrentVersion\RunServices",
    r"Microsoft\Windows\CurrentVersion\RunServicesOnce",
    r"Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"Microsoft\Windows NT\CurrentVersion\Windows",
    r"Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    r"Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom",
    r"Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
    r"Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
    r"Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad",
    r"Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
    r"System\CurrentControlSet\Services",
    r"System\ControlSet001\Services",
    r"System\ControlSet002\Services",
    r"Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs",
    r"System\CurrentControlSet\Control\Session Manager\BootExecute",
    r"System\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations",
    r"System\CurrentControlSet\Control\Lsa",
    r"System\CurrentControlSet\Control\SecurityProviders",
    r"Software\Classes\CLSID",
    r"Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache",
    r"Microsoft\Windows\CurrentVersion\Explorer\StartupApproved",
    r"Software\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers",
]

INTERESTING_KEYS = [
    r"Microsoft\Windows\CurrentVersion\Uninstall",
    r"Microsoft\Windows NT\CurrentVersion",
    r"Microsoft\Windows\CurrentVersion\Internet Settings",
    r"Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
    r"Microsoft\Windows\CurrentVersion\Explorer\ComDlg32",
    r"Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths",
    r"Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
    r"Microsoft\Windows\CurrentVersion\Explorer\MountPoints2",
    r"Microsoft\Windows NT\CurrentVersion\ProfileList",
    r"CurrentVersion\NetworkList",
    r"SOFTWARE\Policies",
]

_TYPE_ABBREV = {
    "reg_sz":               "REG_SZ",
    "reg_expand_sz":        "REG_EXPAND_SZ",
    "reg_binary":           "REG_BINARY",
    "reg_dword":            "REG_DWORD",
    "reg_dword_big_endian": "REG_DWORD_BE",
    "reg_link":             "REG_LINK",
    "reg_multi_sz":         "REG_MULTI_SZ",
    "reg_resource_list":    "REG_RESOURCE_LIST",
    "reg_qword":            "REG_QWORD",
    "reg_none":             "REG_NONE",
}


def _norm_type(t: str) -> str:
    return _TYPE_ABBREV.get(str(t or "").lower().replace(" ", "_"), str(t or ""))


class RegistryExplorer:
    """Browse and search registry data from Volatility output."""

    def __init__(self, logger: logging.Logger):
        self.log = logger
        self._hives: List[Dict[str, Any]] = []
        self._userassist: List[Dict[str, Any]] = []
        self._shellbags: List[Dict[str, Any]] = []
        self._shimcache: List[Dict[str, Any]] = []
        self._printkey: List[Dict[str, Any]] = []
        self._svcscan: List[Dict[str, Any]] = []
        self._key_tree: Dict[str, Dict[str, List[Dict]]] = {}

    def load(self, output_dir: Path) -> int:
        jd = output_dir / "json"
        if not jd.is_dir():
            self.log.error("No json/ directory: %s", jd)
            return 0

        self._hives      = load_json_by_pattern(jd, "hivelist")
        self._userassist = load_json_by_pattern(jd, "userassist")
        self._shellbags  = load_json_by_pattern(jd, "shellbags")
        self._shimcache  = load_json_by_pattern(jd, "shimcache")
        self._printkey   = load_json_by_pattern(jd, "printkey")
        # Load targeted per-key printkey runs (from _run_targeted_printkey)
        merged = jd / "printkey_persistence_merged.json"
        if merged.exists():
            import json as _json
            try:
                extra = _json.loads(merged.read_text(encoding="utf-8", errors="ignore"))
                if isinstance(extra, list):
                    # Convert Vol2 raw_line format → Vol3-compatible dicts
                    _vol2_re = re.compile(
                        r'^(REG_\S+)\s+(.+?)\s{2,}:\s+\([A-Z]+\)\s*(.*)$')
                    converted = []
                    for e in extra:
                        if "raw_line" in e and "key" in e:
                            m = _vol2_re.match(str(e.get("raw_line", "")).strip())
                            if m:
                                converted.append({
                                    "Key":        e["key"],
                                    "Value Name": m.group(2).strip(),
                                    "Type":       m.group(1).strip(),
                                    "Data":       m.group(3).strip().rstrip('\x00'),
                                })
                        else:
                            converted.append(e)
                    seen = {str(e) for e in self._printkey}
                    self._printkey += [e for e in converted if str(e) not in seen]
            except Exception:
                pass
        self._svcscan    = load_json_by_pattern(jd, "svcscan")

        self._build_key_tree()

        total = (len(self._hives) + len(self._userassist) +
                 len(self._shellbags) + len(self._shimcache) +
                 len(self._printkey))
        self.log.info(
            "Registry: %d hives, %d userassist, %d shellbags, "
            "%d shimcache, %d printkey, %d services",
            len(self._hives), len(self._userassist),
            len(self._shellbags), len(self._shimcache),
            len(self._printkey), len(self._svcscan))
        return total

    def _build_key_tree(self):
        """Parse printkey rows into a hive-root → key-path → [values] tree."""
        tree: Dict[str, Dict[str, List[Dict]]] = defaultdict(lambda: defaultdict(list))
        for entry in self._printkey:
            key_path   = str(_gv(entry, "Key", "key", "Path", "Subkey", "Name") or "")
            val_name   = str(_gv(entry, "Value Name", "ValueName", "Name",
                                 "value_name") or "(Default)")
            val_type   = str(_gv(entry, "Type", "type", "Value Type") or "")
            val_data   = str(_gv(entry, "Data", "data", "Value", "Value Data") or "")
            last_write = str(_gv(entry, "Last Write Time", "LastWriteTime",
                                 "Last Write", "last_write") or "")
            if not key_path:
                continue
            key_path = key_path.replace("/", "\\").strip("\\")
            parts = key_path.split("\\")
            hive_root = ""
            for i, p in enumerate(parts):
                p_up = p.upper()
                if any(h in p_up for h in (
                        "HKLM", "HKCU", "HKEY_", "SOFTWARE", "SYSTEM",
                        "SAM", "SECURITY", "NTUSER", "USRCLASS", "REGISTRY")):
                    hive_root = p
                    key_path = "\\".join(parts[i:])
                    break
            if not hive_root:
                hive_root = parts[0] if parts else "UNKNOWN"
            tree[hive_root][key_path].append({
                "value_name": val_name,
                "type":       _norm_type(val_type),
                "data":       val_data[:512],
                "last_write": last_write,
            })
        self._key_tree = {h: dict(keys) for h, keys in tree.items()}

    # ── Public accessors ──────────────────────────────────────────────────────

    def get_hives(self) -> List[Dict[str, Any]]:
        return self._hives

    def get_userassist(self) -> List[Dict[str, Any]]:
        return self._userassist

    def get_shellbags(self) -> List[Dict[str, Any]]:
        return self._shellbags

    def get_shimcache(self) -> List[Dict[str, Any]]:
        return self._shimcache

    def get_key_tree(self) -> Dict:
        return self._key_tree

    def get_services(self) -> List[Dict[str, Any]]:
        return self._svcscan

    def get_services_summary(self) -> List[Dict[str, Any]]:
        out = []
        for svc in self._svcscan:
            out.append({
                "name":    str(_gv(svc, "Name", "ServiceName", "name") or ""),
                "display": str(_gv(svc, "Display", "DisplayName", "display") or ""),
                "state":   str(_gv(svc, "State", "Status", "state") or ""),
                "start":   str(_gv(svc, "Start", "StartType", "start") or ""),
                "type":    str(_gv(svc, "Type", "ServiceType", "type") or ""),
                "pid":     str(_gv(svc, "PID", "pid", "ProcessId") or ""),
                "binary":  str(_gv(svc, "Binary", "BinaryPath", "binary", "ImagePath") or ""),
            })
        return out

    # ── Persistence finder ────────────────────────────────────────────────────

    def find_persistence(self) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        all_data = (self._userassist + self._shellbags +
                    self._shimcache + self._printkey)
        for entry in all_data:
            # Skip key header rows — Type='Key' with no Name/Data are just path
            # markers, not actual registry values. Matching them causes false positives
            # since their Key field contains every persistence path we searched.
            entry_type = str(entry.get("Type", entry.get("type", "")) or "").strip()
            entry_name = str(entry.get("Name", entry.get("name", "")) or "").strip()
            entry_data = str(entry.get("Data", entry.get("data", "")) or "").strip()
            if entry_type == "Key" and not entry_data:
                continue
            # Skip entries with no actual value data
            if not entry_data and entry_name in ("", "(Default)"):
                continue
            all_values = " ".join(str(v).lower() for v in entry.values())
            for pkey in PERSISTENCE_KEYS:
                if pkey.lower() in all_values:
                    results.append({"persistence_key": pkey, "entry": entry})
                    break

        # Also check the parsed key tree for structural matches.
        # Only add entries that have actual value data — skip empty (Default) stubs.
        seen_sig: set = set()
        for hive, keys in self._key_tree.items():
            for key_path, values in keys.items():
                path_lower = key_path.lower()
                for pkey in PERSISTENCE_KEYS:
                    if pkey.lower() in path_lower:
                        for v in values:
                            data_str = str(v.get("data") or "").strip()
                            vname = str(v.get("value_name") or "").strip()
                            # Skip empty or default-only entries with no data
                            if not data_str and vname in ("", "(Default)"):
                                continue
                            sig = (key_path.lower(), vname.lower(), data_str.lower())
                            if sig in seen_sig:
                                continue
                            seen_sig.add(sig)
                            results.append({
                                "persistence_key": pkey,
                                "hive":       hive,
                                "key_path":   key_path,
                                "value_name": vname,
                                "type":       v.get("type", ""),
                                "data":       data_str,
                                "last_write": v.get("last_write", ""),
                            })
                        break

        # Deduplicate across flat + tree search results
        deduped, seen_final = [], set()
        for r in results:
            ent = r.get("entry", {})
            vname = str(r.get("value_name") or
                        ent.get("Value Name", "") or ent.get("Name", "") or "")
            data  = str(r.get("data") or ent.get("Data", "") or ent.get("data", "") or "")
            sig = (vname.lower(), data.lower()[:80])
            if sig not in seen_final:
                seen_final.add(sig)
                deduped.append(r)

        self.log.info("Persistence: %d entries match known keys", len(deduped))
        return deduped

    # ── Search ────────────────────────────────────────────────────────────────

    def search(self, pattern: str) -> Dict[str, List[Dict]]:
        pat = pattern.lower()
        results: Dict[str, List[Dict]] = {}
        for source_name, data in [
            ("hivelist",   self._hives),
            ("userassist", self._userassist),
            ("shellbags",  self._shellbags),
            ("shimcache",  self._shimcache),
            ("printkey",   self._printkey),
        ]:
            matches = [e for e in data
                       if pat in " ".join(str(v).lower() for v in e.values())]
            if matches:
                results[source_name] = matches
        return results

    # ── Tree rendering ────────────────────────────────────────────────────────

    def render_tree(self, max_keys: int = 300) -> str:
        """MemProcFS-style ASCII hierarchy of printkey data."""
        if not self._key_tree:
            return "  (no printkey data available)\n"
        lines = []
        for hive in sorted(self._key_tree):
            lines.append(f"\n╔══ {hive} ══╗")
            keys = self._key_tree[hive]
            key_list = sorted(keys.keys())[:max_keys]
            for i, key_path in enumerate(key_list):
                is_last_key = (i == len(key_list) - 1)
                k_branch = "└─" if is_last_key else "├─"
                lines.append(f"  {k_branch} {key_path}")
                indent = "   " if is_last_key else "│  "
                values = keys[key_path]
                for j, v in enumerate(values):
                    is_last_val = (j == len(values) - 1)
                    v_branch = "└─" if is_last_val else "├─"
                    name   = v.get("value_name", "(Default)")
                    vtype  = v.get("type", "")
                    data   = v.get("data", "")
                    lw     = v.get("last_write", "")
                    lw_str = f"  ← {lw}" if lw else ""
                    type_str = f"[{vtype}]  " if vtype else ""
                    lines.append(
                        f"  {indent}  {v_branch}  {name}  "
                        f"{type_str}= {data[:140]}{lw_str}"
                    )
            if len(keys) > max_keys:
                lines.append(
                    f"  ... and {len(keys) - max_keys} more keys (see JSON)")
        return "\n".join(lines) + "\n"

    # ── Report writer ─────────────────────────────────────────────────────────

    def write_report(self, output_dir: Path) -> Path:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        txt_path  = output_dir / "registry_report.txt"
        json_dir  = output_dir / "json"
        json_dir.mkdir(parents=True, exist_ok=True)
        json_path = json_dir / "registry_report.json"

        persistence = self.find_persistence()
        services    = self.get_services_summary()

        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("  REGISTRY EXPLORER REPORT\n")
            f.write(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")

            # Hives
            f.write("─" * 80 + "\n  REGISTRY HIVES\n" + "─" * 80 + "\n\n")
            if self._hives:
                for h in self._hives:
                    virt = _gv(h, "Virtual", "Offset(V)", "VirtualOffset") or ""
                    phys = _gv(h, "Physical", "Offset(P)", "Offset", "offset") or ""
                    name = _gv(h, "Name", "name", "Path", "FileFullPath") or ""
                    size = _gv(h, "Size", "size") or ""
                    f.write(f"  Name    : {name}\n")
                    if virt:  f.write(f"  Virtual : {virt}\n")
                    if phys:  f.write(f"  Physical: {phys}\n")
                    if size:  f.write(f"  Size    : {size}\n")
                    f.write("\n")
            else:
                f.write("  No hive data available.\n\n")

            # Key tree
            f.write("─" * 80 + "\n  REGISTRY KEY TREE (printkey — MemProcFS style)\n"
                    + "─" * 80 + "\n")
            f.write(self.render_tree())
            f.write("\n")

            # Persistence
            f.write("─" * 80 + f"\n  PERSISTENCE INDICATORS ({len(persistence)})\n"
                    + "─" * 80 + "\n\n")
            if persistence:
                for p in persistence:
                    f.write(f"  ► {p['persistence_key']}\n")
                    if "hive" in p:
                        f.write(f"    Path  : {p.get('hive', '')}\\{p.get('key_path', '')}\n")
                        f.write(f"    Value : {p.get('value_name', '')}  "
                                f"[{p.get('type', '')}]  =  {p.get('data', '')[:200]}\n")
                        if p.get("last_write"):
                            f.write(f"    Write : {p['last_write']}\n")
                    else:
                        for k, v in p["entry"].items():
                            if k not in ("__children", "raw"):
                                val = str(v)
                                f.write(f"    {k}: {val[:120]}\n")
                    f.write("  " + "─" * 40 + "\n")
            else:
                f.write("  No persistence entries found.\n")
            f.write("\n")

            # Services
            f.write("─" * 80 + f"\n  WINDOWS SERVICES ({len(services)})\n"
                    + "─" * 80 + "\n\n")
            if services:
                running = [s for s in services if "running" in s.get("state", "").lower()]
                other   = [s for s in services if s not in running]
                for group, label in ((running, "RUNNING"), (other, "OTHER")):
                    if not group:
                        continue
                    f.write(f"  [{label}]\n")
                    for svc in group:
                        f.write(f"    {svc['name']}")
                        if svc.get("display") and svc["display"] != svc["name"]:
                            f.write(f"  ({svc['display']})")
                        f.write(f"  | State: {svc['state']}"
                                f"  Start: {svc['start']}"
                                f"  Type: {svc['type']}\n")
                        if svc.get("binary"):
                            f.write(f"      Binary: {svc['binary'][:200]}\n")
                        if svc.get("pid"):
                            f.write(f"      PID: {svc['pid']}\n")
                    f.write("\n")
            else:
                f.write("  No service data available.\n\n")

            # UserAssist
            f.write("─" * 80 + f"\n  USERASSIST ({len(self._userassist)})\n"
                    + "─" * 80 + "\n\n")
            if self._userassist:
                for entry in self._userassist[:60]:
                    name  = _gv(entry, "Name", "Value", "name", "Path") or ""
                    count = _gv(entry, "Count", "count", "ID") or ""
                    last  = _gv(entry, "Last Write", "LastWrite",
                                "Last Updated", "FocusCount") or ""
                    raw   = _gv(entry, "raw") or ""
                    if raw:
                        f.write(f"  {raw}\n")
                    else:
                        parts_out = [str(name)]
                        if count: parts_out.append(f"Runs: {count}")
                        if last:  parts_out.append(f"Last: {last}")
                        f.write("  " + "  |  ".join(x for x in parts_out if x) + "\n")
                if len(self._userassist) > 60:
                    f.write(f"\n  ... and {len(self._userassist) - 60} more (see JSON)\n")
            else:
                f.write("  No UserAssist data.\n")
            f.write("\n")

            # ShellBags
            f.write("─" * 80 + f"\n  SHELLBAGS ({len(self._shellbags)})\n"
                    + "─" * 80 + "\n\n")
            if self._shellbags:
                for entry in self._shellbags[:60]:
                    path = _gv(entry, "Path", "path", "Value") or ""
                    mod  = _gv(entry, "Modified Date", "Modified", "LastMod") or ""
                    raw  = _gv(entry, "raw") or ""
                    line = raw or path
                    if mod: line += f"  (Modified: {mod})"
                    f.write(f"  {line}\n")
                if len(self._shellbags) > 60:
                    f.write(f"\n  ... and {len(self._shellbags) - 60} more (see JSON)\n")
            else:
                f.write("  No ShellBag data.\n")
            f.write("\n")

            # ShimCache
            f.write("─" * 80 + f"\n  SHIMCACHE ({len(self._shimcache)})\n"
                    + "─" * 80 + "\n\n")
            if self._shimcache:
                for entry in self._shimcache[:60]:
                    path   = _gv(entry, "Path", "path", "File Path") or ""
                    mod    = _gv(entry, "Modified", "Last Modified", "LastMod") or ""
                    execfl = _gv(entry, "Executed", "executed", "Process Executed") or ""
                    raw    = _gv(entry, "raw") or ""
                    line   = raw or path
                    if execfl: line += f"  [Exec: {execfl}]"
                    if mod:    line += f"  (Modified: {mod})"
                    f.write(f"  {line}\n")
                if len(self._shimcache) > 60:
                    f.write(f"\n  ... and {len(self._shimcache) - 60} more (see JSON)\n")
            else:
                f.write("  No ShimCache data.\n")
            f.write("\n" + "=" * 80 + "\n")

        report = {
            "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "summary": {
                "hives":            len(self._hives),
                "userassist":       len(self._userassist),
                "shellbags":        len(self._shellbags),
                "shimcache":        len(self._shimcache),
                "printkey_entries": len(self._printkey),
                "services":         len(services),
                "persistence_hits": len(persistence),
            },
            "hives": self._hives,
            "key_tree": {
                hive: {
                    kp: vals for kp, vals in sorted(keys.items())
                }
                for hive, keys in self._key_tree.items()
            },
            "persistence": [
                {
                    "key": p.get("persistence_key", ""),
                    "hive": p.get("hive", ""),
                    "key_path": p.get("key_path", ""),
                    "value_name": p.get("value_name", ""),
                    "type": p.get("type", ""),
                    "data": p.get("data", ""),
                    "last_write": p.get("last_write", ""),
                }
                for p in persistence
            ],
            "services":   services,
            "userassist": self._userassist,
            "shellbags":  self._shellbags,
            "shimcache":  self._shimcache,
        }
        json_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        self.log.info("Registry report: %s, %s", txt_path, json_path)
        return txt_path
