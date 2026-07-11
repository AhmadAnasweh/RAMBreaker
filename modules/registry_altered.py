"""CresCent RAM Forensics Toolkit - Registry Alteration Scanner

Scans registry artifacts from memory to identify recently modified or
altered registry entries. Works from Volatility JSON output — no raw hive
access required.

Sources examined:
  - printkey:   per-key last-write timestamps from windows.registry.printkey
  - hivelist:   hive last-write times (Vol3 windows.registry.hivelist)
  - userassist: UserAssist run counts and last-updated timestamps
  - shellbags:  folder access timestamps
  - shimcache:  application execution and file-modified times
  - hivescan:   orphan/unlinked hives that may indicate tampering
"""

import json
import logging
import re
from datetime import datetime, timezone
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


# Registry keys associated with persistence and common attack targets
_SENSITIVE_PATHS = [
    r"CurrentVersion\Run",
    r"CurrentVersion\RunOnce",
    r"CurrentVersion\RunServices",
    r"CurrentVersion\Winlogon",
    r"CurrentVersion\Image File Execution Options",
    r"CurrentVersion\AppInit_DLLs",
    r"CurrentVersion\ShellServiceObjectDelayLoad",
    r"CurrentVersion\Policies\Explorer\Run",
    r"Wow6432Node\CurrentVersion\Run",
    r"Schedule\TaskCache",
    r"Security\SAM",
    r"System\CurrentControlSet\Services",
    r"System\CurrentControlSet\Control\Session Manager",
    r"System\CurrentControlSet\Control\SafeBoot",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
    r"SYSTEM\CurrentControlSet\Control\Lsa",
]

_TS_FIELDS = (
    "Last Write Time", "LastWrite", "LastWriteTime", "Last Updated",
    "Modified Date", "Modified", "LastMod", "Timestamp", "timestamp",
    "Time", "time", "Date", "date",
)


def _parse_timestamp(ts_str: str) -> Optional[datetime]:
    """Try to parse a timestamp string in common Volatility formats."""
    if not ts_str:
        return None
    ts = ts_str.strip()
    # Filter obviously empty or placeholder values
    if ts in ("N/A", "0", "None", "-", "", "0001-01-01", "1601-01-01"):
        return None
    fmts = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S.%f",
        "%m/%d/%Y %H:%M:%S",
        "%Y-%m-%d",
    ]
    # Strip timezone offset for parsing
    ts_clean = re.sub(r"([+-]\d{2}:?\d{2}|Z)$", "", ts).strip()
    for fmt in fmts:
        try:
            return datetime.strptime(ts_clean, fmt)
        except ValueError:
            continue
    return None


_VOL2_UA_RE = re.compile(r'^REG_\w+\s+(.+?)\s*:$')


def _vol2_ua_name(entry: Dict) -> str:
    """Extract program name from a Vol2 userassist entry key."""
    for k in entry:
        m = _VOL2_UA_RE.match(str(k))
        if m:
            return m.group(1).strip()
    return ""


def _vol2_ua_ts(entry: Dict) -> Tuple[Optional[datetime], str]:
    """Extract 'Last updated' timestamp from a Vol2 userassist entry value."""
    for v in entry.values():
        sv = str(v).strip()
        if sv.lower().startswith("last updated:"):
            raw = sv.split(":", 1)[1].strip()
            parsed = _parse_timestamp(raw)
            if parsed:
                return parsed, raw
    return None, ""


def _get_ts(entry: Dict) -> Tuple[Optional[datetime], str]:
    """Return (parsed_datetime, raw_string) from an entry's timestamp field."""
    # Standard Vol3 / structured format
    for field in _TS_FIELDS:
        raw = _gv(entry, field)
        if raw:
            raw_str = str(raw).strip()
            parsed = _parse_timestamp(raw_str)
            if parsed:
                return parsed, raw_str
    # Vol2 userassist: timestamp is in the value string
    ts, raw = _vol2_ua_ts(entry)
    if ts:
        return ts, raw
    return None, ""


def _is_sensitive(text: str) -> Optional[str]:
    """Return the matching sensitive path, or None if no match."""
    text_lower = text.lower()
    for sp in _SENSITIVE_PATHS:
        if sp.lower() in text_lower:
            return sp
    return None


class RegistryAlteredScanner:
    """Find recently modified or suspicious registry changes from Volatility output."""

    def __init__(self, logger: logging.Logger):
        self.log = logger
        self._printkey: List[Dict] = []
        self._hivelist: List[Dict] = []
        self._hivescan: List[Dict] = []
        self._userassist: List[Dict] = []
        self._shellbags: List[Dict] = []
        self._shimcache: List[Dict] = []

    def scan(self, output_dir: Path) -> Dict[str, Any]:
        """Scan registry artifacts for modifications.

        Args:
            output_dir: Analysis output directory containing json/ subdirectory.

        Returns:
            Dict with categorized findings.
        """
        jd = output_dir / "json"
        if not jd.is_dir():
            self.log.error("No json/ directory: %s", jd)
            return {}

        self._printkey = load_json_by_pattern(jd, "printkey")
        self._hivelist = load_json_by_pattern(jd, "hivelist")
        self._hivescan = load_json_by_pattern(jd, "hivescan")
        self._userassist = load_json_by_pattern(jd, "userassist")
        self._shellbags = load_json_by_pattern(jd, "shellbags")
        self._shimcache = load_json_by_pattern(jd, "shimcache")

        self.log.info("Registry alteration scan: printkey=%d hivelist=%d "
                      "userassist=%d shellbags=%d shimcache=%d hivescan=%d",
                      len(self._printkey), len(self._hivelist),
                      len(self._userassist), len(self._shellbags),
                      len(self._shimcache), len(self._hivescan))

        sensitive_hits = self._find_sensitive_keys()
        recent_writes = self._find_recent_writes()
        hive_info = self._analyze_hives()
        userassist_timeline = self._timeline_userassist()
        shimcache_recent = self._recent_shimcache()
        shellbags_recent = self._recent_shellbags()
        anomalies = self._detect_anomalies()

        total = (len(sensitive_hits) + len(recent_writes) +
                 len(userassist_timeline) + len(anomalies))

        return {
            "sensitive_key_hits": sensitive_hits,
            "recent_writes": recent_writes,
            "hive_info": hive_info,
            "userassist_timeline": userassist_timeline,
            "shimcache_recent": shimcache_recent,
            "shellbags_recent": shellbags_recent,
            "anomalies": anomalies,
            "total_findings": total,
        }

    def _find_sensitive_keys(self) -> List[Dict]:
        hits = []
        for entry in self._printkey:
            all_text = json.dumps(entry, default=str)
            match = _is_sensitive(all_text)
            if match:
                key = str(_gv(entry, "Key", "key", "Path", "Subkey", "Name") or "")
                val = str(_gv(entry, "Value", "value", "Data", "data") or "")
                _, ts_raw = _get_ts(entry)
                hits.append({
                    "sensitive_path": match,
                    "key": key,
                    "value": val[:300],
                    "last_write": ts_raw,
                })
        self.log.info("Sensitive key hits: %d", len(hits))
        return hits

    def _find_recent_writes(self) -> List[Dict]:
        """Collect all printkey entries that have a parseable timestamp, sorted newest-first."""
        timestamped = []
        for entry in self._printkey:
            ts, ts_raw = _get_ts(entry)
            if not ts:
                continue
            key = str(_gv(entry, "Key", "key", "Path", "Subkey", "Name") or "")
            val = str(_gv(entry, "Value", "value", "Data", "data") or "")
            is_sensitive = bool(_is_sensitive(key + " " + val))
            timestamped.append({
                "key": key,
                "value": val[:200],
                "last_write": ts_raw,
                "_ts": ts,
                "sensitive": is_sensitive,
            })
        # Sort newest first
        timestamped.sort(key=lambda x: x["_ts"], reverse=True)
        # Remove internal sort key before returning
        for item in timestamped:
            item.pop("_ts", None)
        return timestamped[:100]  # Cap at 100 to keep report readable

    def _analyze_hives(self) -> List[Dict]:
        info = []
        for h in self._hivelist:
            offset = str(_gv(h, "Virtual", "virtual", "Offset", "offset",
                              "Offset(V)", "Physical") or "")
            name = str(_gv(h, "Name", "name", "Path",
                           "FileFullPath", "HiveName") or "")
            ts, ts_raw = _get_ts(h)
            info.append({
                "offset": offset,
                "name": name,
                "last_write": ts_raw or "N/A",
                "sensitive": bool(_is_sensitive(name)),
            })
        # Also include hivescan entries (may reveal orphan/unlinked hives)
        for h in self._hivescan:
            offset = str(_gv(h, "Offset", "offset") or "")
            name = str(_gv(h, "Name", "name", "Path", "HiveName") or "")
            if name:
                info.append({
                    "offset": offset,
                    "name": name,
                    "last_write": "N/A",
                    "source": "hivescan",
                    "note": "Found via pool scan — may be unlinked/orphan hive",
                })
        return info

    def _timeline_userassist(self) -> List[Dict]:
        # Normalize Vol2 and Vol3 formats into (name, count, ts, ts_raw)
        records: Dict[str, Dict] = {}  # keyed by program name

        for entry in self._userassist:
            # Vol2 format: single-key dict with "REG_TYPE   Name :" key
            vol2_name = _vol2_ua_name(entry)
            if vol2_name:
                if vol2_name not in records:
                    records[vol2_name] = {"name": vol2_name, "count": "",
                                          "last_updated": "", "_ts": datetime.min}
                # Extract count from value
                for v in entry.values():
                    sv = str(v).strip()
                    if sv.startswith("Count:"):
                        records[vol2_name]["count"] = sv.split(":", 1)[1].strip()
                    elif sv.lower().startswith("last updated:"):
                        raw = sv.split(":", 1)[1].strip()
                        parsed = _parse_timestamp(raw)
                        if parsed:
                            records[vol2_name]["last_updated"] = raw
                            records[vol2_name]["_ts"] = parsed
                continue

            # Vol3 / structured format
            ts, ts_raw = _get_ts(entry)
            name = str(_gv(entry, "Name", "Value", "name",
                           "Hive Name", "Path", "raw") or "")
            count = str(_gv(entry, "Count", "count", "ID") or "")
            if name and name not in records:
                records[name] = {
                    "name": name, "count": count,
                    "last_updated": ts_raw, "_ts": ts or datetime.min,
                }

        timestamped = list(records.values())
        timestamped.sort(key=lambda x: x["_ts"], reverse=True)
        for item in timestamped:
            item.pop("_ts", None)
        return timestamped[:50]

    def _recent_shimcache(self) -> List[Dict]:
        timestamped = []
        for entry in self._shimcache:
            ts, ts_raw = _get_ts(entry)
            path = str(_gv(entry, "Path", "path", "File Path") or "")
            raw = str(_gv(entry, "raw") or "")
            display = path or raw
            if display:
                timestamped.append({
                    "path": display,
                    "modified": ts_raw,
                    "_ts": ts or datetime.min,
                })
        timestamped.sort(key=lambda x: x["_ts"], reverse=True)
        for item in timestamped:
            item.pop("_ts", None)
        return timestamped[:50]

    def _recent_shellbags(self) -> List[Dict]:
        timestamped = []
        for entry in self._shellbags:
            ts, ts_raw = _get_ts(entry)
            path = str(_gv(entry, "Path", "path", "Value") or "")
            raw = str(_gv(entry, "raw") or "")
            display = path or raw
            if display:
                timestamped.append({
                    "path": display,
                    "modified": ts_raw,
                    "_ts": ts or datetime.min,
                })
        timestamped.sort(key=lambda x: x["_ts"], reverse=True)
        for item in timestamped:
            item.pop("_ts", None)
        return timestamped[:50]

    def _detect_anomalies(self) -> List[Dict]:
        anomalies = []

        # Hivescan entries not in hivelist (orphan hives)
        hivelist_names = {str(_gv(h, "Name", "name", "Path",
                                  "FileFullPath") or "").lower()
                          for h in self._hivelist}
        for h in self._hivescan:
            name = str(_gv(h, "Name", "name", "Path") or "").lower()
            if name and name not in hivelist_names:
                anomalies.append({
                    "type": "orphan_hive",
                    "description": "Hive found by pool scan but not in hivelist — "
                                   "may be unlinked or hidden",
                    "name": name,
                    "offset": str(_gv(h, "Offset", "offset") or ""),
                })

        # Multiple hives with same name (possible hive injection)
        name_counts: Dict[str, int] = {}
        for h in self._hivelist:
            name = str(_gv(h, "Name", "name", "FileFullPath") or "").lower()
            if name:
                name_counts[name] = name_counts.get(name, 0) + 1
        for name, count in name_counts.items():
            if count > 1:
                anomalies.append({
                    "type": "duplicate_hive",
                    "description": f"Hive name appears {count} times in hivelist",
                    "name": name,
                    "count": count,
                })

        # Suspicious values in printkey sensitive paths
        for entry in self._printkey:
            val = str(_gv(entry, "Value", "value", "Data", "data") or "")
            key = str(_gv(entry, "Key", "key", "Path", "Name") or "")
            if _is_sensitive(key) and val:
                # Flag executable paths in Run keys
                if (re.search(r"\.(exe|dll|bat|ps1|vbs|js|cmd|scr|hta|com)\b",
                               val, re.IGNORECASE)
                        and _is_sensitive(key)):
                    anomalies.append({
                        "type": "executable_in_run_key",
                        "description": "Executable path found in autorun registry key",
                        "key": key,
                        "value": val[:200],
                    })

        self.log.info("Registry anomalies: %d", len(anomalies))
        return anomalies

    def write_report(self, output_dir: Path, results: Dict) -> Path:
        """Write registry alteration report (TXT + JSON).

        Args:
            output_dir: Analysis output directory.
            results: Results dict from scan().

        Returns:
            Path to TXT report.
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        txt_path = output_dir / "registry_altered.txt"
        json_dir = output_dir / "json"
        json_dir.mkdir(parents=True, exist_ok=True)
        json_path = json_dir / "registry_altered.json"

        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("  REGISTRY ALTERATION REPORT\n")
            f.write(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("  NOTE: Raw observations — no automated threat assessments.\n")
            f.write("=" * 80 + "\n\n")

            # Anomalies first — highest priority
            f.write("=" * 80 + "\n")
            f.write(f"  ANOMALIES ({len(results['anomalies'])})\n")
            f.write("=" * 80 + "\n\n")
            if results["anomalies"]:
                for a in results["anomalies"]:
                    f.write(f"  [{a.get('type', 'unknown').upper()}]\n")
                    f.write(f"    Description: {a.get('description', '')}\n")
                    for k, v in a.items():
                        if k not in ("type", "description"):
                            f.write(f"    {k:16s}: {str(v)[:200]}\n")
                    f.write("-" * 40 + "\n")
            else:
                f.write("  No anomalies detected.\n")
            f.write("\n")

            # Sensitive key hits
            f.write("=" * 80 + "\n")
            f.write(f"  SENSITIVE REGISTRY KEY HITS ({len(results['sensitive_key_hits'])})\n")
            f.write("=" * 80 + "\n\n")
            if results["sensitive_key_hits"]:
                for hit in results["sensitive_key_hits"]:
                    f.write(f"  Path:       {hit.get('sensitive_path', '')}\n")
                    f.write(f"  Key:        {hit.get('key', '')[:150]}\n")
                    if hit.get("value"):
                        f.write(f"  Value:      {hit['value'][:150]}\n")
                    if hit.get("last_write"):
                        f.write(f"  Last Write: {hit['last_write']}\n")
                    f.write("-" * 40 + "\n")
            else:
                f.write("  None found (no printkey data or no sensitive paths matched).\n")
            f.write("\n")

            # Hive info
            f.write("=" * 80 + "\n")
            f.write(f"  REGISTRY HIVES ({len(results['hive_info'])})\n")
            f.write("=" * 80 + "\n\n")
            for h in results["hive_info"]:
                marker = " [SENSITIVE]" if h.get("sensitive") else ""
                f.write(f"  {h.get('offset', ''):20s}  {h.get('name', '')}{marker}\n")
                if h.get("last_write") and h["last_write"] != "N/A":
                    f.write(f"    Last Write: {h['last_write']}\n")
                if h.get("note"):
                    f.write(f"    NOTE: {h['note']}\n")
            f.write("\n")

            # Recent writes (top 30)
            recent = results.get("recent_writes", [])
            f.write("=" * 80 + "\n")
            f.write(f"  RECENT REGISTRY WRITES (top {min(30, len(recent))} of "
                    f"{len(recent)} timestamped entries)\n")
            f.write("=" * 80 + "\n\n")
            for entry in recent[:30]:
                sens = " [SENSITIVE]" if entry.get("sensitive") else ""
                f.write(f"  {entry.get('last_write', ''):26s}  "
                        f"{entry.get('key', '')[:80]}{sens}\n")
                if entry.get("value"):
                    f.write(f"    Value: {entry['value'][:100]}\n")
            if not recent:
                f.write("  No timestamped printkey entries found.\n")
            f.write("\n")

            # UserAssist timeline
            ua = results.get("userassist_timeline", [])
            f.write("=" * 80 + "\n")
            f.write(f"  USERASSIST EXECUTION TIMELINE (top {min(30, len(ua))} "
                    f"of {len(ua)})\n")
            f.write("=" * 80 + "\n\n")
            for entry in ua[:30]:
                f.write(f"  {entry.get('last_updated', ''):26s}  "
                        f"[count: {entry.get('count', '?'):4s}]  "
                        f"{entry.get('name', '')[:80]}\n")
            if not ua:
                f.write("  No UserAssist data.\n")
            f.write("\n")

            # ShimCache recent
            sc = results.get("shimcache_recent", [])
            f.write("=" * 80 + "\n")
            f.write(f"  SHIMCACHE (APP EXECUTION HISTORY — top {min(20, len(sc))} "
                    f"of {len(sc)})\n")
            f.write("=" * 80 + "\n\n")
            for entry in sc[:20]:
                f.write(f"  {entry.get('modified', ''):26s}  "
                        f"{entry.get('path', '')[:80]}\n")
            if not sc:
                f.write("  No ShimCache data.\n")
            f.write("\n")

            # ShellBags recent
            sb = results.get("shellbags_recent", [])
            f.write("=" * 80 + "\n")
            f.write(f"  SHELLBAGS (FOLDER ACCESS — top {min(20, len(sb))} "
                    f"of {len(sb)})\n")
            f.write("=" * 80 + "\n\n")
            for entry in sb[:20]:
                f.write(f"  {entry.get('modified', ''):26s}  "
                        f"{entry.get('path', '')[:80]}\n")
            if not sb:
                f.write("  No ShellBag data.\n")
            f.write("\n")

            f.write("=" * 80 + "\n  SUMMARY\n" + "=" * 80 + "\n\n")
            f.write(f"  Anomalies detected:        {len(results['anomalies'])}\n")
            f.write(f"  Sensitive key hits:        {len(results['sensitive_key_hits'])}\n")
            f.write(f"  Hives analyzed:            {len(results['hive_info'])}\n")
            f.write(f"  Timestamped key writes:    {len(results['recent_writes'])}\n")
            f.write(f"  UserAssist entries:        {len(results['userassist_timeline'])}\n")
            f.write(f"  ShimCache entries:         {len(results['shimcache_recent'])}\n")
            f.write(f"  ShellBag entries:          {len(results['shellbags_recent'])}\n\n")
            f.write("=" * 80 + "\n  END\n" + "=" * 80 + "\n")

        json_path.write_text(
            json.dumps(results, indent=2, default=str), encoding="utf-8")
        self.log.info("Registry alteration report: %s  JSON: %s", txt_path, json_path)
        return txt_path
