"""
CresCent RAM Forensics Toolkit v4.0 - Evidence Timeline

Unified chronological view of ALL timestamped evidence:
  - Process creation + exit + command lines
  - Network connections (netscan + netstat + Vol2 connscan/connections)
  - ShimCache execution evidence (Vol3 + Vol2)
  - UserAssist (user-executed programs)
  - MFT file creation/modification            [Windows]
  - Page-cache + lsof file times              [Linux]
  - Services
  - EVTX parsed events

Output:
  timeline.txt   — Human-readable with narrative context
  timeline.csv   — For spreadsheet/SIEM import
  timeline.json  — Machine-readable

OS coverage note (why the Linux loaders exist)
----------------------------------------------
Five of this module's sources — shimcache, userassist, mftscan, svcscan, evtx —
are Windows-only plugins. On a Linux image the ONLY source that ever produced
events was `pslist`'s CREATION TIME, and Vol3 derives that from the boot time
(`task.get_create_time()` -> `get_boottime()`), which returns None whenever the
kernel's timekeeping symbols aren't recoverable. When that happens the entire
timeline collapses to **zero events** on an otherwise perfectly healthy run —
observed on kali-linux-2026.1 (19/19 plugins OK, 358 processes, 0 timeline
events), while a 2026-07-06 Kali run on an older kernel produced 303.

That single point of failure is the real defect: Linux images carry tens of
thousands of file timestamps that were simply never wired up. `_load_pagecache`
(the MFT analogue) and the file half of `_load_lsof_files` give the Linux
timeline independent sources, so losing process times degrades it instead of
emptying it.

macOS is NOT affected the same way: `mac.pslist` reports `Start Time` from
`proc.p_start`, an absolute wall-clock value with no boot-time dependency, and
`_load_processes` already accepts that column. macOS has no file-time source at
all, though — `mac.list_files` emits only (Address, File Path) and the bundled
`mac.pagecache` only (Vnode, Path, Size, CachedPages, CachedBytes) — so its
timeline is process/network events only, and there is nothing to wire up without
changing a Volatility plugin.
"""

import csv
import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from utils.json_converter import load_json_by_pattern

# A Linux page-cache walk yields one row per cached inode — ~35k on a 16 GB
# desktop image, ~66k events once A/M/C times are split out. That is legitimate
# evidence (a real filesystem timeline is large), so this cap exists only to
# bound a pathological image (a busy server can cache an order of magnitude
# more), NOT to trim the normal case: a cap that engages routinely would be
# silently discarding ordinary evidence. Sized ~3x the observed desktop figure.
# When it does engage it keeps the **most recent** events (recent filesystem
# activity is what triage wants), logs a warning, and states the trim in the
# timeline.txt header — never a silent drop. The complete untrimmed data always
# remains in json/linux_pagecache_Files.json.
MAX_FILE_EVENTS = 200000


def _gv(item, *keys):
    # Exact match first
    for k in keys:
        if k in item:
            return item[k]
    # Case-insensitive fallback (Vol2/Vol3 column name variations)
    lower_map = {str(k).lower(): k for k in item}
    for k in keys:
        lk = str(k).lower()
        if lk in lower_map:
            return item[lower_map[lk]]
    return None


def _parse_ts(raw) -> Optional[str]:
    """Try to parse a timestamp into ISO format. Returns None if unparsable."""
    if not raw or raw == "N/A" or raw == "-" or raw == "0":
        return None
    s = str(raw).strip()
    # Filter known placeholder/epoch values that aren't real evidence:
    #   1601-01-01 = Windows FILETIME zero
    #   1970-01-01 = Unix epoch zero
    #   1980-01-01 = FAT filesystem epoch (appears in some MFT records)
    #   0001-01-01 = .NET DateTime.MinValue
    if (s.startswith("1970-") or s.startswith("0001-")
            or s.startswith("1601-") or s.startswith("1980-01-01")):
        return None
    # Normalise an ISO-ish stamp to "YYYY-MM-DD[T ]HH:MM:SS[.mmm]".
    # A blind s[:23] slice used to cut Vol3's Linux format
    # "2013-09-30T00:18:35+00:00" (25 chars) down to "2013-09-30T00:18:35+00:" —
    # a half-severed timezone offset that breaks strict CSV/SIEM parsers. Match
    # the parts explicitly instead: keep the datetime (+ milliseconds) and drop
    # the offset, which is always UTC in Volatility output.
    m = re.match(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})(\.\d+)?", s)
    if m:
        return m.group(1) + (m.group(2) or "")[:4]
    if re.match(r"\d{4}-\d{2}-\d{2}", s):
        return s[:23]
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f",
                "%Y-%m-%d %H:%M:%S UTC", "%m/%d/%Y %H:%M:%S",
                "%a %b %d %H:%M:%S %Y"):
        try:
            return datetime.strptime(s[:26], fmt).isoformat(sep=" ")
        except (ValueError, IndexError):
            continue
    if any(c.isdigit() for c in s) and ("-" in s or "/" in s):
        return s
    return None


def _is_external(ip: str) -> bool:
    """Check if an IP is external (not private/loopback/wildcard)."""
    if not ip or ip in ("0.0.0.0", "*", "::", "127.0.0.1", "::1", ""):
        return False
    if ip.startswith("10.") or ip.startswith("192.168."):
        return False
    if ip.startswith("172."):
        parts = ip.split(".")
        if len(parts) >= 2:
            try:
                second = int(parts[1])
                if 16 <= second <= 31:
                    return False
            except ValueError:
                pass
    if ip.startswith("fe80:") or ip.startswith("::1"):
        return False
    return True


class Timeline:
    """Build unified evidence timeline from all Volatility JSON output."""

    def __init__(self, logger: logging.Logger):
        self.log = logger
        self._events: List[Dict[str, str]] = []
        self._cmdlines: Dict[str, str] = {}  # PID → cmdline
        self._file_events_trimmed = 0        # set by _load_file_times' cap

    def load(self, output_dir: Path) -> int:
        """Load timeline events from all available JSON sources."""
        jd = output_dir / "json"
        if not jd.is_dir():
            self.log.error("No json/ directory")
            return 0

        self._events.clear()
        self._cmdlines.clear()
        self._file_events_trimmed = 0

        # Pre-load cmdlines for enriching process events
        self._load_cmdlines(jd)

        # === PROCESS EVENTS ===
        self._load_processes(jd)

        # === NETWORK EVENTS ===
        self._load_network(jd)

        # === SHIMCACHE (execution evidence) ===
        self._load_shimcache(jd)

        # === USERASSIST (user-executed programs) ===
        self._load_userassist(jd)

        # === MFT (file system timestamps) — Windows ===
        self._load_mft(jd)

        # === Page cache + lsof (file system timestamps) — Linux ===
        self._load_file_times(jd)

        # === SERVICES ===
        self._load_services(jd)

        # === EVTX (parsed event log entries) ===
        self._load_evtx(jd)

        # Sort chronologically
        self._events.sort(key=lambda e: e["timestamp"])
        self.log.info("Timeline: %d events loaded", len(self._events))
        return len(self._events)

    def _load_cmdlines(self, jd: Path):
        """Pre-load process command lines for enrichment."""
        for item in load_json_by_pattern(jd, "cmdline"):
            pid = str(_gv(item, "PID", "pid", "Pid") or "")
            args = str(_gv(item, "Args", "args", "CommandLine", "cmdline") or "").strip()
            if pid and args and args.lower() not in ("n/a", "-"):
                self._cmdlines[pid] = args
        # Linux: cmdlines come from psaux ("Arguments" field)
        for item in load_json_by_pattern(jd, "psaux"):
            pid = str(_gv(item, "PID", "pid", "Pid") or "")
            args = str(_gv(item, "Arguments", "Args", "args", "ARGS") or "").strip()
            if pid and args and args.lower() not in ("n/a", "-") and pid not in self._cmdlines:
                self._cmdlines[pid] = args

    def _load_processes(self, jd: Path):
        """Load process creation and exit events with cmdline context."""
        for p in load_json_by_pattern(jd, "pslist"):
            name = str(_gv(p, "ImageFileName", "Name", "Process", "name", "COMM", "Comm") or "")
            pid = str(_gv(p, "PID", "pid", "Pid") or "")
            ppid = str(_gv(p, "PPID", "ppid", "InheritedFromPID") or "")
            cmdline = self._cmdlines.get(pid, "")

            # Process creation
            ts = _parse_ts(_gv(p, "CreateTime", "Create Time", "createtime",
                               "CREATION TIME", "Creation Time", "Start Time", "start_time",
                               "Start"))
            if ts:
                detail = f"[PID {pid}] {name}"
                if ppid and ppid != "0":
                    detail += f" (parent: {ppid})"
                if cmdline:
                    cmd_short = cmdline[:120] + "..." if len(cmdline) > 120 else cmdline
                    detail += f" | {cmd_short}"
                self._events.append({
                    "timestamp": ts, "source": "pslist",
                    "type": "Process Created", "detail": detail,
                    "pid": pid, "process": name,
                })

            # Process exit
            ts_exit = _parse_ts(_gv(p, "ExitTime", "Exit Time", "exittime", "Exit"))
            if ts_exit:
                self._events.append({
                    "timestamp": ts_exit, "source": "pslist",
                    "type": "Process Exited", "detail": f"[PID {pid}] {name}",
                    "pid": pid, "process": name,
                })

    def _load_network(self, jd: Path):
        """Load network events from ALL network plugins (Windows + Linux)."""
        seen = set()

        def _add_net_event(source, pid, owner, proto, local, lport,
                           foreign, fport, state, ts):
            dedup_key = f"{ts}|{pid}|{local}:{lport}|{foreign}:{fport}"
            if dedup_key in seen:
                return
            seen.add(dedup_key)

            direction = ""
            if state.upper() == "LISTENING":
                direction = "LISTEN"
            elif _is_external(foreign):
                direction = "→ EXTERNAL"
            elif foreign and foreign not in ("0.0.0.0", "*", "::", ""):
                direction = "→"

            detail = f"[PID {pid}] {owner}"
            if proto:
                detail += f" ({proto})"
            detail += f" {local}:{lport}"
            if foreign and foreign not in ("0.0.0.0", "*", "::"):
                detail += f" {direction} {foreign}:{fport}"
            if state and state.upper() != "LISTENING":
                detail += f" [{state}]"
            elif state.upper() == "LISTENING":
                detail += " [LISTENING]"

            event_type = "Network Connection"
            if state.upper() == "LISTENING":
                event_type = "Network Listen"
            elif _is_external(foreign):
                event_type = "Network → External"
            elif state.upper() == "CLOSED":
                event_type = "Network Closed"

            self._events.append({
                "timestamp": ts, "source": source,
                "type": event_type, "detail": detail,
                "pid": pid, "process": owner,
            })

        # Windows sources + Linux sockscan/sockets
        for source in ("netscan", "netstat", "connscan", "connections",
                        "sockscan", "sockets"):
            for n in load_json_by_pattern(jd, source):
                ts = _parse_ts(_gv(n, "Created", "TimeStamp", "created",
                                    "Create Time"))
                if not ts:
                    continue
                _add_net_event(
                    source,
                    str(_gv(n, "PID", "pid", "Pid") or ""),
                    str(_gv(n, "Owner", "owner") or ""),
                    str(_gv(n, "Proto", "Protocol", "proto") or ""),
                    str(_gv(n, "LocalAddr", "Local Address", "LocalAddress", "Local IP") or ""),
                    str(_gv(n, "LocalPort", "Local Port") or ""),
                    str(_gv(n, "ForeignAddr", "Foreign Address", "ForeignAddress", "Remote IP") or ""),
                    str(_gv(n, "ForeignPort", "Foreign Port", "Remote Port") or ""),
                    str(_gv(n, "State", "state") or ""),
                    ts,
                )

        # Linux Vol3 sockstat — different field names
        for n in load_json_by_pattern(jd, "sockstat"):
            ts = _parse_ts(_gv(n, "Created", "created", "TimeStamp"))
            if not ts:
                continue
            _add_net_event(
                "sockstat",
                str(_gv(n, "PID", "pid") or ""),
                str(_gv(n, "Process", "process", "Name", "name") or ""),
                str(_gv(n, "Socket Type", "Type", "Proto", "proto") or "SOCK"),
                str(_gv(n, "Source Addr", "Source Address", "SrcAddr", "LocalAddr") or ""),
                str(_gv(n, "Source Port", "SrcPort", "LocalPort") or ""),
                str(_gv(n, "Destination Addr", "Destination Address",
                        "DstAddr", "ForeignAddr") or ""),
                str(_gv(n, "Destination Port", "DstPort", "ForeignPort") or ""),
                str(_gv(n, "State", "state") or ""),
                ts,
            )

        # Linux lsof — socket entries only (Vol3 fields: Path, Type, Process, PID)
        for entry in load_json_by_pattern(jd, "lsof"):
            path_field = str(_gv(entry, "Path", "Name", "name", "FILE") or "")
            file_type = str(_gv(entry, "Type", "type") or "")
            if not (file_type.upper() in ("SOCK", "IPV4", "IPV6")
                    or "->" in path_field):
                continue
            ts = _parse_ts(_gv(entry, "Accessed", "Modified", "Changed",
                               "Created", "created"))
            if not ts:
                continue
            pid = str(_gv(entry, "PID", "pid") or "")
            proc = str(_gv(entry, "Process", "COMMAND", "Command", "name") or "")
            remote = path_field.split("->")[1].strip() if "->" in path_field else path_field
            _add_net_event("lsof", pid, proc, file_type,
                           "", "", remote, "", "", ts)

    def _load_file_times(self, jd: Path):
        """Linux file-system timeline — the MFT analogue for Linux images.

        Two independent sources, both no-ops when their JSON is absent (so this
        is safe to call on Windows/macOS runs without any OS branching):

          * ``linux.pagecache.Files`` — one row per cached inode, carrying
            ModificationTime / AccessTime / ChangeTime. The bulk source.
          * ``linux.lsof`` non-socket rows — fewer, but each is **attributed to a
            PID**, which page-cache rows are not. Socket rows are skipped here:
            they belong to ``_load_network`` and their times are epoch-0 anyway.

        Timestamps are deduplicated per file exactly as ``_load_mft`` does (only
        emit A/C when they differ from M), which on a real image roughly halves
        the event count without losing information.
        """
        collected: List[Dict[str, str]] = []

        # --- page cache: the bulk of a Linux filesystem timeline ---------------
        for f in load_json_by_pattern(jd, "pagecache"):
            path = str(_gv(f, "FilePath", "File Path", "Path", "path") or "")
            if not path:
                continue
            ftype = str(_gv(f, "FileType", "Type") or "")
            label = f"{path} [{ftype}]" if ftype else path

            ts_m = _parse_ts(_gv(f, "ModificationTime", "Modified", "mtime"))
            ts_a = _parse_ts(_gv(f, "AccessTime", "Accessed", "atime"))
            ts_c = _parse_ts(_gv(f, "ChangeTime", "Changed", "ctime"))

            if ts_m:
                collected.append({
                    "timestamp": ts_m, "source": "pagecache",
                    "type": "File Modified", "detail": label,
                    "pid": "", "process": ""})
            if ts_a and ts_a != ts_m:
                collected.append({
                    "timestamp": ts_a, "source": "pagecache",
                    "type": "File Accessed", "detail": label,
                    "pid": "", "process": ""})
            if ts_c and ts_c != ts_m and ts_c != ts_a:
                collected.append({
                    "timestamp": ts_c, "source": "pagecache",
                    "type": "File Metadata Changed", "detail": label,
                    "pid": "", "process": ""})

        # --- lsof: the same times, but tied to the process holding the fd ------
        for e in load_json_by_pattern(jd, "lsof"):
            ftype = str(_gv(e, "Type", "type") or "")
            path = str(_gv(e, "Path", "Name", "name") or "")
            # Sockets are _load_network's job (and carry epoch-0 times).
            if ftype.upper() in ("SOCK", "IPV4", "IPV6") or "->" in path:
                continue
            if not path:
                continue
            pid = str(_gv(e, "PID", "pid") or "")
            proc = str(_gv(e, "Process", "COMMAND", "Command") or "")
            detail = f"{path} [{ftype}]" if ftype else path
            if proc:
                detail += f" (open by {proc}"
                detail += f" PID {pid})" if pid else ")"

            ts_m = _parse_ts(_gv(e, "Modified", "modified"))
            ts_a = _parse_ts(_gv(e, "Accessed", "accessed"))
            ts_c = _parse_ts(_gv(e, "Changed", "changed"))

            if ts_m:
                collected.append({
                    "timestamp": ts_m, "source": "lsof",
                    "type": "Open File Modified", "detail": detail,
                    "pid": pid, "process": proc})
            if ts_a and ts_a != ts_m:
                collected.append({
                    "timestamp": ts_a, "source": "lsof",
                    "type": "Open File Accessed", "detail": detail,
                    "pid": pid, "process": proc})
            if ts_c and ts_c != ts_m and ts_c != ts_a:
                collected.append({
                    "timestamp": ts_c, "source": "lsof",
                    "type": "Open File Metadata Changed", "detail": detail,
                    "pid": pid, "process": proc})

        # Cap most-recent-first; record the trim so it is never silent.
        if len(collected) > MAX_FILE_EVENTS:
            collected.sort(key=lambda e: e["timestamp"], reverse=True)
            self._file_events_trimmed = len(collected) - MAX_FILE_EVENTS
            self.log.warning(
                "Timeline: %d file events exceed the %d cap — keeping the most "
                "recent %d (full data remains in json/); see timeline.txt header",
                len(collected), MAX_FILE_EVENTS, MAX_FILE_EVENTS)
            collected = collected[:MAX_FILE_EVENTS]

        self._events.extend(collected)

    def _load_shimcache(self, jd: Path):
        """Load ShimCache execution evidence (Vol3 + Vol2)."""
        for s in load_json_by_pattern(jd, "shimcache"):
            ts = _parse_ts(_gv(s, "Modified", "Last Modified", "LastMod",
                               "Modified Date", "Last Modified Date",
                               "Last Update", "LastModified"))
            path = str(_gv(s, "Path", "path", "File Path", "FilePath") or "")
            size = _gv(s, "Size", "size", "File Size")

            if ts and path:
                detail = path
                if size and str(size) != "0" and str(size) != "-1":
                    detail += f" ({size} bytes)"
                self._events.append({
                    "timestamp": ts, "source": "shimcache",
                    "type": "ShimCache (Executed)",
                    "detail": detail,
                    "pid": "", "process": Path(path).name if "\\" in path else path,
                })

    def _load_userassist(self, jd: Path):
        """Load UserAssist execution records."""
        for u in load_json_by_pattern(jd, "userassist"):
            ts = _parse_ts(_gv(u, "Last Write", "LastWrite",
                               "Last Updated", "Timestamp"))
            name = str(_gv(u, "Name", "Value", "name", "Path") or "")
            count = _gv(u, "Count", "count", "ID") or ""
            focus = _gv(u, "Focus Count", "FocusCount") or ""

            if ts and name:
                detail = name
                parts = []
                if count:
                    parts.append(f"count: {count}")
                if focus:
                    parts.append(f"focus: {focus}")
                if parts:
                    detail += f" ({', '.join(parts)})"
                self._events.append({
                    "timestamp": ts, "source": "userassist",
                    "type": "UserAssist (Executed)",
                    "detail": detail,
                    "pid": "", "process": "",
                })

    def _load_mft(self, jd: Path):
        """Load MFT file creation/modification timestamps."""
        for m in load_json_by_pattern(jd, "mftscan"):
            name = str(_gv(m, "FileName", "Filename", "Name",
                           "Record Name") or "")
            if not name:
                continue

            ts_created = _parse_ts(_gv(m, "Created", "Creation",
                                        "creation", "Created Date"))
            if ts_created:
                self._events.append({
                    "timestamp": ts_created, "source": "mftscan",
                    "type": "MFT File Created", "detail": name,
                    "pid": "", "process": "",
                })

            ts_modified = _parse_ts(_gv(m, "Modified", "Modification",
                                         "Modified Date"))
            if ts_modified and ts_modified != ts_created:
                self._events.append({
                    "timestamp": ts_modified, "source": "mftscan",
                    "type": "MFT File Modified", "detail": name,
                    "pid": "", "process": "",
                })

    def _load_services(self, jd: Path):
        """Load service creation/start timestamps."""
        for s in load_json_by_pattern(jd, "svcscan"):
            ts = _parse_ts(_gv(s, "Start", "start", "Created"))
            name = str(_gv(s, "Name", "Service Name", "name") or "")
            binary = str(_gv(s, "Binary", "Binary Path",
                              "BinaryPath", "binary") or "")
            state = str(_gv(s, "State", "state") or "")
            start_type = str(_gv(s, "Start Type", "StartType", "Type") or "")

            if ts and name:
                detail = name
                if binary:
                    detail += f": {binary}"
                if state:
                    detail += f" [{state}]"
                self._events.append({
                    "timestamp": ts, "source": "svcscan",
                    "type": "Service", "detail": detail,
                    "pid": "", "process": name,
                })

    def _load_evtx(self, jd: Path):
        """Load parsed EVTX event log entries."""
        evtx_json = jd / "evtx_report.json"
        if not evtx_json.exists():
            return

        try:
            data = json.loads(evtx_json.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            return

        events = data if isinstance(data, list) else data.get("events", [])
        for e in events:
            ts = _parse_ts(_gv(e, "TimeCreated", "TimeGenerated",
                               "timestamp", "Timestamp", "time"))
            if not ts:
                continue

            eid = str(_gv(e, "EventID", "event_id", "EventId") or "")
            source = str(_gv(e, "Source", "Provider", "Channel") or "EVTX")
            desc = str(_gv(e, "Description", "Message", "detail",
                           "Summary") or "")

            # Shorten description for timeline
            if len(desc) > 200:
                desc = desc[:200] + "..."

            detail = f"Event {eid}"
            if desc:
                detail += f": {desc}"

            self._events.append({
                "timestamp": ts, "source": "evtx",
                "type": f"EVTX [{eid}]", "detail": detail,
                "pid": "", "process": "",
            })

    def filter(self, start: str = "", end: str = "",
               source: str = "", keyword: str = "",
               event_type: str = "") -> List[Dict]:
        """Filter events by time range, source, type, or keyword."""
        result = self._events
        if start:
            result = [e for e in result if e["timestamp"] >= start]
        if end:
            result = [e for e in result if e["timestamp"] <= end]
        if source:
            src = source.lower()
            result = [e for e in result if src in e["source"].lower()]
        if event_type:
            et = event_type.lower()
            result = [e for e in result if et in e["type"].lower()]
        if keyword:
            kw = keyword.lower()
            result = [e for e in result
                      if kw in e["detail"].lower() or kw in e["type"].lower()]
        return result

    def get_process_narrative(self, pid: str) -> List[Dict]:
        """Get all events for a specific PID in chronological order.

        Returns a narrative like:
          19:35:11  Process Created  [PID 1234] svchost.exe (parent: 784)
          19:35:13  Network → External  [PID 1234] svchost.exe → 167.172.227.148:8080
          19:35:15  Process Created  [PID 5678] cmd.exe (parent: 1234)
        """
        return [e for e in self._events
                if e.get("pid") == pid or f"PID {pid}]" in e.get("detail", "")]

    def write_report(self, output_dir: Path) -> Tuple[Path, Path, Path]:
        """Write timeline as TXT, CSV, and JSON."""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        txt_path = output_dir / "timeline.txt"
        csv_path = output_dir / "timeline.csv"
        json_dir = output_dir / "json"
        json_dir.mkdir(parents=True, exist_ok=True)
        json_path = json_dir / "timeline.json"

        # Count by source
        source_counts: Dict[str, int] = {}
        type_counts: Dict[str, int] = {}
        for e in self._events:
            source_counts[e["source"]] = source_counts.get(e["source"], 0) + 1
            type_counts[e["type"]] = type_counts.get(e["type"], 0) + 1

        # TXT — with narrative headers
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("=" * 110 + "\n")
            f.write("  EVIDENCE TIMELINE — CresCent RAM Forensics Toolkit v4.0\n")
            f.write(f"  Total events: {len(self._events)}\n")
            if self._file_events_trimmed:
                f.write(f"  NOTE: {self._file_events_trimmed} older file events "
                        f"were trimmed (cap {MAX_FILE_EVENTS}, most-recent kept). "
                        f"Full data: json/linux_pagecache_Files.json\n")
            f.write("=" * 110 + "\n\n")

            # Summary by source
            f.write("  Sources:\n")
            for src, cnt in sorted(source_counts.items(), key=lambda x: -x[1]):
                f.write(f"    {src:14s}  {cnt:>6d} events\n")
            f.write("\n")

            # Summary by type
            f.write("  Event types:\n")
            for typ, cnt in sorted(type_counts.items(), key=lambda x: -x[1]):
                f.write(f"    {typ:24s}  {cnt:>6d}\n")

            f.write("\n" + "-" * 110 + "\n\n")

            # Timeline entries
            prev_date = ""
            for e in self._events:
                # Add date separator when day changes
                curr_date = e["timestamp"][:10]
                if curr_date != prev_date:
                    if prev_date:
                        f.write("\n")
                    f.write(f"  ── {curr_date} ──\n\n")
                    prev_date = curr_date

                # Mark external network connections
                marker = "  "
                if "External" in e["type"]:
                    marker = "▶ "
                elif "Exited" in e["type"]:
                    marker = "◀ "

                f.write(f"  {marker}{e['timestamp']:26s}  [{e['source']:12s}]  "
                        f"{e['type']:24s}  {e['detail']}\n")

            f.write("\n" + "=" * 110 + "\n")

        # CSV
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            fields = ["timestamp", "source", "type", "detail", "pid", "process"]
            w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            w.writeheader()
            w.writerows(self._events)

        # JSON
        json_path.write_text(
            json.dumps(self._events, indent=2, default=str),
            encoding="utf-8")

        self.log.info("Timeline: %s, %s, %s", txt_path, csv_path, json_path)
        return txt_path, csv_path, json_path

    @property
    def events(self) -> List[Dict[str, str]]:
        return self._events
