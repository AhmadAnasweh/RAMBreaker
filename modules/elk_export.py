"""
CresCent RAM Forensics Toolkit v4.0 - ELK/Kibana Export

Generates NDJSON (Newline-Delimited JSON) files for Elasticsearch bulk import.
Each data type gets its own index and NDJSON file. Import with one curl command
or Kibana's file upload.

Usage after export:
    # Import all at once:
    for f in elk_export/*.ndjson; do
        curl -s -H "Content-Type: application/x-ndjson" \
             -XPOST "http://localhost:9200/_bulk" --data-binary @"$f"
    done

    # Or import one index:
    curl -s -H "Content-Type: application/x-ndjson" \
         -XPOST "http://localhost:9200/_bulk" \
         --data-binary @elk_export/crescent-processes.ndjson

    # Or use Kibana UI: Management → Stack Management → Data → Upload File

Indices created:
    crescent-processes      Process list with cmdline, flags
    crescent-network        Network connections with process mapping
    crescent-timeline       Chronological evidence events
    crescent-iocs           All IOC matches
    crescent-malfind        Injected code detections
    crescent-services       Windows services
    crescent-registry       Registry artifacts (userassist, shimcache, shellbags)
    crescent-evtx           Parsed Windows Event Log entries
    crescent-files          Files found in memory (filescan)
    crescent-suspicious     Flagged suspicious processes
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from utils.json_converter import load_json_by_pattern


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


class ELKExporter:
    """Export all forensic data as NDJSON for Elasticsearch bulk import."""

    def __init__(self, logger: logging.Logger, index_prefix: str = "crescent"):
        """Initialize the ELK exporter.

        Args:
            logger: Logger instance.
            index_prefix: Prefix for all Elasticsearch index names.
                         Default: 'crescent' → indices like 'crescent-processes'.
        """
        self.log = logger
        self.prefix = index_prefix

    def export_all(self, output_dir: Path, elk_dir: Optional[Path] = None) -> Dict[str, int]:
        """Export all available data to NDJSON files.

        Args:
            output_dir: Base analysis output directory.
            elk_dir: Output directory for NDJSON files.
                    Default: <output_dir>/elk_export/

        Returns:
            Dict mapping index name → document count.
        """
        od = Path(output_dir)
        if elk_dir is None:
            elk_dir = od / "elk_export"
        elk_dir = Path(elk_dir)
        elk_dir.mkdir(parents=True, exist_ok=True)

        jd = od / "json"
        counts: Dict[str, int] = {}

        # 1. Processes
        c = self._export_processes(jd, od, elk_dir)
        if c:
            counts[f"{self.prefix}-processes"] = c

        # 2. Network
        c = self._export_network(jd, elk_dir)
        if c:
            counts[f"{self.prefix}-network"] = c

        # 3. Timeline
        c = self._export_timeline(od, elk_dir)
        if c:
            counts[f"{self.prefix}-timeline"] = c

        # 4. IOCs
        c = self._export_iocs(od, elk_dir)
        if c:
            counts[f"{self.prefix}-iocs"] = c

        # 5. Malfind
        c = self._export_malfind(jd, elk_dir)
        if c:
            counts[f"{self.prefix}-malfind"] = c

        # 6. Services
        c = self._export_services(jd, elk_dir)
        if c:
            counts[f"{self.prefix}-services"] = c

        # 7. Registry
        c = self._export_registry(od, elk_dir)
        if c:
            counts[f"{self.prefix}-registry"] = c

        # 8. EVTX
        c = self._export_evtx(od, elk_dir)
        if c:
            counts[f"{self.prefix}-evtx"] = c

        # 9. Files
        c = self._export_files(jd, elk_dir)
        if c:
            counts[f"{self.prefix}-files"] = c

        # 10. Browser History
        c = self._export_browser(od, elk_dir)
        if c:
            counts[f"{self.prefix}-browser"] = c

        # 11. Suspicious
        c = self._export_suspicious(jd, od, elk_dir)
        if c:
            counts[f"{self.prefix}-suspicious"] = c

        # Write import script
        self._write_import_script(elk_dir, counts)

        total = sum(counts.values())
        self.log.info("ELK export: %d documents across %d indices in %s",
                      total, len(counts), elk_dir)
        return counts

    # ------------------------------------------------------------------
    # Individual exporters
    # ------------------------------------------------------------------

    def _export_processes(self, jd: Path, od: Path, elk_dir: Path) -> int:
        """Export process list with cmdline and suspicious flags."""
        if not jd or not jd.is_dir():
            return 0

        pslist = load_json_by_pattern(jd, "pslist")
        if not pslist:
            return 0

        # Build cmdline map
        cmds = {}
        for c in load_json_by_pattern(jd, "cmdline"):
            pid = str(_gv(c, "PID", "pid", "Pid") or "")
            args = str(_gv(c, "Args", "args", "CommandLine") or "")
            if pid:
                cmds[pid] = args

        # Build psscan set for hidden detection
        psscan_pids = set()
        for p in load_json_by_pattern(jd, "psscan"):
            pid = str(_gv(p, "PID", "pid", "Pid") or "")
            if pid:
                psscan_pids.add(pid)
        pslist_pids = set()
        for p in pslist:
            pid = str(_gv(p, "PID", "pid", "Pid") or "")
            if pid:
                pslist_pids.add(pid)

        index = f"{self.prefix}-processes"
        docs = []
        seen = set()

        for p in pslist + load_json_by_pattern(jd, "psscan"):
            pid = str(_gv(p, "PID", "pid", "Pid") or "")
            if not pid or pid in seen:
                continue
            seen.add(pid)

            doc = {
                "pid": int(pid) if pid.isdigit() else pid,
                "name": str(_gv(p, "ImageFileName", "Name", "Process", "name", "COMM", "Comm") or ""),
                "ppid": str(_gv(p, "PPID", "ppid", "Ppid") or ""),
                "threads": _gv(p, "Threads", "threads", "NumberOfThreads"),
                "offset": str(_gv(p, "Offset", "offset") or ""),
                "create_time": str(_gv(p, "CreateTime", "Create Time") or ""),
                "exit_time": str(_gv(p, "ExitTime", "Exit Time") or ""),
                "cmdline": cmds.get(pid, ""),
                "hidden": pid in psscan_pids and pid not in pslist_pids,
                "@timestamp": str(_gv(p, "CreateTime", "Create Time") or
                                  datetime.now().isoformat()),
            }
            docs.append(doc)

        return self._write_ndjson(elk_dir, index, docs)

    def _export_network(self, jd: Path, elk_dir: Path) -> int:
        """Export network connections."""
        if not jd or not jd.is_dir():
            return 0

        docs = []
        index = f"{self.prefix}-network"

        # PID→name map
        pid_names = {}
        for p in load_json_by_pattern(jd, "pslist"):
            pid = str(_gv(p, "PID", "pid", "Pid") or "")
            name = str(_gv(p, "ImageFileName", "Name", "COMM", "Comm") or "")
            if pid:
                pid_names[pid] = name

        for pat in ("netscan", "netstat", "connscan", "connections",
                     "sockscan", "sockets", "sockstat"):
            for n in load_json_by_pattern(jd, pat):
                pid = str(_gv(n, "PID", "pid", "Pid", "Owner Pid") or "")
                # sockstat uses Source/Destination Addr; Windows uses Local/Foreign
                local_addr = str(_gv(n, "LocalAddr", "Local Address",
                                      "LocalAddress", "Local IP", "Source Addr",
                                      "Source Address", "SrcAddr") or "")
                local_port = str(_gv(n, "LocalPort", "Local Port",
                                      "Source Port", "SrcPort") or "")
                remote_addr = str(_gv(n, "ForeignAddr", "Foreign Address",
                                       "RemoteAddr", "Remote IP", "Destination Addr",
                                       "Destination Address", "DstAddr") or "")
                remote_port = str(_gv(n, "ForeignPort", "Foreign Port",
                                       "RemotePort", "Remote Port", "Destination Port",
                                       "DstPort") or "")
                state = str(_gv(n, "State", "state") or "")
                proto = str(_gv(n, "Proto", "Protocol", "proto",
                                 "Socket Type", "Type") or "TCP")
                created = str(_gv(n, "Created", "TimeStamp", "created") or "")

                # Determine if external
                is_external = True
                for prefix in ("127.", "10.", "192.168.", "0.0.0.0",
                                "::", "*", "0:0"):
                    if remote_addr.startswith(prefix):
                        is_external = False
                        break

                doc = {
                    "pid": int(pid) if pid.isdigit() else pid,
                    "process_name": pid_names.get(pid,
                                                   str(_gv(n, "Owner", "owner") or "")),
                    "protocol": proto,
                    "local_address": local_addr,
                    "local_port": int(local_port) if local_port.isdigit() else local_port,
                    "remote_address": remote_addr,
                    "remote_port": int(remote_port) if remote_port.isdigit() else remote_port,
                    "state": state,
                    "source_plugin": pat,
                    "is_external": is_external,
                    "@timestamp": created if created else datetime.now().isoformat(),
                }
                docs.append(doc)

        return self._write_ndjson(elk_dir, index, docs)

    def _export_timeline(self, od: Path, elk_dir: Path) -> int:
        """Export timeline events."""
        tl_json = od / "json" / "timeline.json"
        if not tl_json.exists():
            return 0

        try:
            events = json.loads(tl_json.read_text(encoding="utf-8",
                                                    errors="ignore"))
        except Exception:
            return 0

        index = f"{self.prefix}-timeline"
        docs = []
        for e in events:
            doc = {
                "event_type": e.get("type", ""),
                "source_plugin": e.get("source", ""),
                "detail": e.get("detail", ""),
                "@timestamp": e.get("timestamp", datetime.now().isoformat()),
            }
            docs.append(doc)

        return self._write_ndjson(elk_dir, index, docs)

    def _export_iocs(self, od: Path, elk_dir: Path) -> int:
        """Export all IOC matches."""
        ioc_json = od / "iocs" / "ioc_results.json"
        if not ioc_json.exists():
            return 0

        try:
            data = json.loads(ioc_json.read_text(encoding="utf-8",
                                                   errors="ignore"))
        except Exception:
            return 0

        index = f"{self.prefix}-iocs"
        docs = []
        results = data.get("results", {})
        for ioc_type, info in results.items():
            for value in info.get("values", []):
                doc = {
                    "ioc_type": ioc_type,
                    "ioc_category": info.get("category", ""),
                    "ioc_description": info.get("description", ""),
                    "value": value,
                    "@timestamp": datetime.now().isoformat(),
                }
                docs.append(doc)

        # Also read individual txt files for types not in JSON
        iocs_dir = od / "iocs"
        if iocs_dir.is_dir():
            json_types = set(results.keys())
            for f in iocs_dir.glob("ioc_*.txt"):
                if f.name == "ioc_summary.txt":
                    continue
                ioc_name = f.stem.replace("ioc_", "")
                if ioc_name in json_types:
                    continue
                try:
                    lines = [l.strip() for l in f.read_text(
                        encoding="utf-8", errors="ignore").splitlines()
                             if l.strip() and not l.startswith("#")]
                    for value in lines:
                        docs.append({
                            "ioc_type": ioc_name,
                            "ioc_category": "",
                            "ioc_description": "",
                            "value": value,
                            "@timestamp": datetime.now().isoformat(),
                        })
                except Exception:
                    pass

        return self._write_ndjson(elk_dir, index, docs)

    def _export_malfind(self, jd: Path, elk_dir: Path) -> int:
        """Export malfind detections."""
        if not jd or not jd.is_dir():
            return 0

        malfind = load_json_by_pattern(jd, "malfind")
        if not malfind:
            return 0

        index = f"{self.prefix}-malfind"
        docs = []
        for m in malfind:
            doc = {
                "pid": str(_gv(m, "PID", "pid", "Pid") or ""),
                "process_name": str(_gv(m, "Process", "process", "Name") or ""),
                "address": str(_gv(m, "Address", "Start VPN", "Vad Start") or ""),
                "protection": str(_gv(m, "Protection", "protection") or ""),
                "tag": str(_gv(m, "Tag", "tag") or ""),
                "@timestamp": datetime.now().isoformat(),
            }
            docs.append(doc)

        return self._write_ndjson(elk_dir, index, docs)

    def _export_services(self, jd: Path, elk_dir: Path) -> int:
        """Export Windows services."""
        if not jd or not jd.is_dir():
            return 0

        svcs = load_json_by_pattern(jd, "svcscan")
        if not svcs:
            return 0

        index = f"{self.prefix}-services"
        docs = []
        for s in svcs:
            doc = {
                "name": str(_gv(s, "Name", "Service Name", "name") or ""),
                "display_name": str(_gv(s, "Display", "Display Name",
                                         "display") or ""),
                "state": str(_gv(s, "State", "state") or ""),
                "start_type": str(_gv(s, "Start", "start") or ""),
                "binary_path": str(_gv(s, "Binary", "Binary Path",
                                        "binary") or ""),
                "service_type": str(_gv(s, "Type", "type") or ""),
                "@timestamp": datetime.now().isoformat(),
            }
            docs.append(doc)

        return self._write_ndjson(elk_dir, index, docs)

    def _export_registry(self, od: Path, elk_dir: Path) -> int:
        """Export registry artifacts."""
        reg_json = od / "json" / "registry_report.json"
        if not reg_json.exists():
            return 0

        try:
            data = json.loads(reg_json.read_text(encoding="utf-8",
                                                   errors="ignore"))
        except Exception:
            return 0

        index = f"{self.prefix}-registry"
        docs = []

        # Persistence entries
        for p in data.get("persistence", []):
            doc = {
                "registry_type": "persistence",
                "key_path": p.get("key", ""),
                "data": json.dumps(p.get("data", {}), default=str),
                "is_persistence": True,
                "@timestamp": datetime.now().isoformat(),
            }
            docs.append(doc)

        # UserAssist
        for u in data.get("userassist", []):
            doc = {
                "registry_type": "userassist",
                "name": str(_gv(u, "Name", "Value", "name", "Path") or ""),
                "count": str(_gv(u, "Count", "count", "ID") or ""),
                "last_write": str(_gv(u, "Last Write", "LastWrite") or ""),
                "is_persistence": False,
                "@timestamp": str(_gv(u, "Last Write", "LastWrite") or
                                  datetime.now().isoformat()),
            }
            docs.append(doc)

        # ShimCache
        for s in data.get("shimcache", []):
            doc = {
                "registry_type": "shimcache",
                "path": str(_gv(s, "Path", "path", "File Path") or ""),
                "modified": str(_gv(s, "Modified", "Last Modified") or ""),
                "is_persistence": False,
                "@timestamp": str(_gv(s, "Modified", "Last Modified") or
                                  datetime.now().isoformat()),
            }
            docs.append(doc)

        # ShellBags
        for sb in data.get("shellbags", []):
            doc = {
                "registry_type": "shellbags",
                "path": str(_gv(sb, "Path", "path", "Value") or ""),
                "modified": str(_gv(sb, "Modified Date", "Modified") or ""),
                "is_persistence": False,
                "@timestamp": str(_gv(sb, "Modified Date", "Modified") or
                                  datetime.now().isoformat()),
            }
            docs.append(doc)

        return self._write_ndjson(elk_dir, index, docs)

    def _export_evtx(self, od: Path, elk_dir: Path) -> int:
        """Export parsed EVTX events."""
        evtx_json = od / "json" / "evtx_report.json"
        if not evtx_json.exists():
            return 0

        try:
            events = json.loads(evtx_json.read_text(encoding="utf-8",
                                                      errors="ignore"))
        except Exception:
            return 0

        index = f"{self.prefix}-evtx"
        docs = []
        for e in events:
            doc = dict(e)  # Copy all fields
            # Ensure @timestamp
            if "TimeCreated" in doc:
                doc["@timestamp"] = doc["TimeCreated"]
            elif "@timestamp" not in doc:
                doc["@timestamp"] = datetime.now().isoformat()
            # Clean internal fields
            doc.pop("_interesting", None)
            doc.pop("_description", None)
            # Add description as field
            if e.get("_description"):
                doc["event_description"] = e["_description"]
            if e.get("_interesting"):
                doc["is_security_relevant"] = True
            docs.append(doc)

        return self._write_ndjson(elk_dir, index, docs)

    def _export_files(self, jd: Path, elk_dir: Path) -> int:
        """Export filescan (Windows) or lsof (Linux) file data."""
        if not jd or not jd.is_dir():
            return 0

        # Windows: filescan; Linux: lsof (pagecache file paths); macOS: list_files
        files = load_json_by_pattern(jd, "filescan")
        if not files:
            # Linux fallback: pull real file paths from lsof (exclude sockets/pipes)
            for entry in load_json_by_pattern(jd, "lsof"):
                path = str(_gv(entry, "Path", "Name", "name") or "")
                ftype = str(_gv(entry, "Type", "type") or "")
                if path and ftype in ("REG", "DIR") and not path.startswith("<"):
                    files.append({"Name": path, "Offset": "",
                                  "PID": _gv(entry, "PID", "pid") or "",
                                  "Process": _gv(entry, "Process", "process") or ""})

        if not files:
            # macOS fallback: mac.list_files.List_Files
            for entry in load_json_by_pattern(jd, "list_files"):
                path = str(_gv(entry, "File Path", "Path", "Name", "name") or "")
                if path and not path.startswith("<"):
                    files.append({"Name": path, "Offset": "",
                                  "PID": _gv(entry, "PID", "pid") or "",
                                  "Process": _gv(entry, "Process", "process") or ""})

        if not files:
            return 0

        index = f"{self.prefix}-files"
        docs = []
        for f in files:
            name = str(_gv(f, "Name", "name", "FileName", "File Name", "Path") or "")
            offset = _gv(f, "Offset", "offset", "Offset(P)") or ""
            if isinstance(offset, int):
                offset = hex(offset)

            # Extract just the filename
            short = name.rsplit("\\", 1)[-1] if "\\" in name else name.rsplit("/", 1)[-1]
            # Extract extension
            ext = ("." + short.rsplit(".", 1)[-1].lower()) if "." in short else ""

            doc = {
                "offset": str(offset),
                "full_path": name,
                "filename": short,
                "extension": ext,
                "@timestamp": datetime.now().isoformat(),
            }
            docs.append(doc)

        return self._write_ndjson(elk_dir, index, docs)

    def _export_suspicious(self, jd: Path, od: Path, elk_dir: Path) -> int:
        """Export suspicious process observations."""
        if not jd or not jd.is_dir():
            return 0

        # Rebuild suspicious from process data
        pslist = load_json_by_pattern(jd, "pslist")
        psscan = load_json_by_pattern(jd, "psscan")
        cmdline = load_json_by_pattern(jd, "cmdline")

        cmds = {}
        for c in cmdline:
            pid = str(_gv(c, "PID", "pid", "Pid") or "")
            args = str(_gv(c, "Args", "args", "CommandLine") or "")
            if pid:
                cmds[pid] = args

        pslist_pids = set(str(_gv(p, "PID", "pid", "Pid") or "")
                          for p in pslist)
        psscan_pids = set(str(_gv(p, "PID", "pid", "Pid") or "")
                          for p in psscan)

        # Read the suspicious report if it exists
        sp = od / "suspicious_processes.txt"
        if not sp.exists():
            return 0

        # Parse the suspicious report
        index = f"{self.prefix}-suspicious"
        docs = []
        current = {}
        for line in sp.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line.startswith("PID:"):
                if current:
                    docs.append(current)
                parts = line.split()
                current = {
                    "pid": parts[1] if len(parts) > 1 else "",
                    "flags": [],
                    "@timestamp": datetime.now().isoformat(),
                }
                # Extract name
                for i, p in enumerate(parts):
                    if p == "Name:":
                        current["name"] = parts[i + 1] if i + 1 < len(parts) else ""
            elif line.startswith("PPID:"):
                current["ppid"] = line.split(":")[1].strip() if ":" in line else ""
            elif line.startswith("CmdLine:"):
                current["cmdline"] = line.split(":", 1)[1].strip() if ":" in line else ""
            elif line.startswith("->"):
                current.setdefault("flags", []).append(line[2:].strip())
        if current and current.get("pid"):
            docs.append(current)

        # Convert flags list to string for ELK
        for doc in docs:
            doc["flags_text"] = " | ".join(doc.get("flags", []))
            doc["flag_count"] = len(doc.get("flags", []))

        return self._write_ndjson(elk_dir, index, docs)

    def _export_browser(self, od: Path, elk_dir: Path) -> int:
        """Export browser history."""
        bh_json = od / "iocs" / "json" / "browser_history.json"
        if not bh_json.exists():
            return 0
        try:
            data = json.loads(bh_json.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            return 0

        index = f"{self.prefix}-browser"
        docs = []
        for url in data.get("urls", []):
            cat = ""
            for c, urls in data.get("categories", {}).items():
                if url in urls:
                    cat = c
                    break
            docs.append({
                "url": url,
                "category": cat,
                "@timestamp": datetime.now().isoformat(),
            })
        for s in data.get("searches", []):
            docs.append({
                "url": "",
                "category": "search",
                "search_engine": s.get("engine", ""),
                "search_query": s.get("query", ""),
                "@timestamp": datetime.now().isoformat(),
            })
        return self._write_ndjson(elk_dir, index, docs)

    # ------------------------------------------------------------------
    # NDJSON writer
    # ------------------------------------------------------------------

    def _write_ndjson(self, elk_dir: Path, index: str,
                      docs: List[Dict]) -> int:
        """Write documents as NDJSON for Elasticsearch bulk import.

        Format: alternating action/document lines:
            {"index":{"_index":"crescent-processes"}}
            {"pid":4,"name":"System",...}

        Args:
            elk_dir: Output directory.
            index: Elasticsearch index name.
            docs: List of document dicts.

        Returns:
            Number of documents written.
        """
        if not docs:
            return 0

        path = elk_dir / f"{index}.ndjson"
        with open(path, "w", encoding="utf-8") as f:
            for doc in docs:
                # Action line
                action = json.dumps({"index": {"_index": index}},
                                     default=str)
                f.write(action + "\n")
                # Document line
                f.write(json.dumps(doc, default=str) + "\n")

        self.log.info("  %s: %d documents → %s", index, len(docs), path.name)
        return len(docs)

    # ------------------------------------------------------------------
    # Import helper script
    # ------------------------------------------------------------------

    def _write_import_script(self, elk_dir: Path,
                              counts: Dict[str, int]) -> None:
        """Write a bash script to import all NDJSON files into Elasticsearch."""
        script_path = elk_dir / "import_to_elk.sh"
        with open(script_path, "w", encoding="utf-8") as f:
            f.write("#!/bin/bash\n")
            f.write("# CresCent RAM Forensics Toolkit - ELK Import Script\n")
            f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Indices: {len(counts)} | Documents: {sum(counts.values())}\n")
            f.write("#\n")
            f.write("# Usage:\n")
            f.write("#   ./import_to_elk.sh                    (localhost:9200)\n")
            f.write("#   ./import_to_elk.sh http://elk:9200    (custom host)\n")
            f.write("#   ./import_to_elk.sh https://elk:9200 user:pass  (with auth)\n")
            f.write("#\n\n")
            f.write('ES_HOST="${1:-http://localhost:9200}"\n')
            f.write('AUTH=""\n')
            f.write('if [ -n "$2" ]; then\n')
            f.write('    AUTH="-u $2"\n')
            f.write('fi\n\n')
            f.write('DIR="$(cd "$(dirname "$0")" && pwd)"\n\n')
            f.write('echo "CresCent ELK Import"\n')
            f.write('echo "Target: $ES_HOST"\n')
            f.write(f'echo "Indices: {len(counts)}"\n')
            f.write(f'echo "Documents: {sum(counts.values())}"\n')
            f.write('echo ""\n\n')

            for index, count in sorted(counts.items()):
                fname = f"{index}.ndjson"
                f.write(f'echo "Importing {index} ({count} docs)..."\n')
                f.write(f'curl -s -H "Content-Type: application/x-ndjson" '
                        f'$AUTH -XPOST "$ES_HOST/_bulk" '
                        f'--data-binary @"$DIR/{fname}" | '
                        f'python3 -c "import sys,json;'
                        f'd=json.load(sys.stdin);'
                        f'print(\'  OK\' if not d.get(\'errors\') else '
                        f'\'  ERRORS: \'+str(d))" 2>/dev/null || '
                        f'echo "  curl failed"\n\n')

            f.write('echo ""\n')
            f.write('echo "Done! Open Kibana and create index patterns:"\n')
            for index in sorted(counts.keys()):
                f.write(f'echo "  {index}"\n')
            f.write('echo ""\n')
            f.write('echo "Suggested Kibana steps:"\n')
            f.write('echo "  1. Stack Management → Index Patterns → Create"\n')
            f.write(f'echo "  2. Pattern: {self.prefix}-*"\n')
            f.write('echo "  3. Time field: @timestamp"\n')
            f.write('echo "  4. Go to Discover and explore!"\n')

        # Make executable
        import os
        os.chmod(script_path, 0o755)
        self.log.info("Import script: %s", script_path)
