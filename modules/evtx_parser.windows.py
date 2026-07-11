"""
CresCent RAM Forensics Toolkit v4.0 - EVTX Parser

Parses Windows Event Log (.evtx) files that were dumped from memory.
Uses python-evtx library if available, falls back to strings-based extraction.
Focuses on security-relevant events: logons, service installs, PowerShell, etc.
"""

import json
import logging
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# Security-relevant Event IDs
INTERESTING_EVENTS = {
    # Security.evtx
    "4624": "Successful Logon",
    "4625": "Failed Logon",
    "4648": "Logon with Explicit Credentials",
    "4672": "Special Privileges Assigned",
    "4688": "New Process Created",
    "4697": "Service Installed",
    "4698": "Scheduled Task Created",
    "4720": "User Account Created",
    "4722": "User Account Enabled",
    "4723": "Password Change Attempt",
    "4724": "Password Reset Attempt",
    "4725": "User Account Disabled",
    "4726": "User Account Deleted",
    "4728": "Member Added to Security Group",
    "4732": "Member Added to Local Group",
    "4756": "Member Added to Universal Group",
    "4768": "Kerberos TGT Requested",
    "4769": "Kerberos Service Ticket Requested",
    "4776": "NTLM Authentication",
    # System.evtx
    "7034": "Service Crashed",
    "7035": "Service Control Manager",
    "7036": "Service State Changed",
    "7040": "Service Start Type Changed",
    "7045": "New Service Installed",
    # PowerShell
    "4103": "PowerShell Module Logging",
    "4104": "PowerShell Script Block Logging",
    "400": "PowerShell Engine Start",
    "403": "PowerShell Engine Stop",
    # Sysmon (if present)
    "1": "Sysmon Process Create",
    "3": "Sysmon Network Connection",
    "7": "Sysmon Image Loaded",
    "8": "Sysmon CreateRemoteThread",
    "11": "Sysmon File Created",
    "13": "Sysmon Registry Value Set",
}


class EVTXParser:
    """Parse dumped Windows Event Log files."""

    def __init__(self, logger: logging.Logger):
        self.log = logger
        self._has_evtx_lib = False
        self._check_library()

    def _check_library(self):
        """Check if python-evtx is available."""
        try:
            import Evtx.Evtx
            self._has_evtx_lib = True
            self.log.info("python-evtx library available")
        except ImportError:
            self._has_evtx_lib = False
            self.log.info("python-evtx not installed, using strings fallback. "
                          "Install: pip3 install python-evtx --break-system-packages")

    def find_evtx_files(self, output_dir: Path) -> List[Path]:
        """Find dumped .evtx files in the output directory.

        Handles Vol2/Vol3 dump naming conventions:
          - file.0x...DataSectionObject.Security.evtx.dat  (Vol3 format)
          - file.0x...SharedCacheMap.Security.evtx.vacb     (skip - cache only)
          - Security.evtx                                    (clean name)
          - *.dat with ElfFile magic bytes                   (any renamed EVTX)

        Only picks DataSectionObject .dat files (actual content).
        Skips SharedCacheMap .vacb files (cache manager, no useful data).

        Args:
            output_dir: Base analysis output directory.

        Returns:
            List of .evtx file paths.
        """
        evtx_files = []
        search_dirs = [
            output_dir / "dumped_files",
            output_dir / "dumped_files" / "evtx",
            output_dir / "evtx_files",
            output_dir,
        ]

        for d in search_dirs:
            if not d.is_dir():
                continue

            for f in sorted(d.iterdir()):
                if not f.is_file():
                    continue
                fname = f.name.lower()

                # Skip .vacb files (SharedCacheMap = cache manager, useless)
                if fname.endswith(".vacb"):
                    continue

                # Match: *.evtx (clean name)
                if fname.endswith(".evtx"):
                    evtx_files.append(f)
                    continue

                # Match: *.evtx.dat (Vol3 DataSectionObject dumps)
                if ".evtx.dat" in fname and "datasectionobject" in fname:
                    evtx_files.append(f)
                    self.log.debug("EVTX (DataSectionObject): %s", f.name)
                    continue

                # Match: any .dat with "evtx" in the name
                if fname.endswith(".dat") and ".evtx" in fname:
                    evtx_files.append(f)
                    self.log.debug("EVTX (.dat): %s", f.name)
                    continue

                # Fallback: any .dat file - check magic bytes
                if fname.endswith(".dat"):
                    try:
                        with open(f, "rb") as fh:
                            magic = fh.read(8)
                            if magic[:7] == b"ElfFile":
                                evtx_files.append(f)
                                self.log.debug("EVTX (magic): %s", f.name)
                    except Exception:
                        pass

        # Deduplicate
        seen = set()
        unique = []
        for f in evtx_files:
            r = f.resolve()
            if r not in seen:
                seen.add(r)
                unique.append(f)

        if unique:
            self.log.info("Found %d EVTX files:", len(unique))
            for f in unique:
                # Extract the log name from the filename
                name = f.name
                for part in name.split("."):
                    if "evtx" in part.lower():
                        break
                    if part not in ("file", "dat") and not part.startswith("0x"):
                        name = part
                self.log.info("  %s", f.name)
        else:
            self.log.info("No EVTX files found")

        return unique

    def parse_file(self, path: Path) -> List[Dict[str, Any]]:
        """Parse a single EVTX file.

        Uses python-evtx if available, otherwise falls back to strings.

        Args:
            path: Path to .evtx file.

        Returns:
            List of event dicts.
        """
        if self._has_evtx_lib:
            return self._parse_with_library(path)
        else:
            return self._parse_with_strings(path)

    def _parse_with_library(self, path: Path) -> List[Dict[str, Any]]:
        """Parse EVTX using python-evtx library."""
        import Evtx.Evtx as evtx
        import Evtx.Views as e_views

        events = []
        try:
            with evtx.Evtx(str(path)) as log:
                for record in log.records():
                    try:
                        xml = record.xml()
                        event = self._parse_xml_event(xml)
                        if event:
                            event["source_file"] = path.name
                            events.append(event)
                    except Exception:
                        continue
        except Exception as e:
            self.log.error("EVTX parse error %s: %s", path.name, e)

        self.log.info("Parsed %s: %d events", path.name, len(events))
        return events

    def _parse_xml_event(self, xml: str) -> Optional[Dict[str, Any]]:
        """Extract key fields from an EVTX XML record."""
        event = {}

        # EventID
        m = re.search(r"<EventID[^>]*>(\d+)</EventID>", xml)
        if m:
            event["EventID"] = m.group(1)

        # TimeCreated
        m = re.search(r'SystemTime="([^"]+)"', xml)
        if m:
            event["TimeCreated"] = m.group(1)

        # Computer
        m = re.search(r"<Computer>([^<]+)</Computer>", xml)
        if m:
            event["Computer"] = m.group(1)

        # Channel
        m = re.search(r"<Channel>([^<]+)</Channel>", xml)
        if m:
            event["Channel"] = m.group(1)

        # Provider
        m = re.search(r'Name="([^"]+)"', xml)
        if m:
            event["Provider"] = m.group(1)

        # EventData fields
        for dm in re.finditer(r'<Data Name="([^"]+)">([^<]*)</Data>', xml):
            event[dm.group(1)] = dm.group(2)

        # Mark interesting events
        eid = event.get("EventID", "")
        if eid in INTERESTING_EVENTS:
            event["_description"] = INTERESTING_EVENTS[eid]
            event["_interesting"] = True
        else:
            event["_interesting"] = False

        return event if event.get("EventID") else None

    def _parse_with_strings(self, path: Path) -> List[Dict[str, Any]]:
        """Fallback: extract event data using strings command.

        WARNING: EVTX records are stored in BinXml (binary XML). The strings
        utility cannot meaningfully reconstruct field-level data from BinXml,
        so this fallback typically recovers only a small fraction (often <5%)
        of the events actually in the file — and the fields it does recover
        are best-effort fragments. Install python-evtx for accurate parsing:
            pip3 install python-evtx --break-system-packages
        """
        self.log.warning(
            "EVTX strings fallback in use for %s — results are INCOMPLETE "
            "and LOSSY. Install python-evtx for full parsing.", path.name)
        events = []
        try:
            proc = subprocess.run(
                ["strings", "-a", str(path)],
                capture_output=True, text=True, timeout=60)
            lines = proc.stdout.splitlines()
        except Exception as e:
            self.log.error("strings failed on %s: %s", path.name, e)
            return []

        # Look for EventID patterns in strings output
        current_block = []
        for line in lines:
            line = line.strip()
            if not line:
                if current_block:
                    event = self._parse_string_block(current_block, path.name)
                    if event:
                        events.append(event)
                    current_block = []
                continue
            current_block.append(line)

        self.log.warning(
            "Strings fallback %s: extracted %d event fragments — actual "
            "event count is almost certainly higher. Install python-evtx.",
            path.name, len(events))
        return events

    def _parse_string_block(self, lines: List[str],
                            source: str) -> Optional[Dict]:
        """Try to extract event info from a block of strings."""
        text = " ".join(lines)
        event_id_match = re.search(r"EventID[>\s:]+(\d{1,5})", text)
        if not event_id_match:
            return None

        eid = event_id_match.group(1)
        event = {
            "EventID": eid,
            "source_file": source,
            "raw": text[:500],
            # Mark this event as recovered via the lossy strings fallback so
            # the HTML report / SIEM consumers can flag it for the analyst.
            "_low_fidelity": True,
            "_fidelity_note": "Recovered via strings fallback; fields are partial.",
        }

        if eid in INTERESTING_EVENTS:
            event["_description"] = INTERESTING_EVENTS[eid]
            event["_interesting"] = True
        else:
            event["_interesting"] = False

        return event

    def parse_all(self, output_dir: Path) -> List[Dict[str, Any]]:
        """Find and parse all EVTX files.

        Args:
            output_dir: Base analysis output directory.

        Returns:
            All events from all files.
        """
        files = self.find_evtx_files(output_dir)
        all_events = []
        for f in files:
            all_events.extend(self.parse_file(f))

        # Sort by time
        all_events.sort(key=lambda e: e.get("TimeCreated", ""))
        self.log.info("Total EVTX events: %d", len(all_events))
        return all_events

    def get_interesting_events(self,
                                events: List[Dict]) -> List[Dict]:
        """Filter to only security-relevant events."""
        return [e for e in events if e.get("_interesting")]

    def write_report(self, output_dir: Path,
                     events: List[Dict]) -> Path:
        """Write parsed events to TXT and JSON.

        Args:
            output_dir: Output directory.
            events: List of event dicts.

        Returns:
            Path to TXT report.
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        txt_path = output_dir / "evtx_report.txt"
        json_dir = output_dir / "json"
        json_dir.mkdir(parents=True, exist_ok=True)
        json_path = json_dir / "evtx_report.json"

        interesting = self.get_interesting_events(events)

        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("  WINDOWS EVENT LOG ANALYSIS\n")
            f.write(f"  Total events: {len(events)}\n")
            f.write(f"  Security-relevant: {len(interesting)}\n")
            f.write("=" * 80 + "\n\n")

            if interesting:
                f.write("--- SECURITY-RELEVANT EVENTS ---\n\n")
                for e in interesting:
                    eid = e.get("EventID", "?")
                    desc = e.get("_description", "")
                    ts = e.get("TimeCreated", "")
                    src = e.get("source_file", "")
                    f.write(f"  [{eid}] {desc}\n")
                    f.write(f"  Time: {ts}  Source: {src}\n")
                    # Show key data fields
                    skip = {"EventID", "TimeCreated", "Computer", "Channel",
                            "Provider", "source_file", "_description",
                            "_interesting", "raw"}
                    for k, v in e.items():
                        if k not in skip and v:
                            f.write(f"    {k}: {v}\n")
                    f.write("-" * 40 + "\n")
            else:
                f.write("  No security-relevant events found.\n")

            # Summary by EventID
            f.write("\n--- EVENT ID SUMMARY ---\n\n")
            id_counts: Dict[str, int] = {}
            for e in events:
                eid = e.get("EventID", "?")
                id_counts[eid] = id_counts.get(eid, 0) + 1
            for eid, count in sorted(id_counts.items(),
                                      key=lambda x: -x[1]):
                desc = INTERESTING_EVENTS.get(eid, "")
                marker = " *" if desc else ""
                f.write(f"  {eid:8s} {count:>6d}  {desc}{marker}\n")

            f.write("\n" + "=" * 80 + "\n")

        json_path.write_text(
            json.dumps(events, indent=2, default=str), encoding="utf-8")

        self.log.info("EVTX report: %s", txt_path)
        return txt_path
