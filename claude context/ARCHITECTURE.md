# CresCent Toolkit — Module API & JSON Field Reference

> **Scope note (read first):** This doc is the **module-by-module API reference, JSON
> field-name reference, `load_json_by_pattern()` behavior, and suspicious-process
> detection logic**. That content is still accurate for v6 because the cross-platform
> modules were not changed by the v6 refactor. **However, the directory layout and
> dependency tree below describe the older v5.0 flat structure** — in v6 the multi-OS
> modules are split into `*.windows.py` / `*.linux.py` / `*.mac.py` with `importlib.util`
> dispatchers. For the current v6 layout, dispatcher pattern, CLI surface, plugin lists,
> and bug history, see **ARCHITECTURE_V6.md** (authoritative). Use this file for API
> signatures and Vol JSON field names.

## Overview

CresCent is a RAM forensics toolkit built around Volatility 2/3. It takes a memory image (`.raw`, `.mem`, `.lime`, `.dmp`) and produces:
- Structured JSON data per Volatility plugin
- Human-readable text reports
- An interactive HTML report
- Timeline CSV
- ELK/Elasticsearch NDJSON export

**Supported OS targets**: Windows, Linux (Vol2 + Vol3), macOS (Vol3).

---

## Directory Structure

```
CresCent_Toolkit_v5.0/
├── crescent_toolkit.py          # Main entry point — CLI + all command handlers
├── modules/                     # All analysis modules (see Module Reference)
│   ├── volatility.py            # VolatilityWrapper — runs Vol plugins, detects OS
│   ├── extractor.py             # Orchestrates Vol plugin runs → json/
│   ├── process_dumper.py        # Process analysis + exe/mem dumping
│   ├── correlator.py            # Cross-reference all data → correlation report
│   ├── network_map.py           # Network connection map
│   ├── timeline.py              # Unified chronological event timeline
│   ├── html_report.py           # Interactive HTML report generator
│   ├── elk_export.py            # Elasticsearch/ELK NDJSON export
│   ├── file_dumper.py           # File extraction (Windows filescan / Linux pagecache)
│   ├── process_tree.py          # ASCII process tree
│   ├── system_info.py           # System info from Vol output
│   ├── scheduled_tasks.py       # Scheduled tasks / cron / launchd jobs
│   ├── ioc_extractor.py         # IOC extraction (IPs, domains, hashes, etc.)
│   ├── strings_extractor.py     # Strings from memory image
│   ├── memory_grep.py           # Grep patterns across memory strings
│   ├── browser_history.py       # Browser history from strings
│   ├── cmd_analyzer.py          # Command-line / PowerShell analysis
│   ├── comms_scanner.py         # Comms artifact scanner (tokens, API keys, etc.)
│   ├── yara_scanner.py          # YARA rule scanning
│   ├── evtx_parser.py           # Windows EVTX log parser
│   ├── registry_explorer.py     # Windows registry exploration
│   ├── registry_altered.py      # Windows registry anomaly detection
│   ├── popular_files.py         # Popular/suspicious file path analysis
│   ├── linux_resolver.py        # Linux ISF/symbol auto-resolver for Vol3
│   ├── auto_hash.py             # MD5/SHA hashing of dumped files
│   ├── export_pack.py           # Package results into ZIP
│   ├── elk_export.py            # ELK NDJSON exporter
│   ├── installer.py             # Dependency installer
│   └── logger.py                # Logging service
├── utils/
│   ├── json_converter.py        # Vol2 text → JSON; load_json_by_pattern()
│   └── ui.py                    # Console UI helpers (msg_ok, msg_fail, etc.)
└── .docs/
    └── ARCHITECTURE.md          # This file
```

---

## Module Dependency Tree

```
crescent_toolkit.py
│
├── CORE INFRASTRUCTURE
│   ├── modules/volatility.py (VolatilityWrapper)
│   │   └── modules/linux_resolver.py  [Linux/macOS only]
│   ├── modules/extractor.py
│   │   └── modules/volatility.py
│   ├── modules/logger.py (LogService)
│   └── utils/json_converter.py
│       └── (standalone, no module deps)
│
├── PROCESS ANALYSIS
│   ├── modules/process_dumper.py (ProcessDumper)
│   │   ├── modules/volatility.py
│   │   └── utils/json_converter.py
│   ├── modules/process_tree.py (ProcessTree)
│   │   └── utils/json_converter.py
│   └── modules/system_info.py (SystemInfo)
│       └── utils/json_converter.py
│
├── NETWORK ANALYSIS
│   └── modules/network_map.py (NetworkMap)
│       └── utils/json_converter.py
│
├── CORRELATION
│   └── modules/correlator.py (Correlator)
│       └── utils/json_converter.py
│
├── TIMELINE
│   └── modules/timeline.py (Timeline)
│       └── utils/json_converter.py
│
├── FILE ANALYSIS
│   ├── modules/file_dumper.py (FileDumper)
│   │   ├── modules/volatility.py
│   │   └── utils/json_converter.py
│   └── modules/popular_files.py (PopularFilesScanner)
│       └── utils/json_converter.py
│
├── STRING/CONTENT ANALYSIS
│   ├── modules/strings_extractor.py (StringsExtractor)
│   ├── modules/memory_grep.py (MemoryGrep)
│   ├── modules/ioc_extractor.py (IOCExtractor)
│   ├── modules/browser_history.py (BrowserHistoryScanner)
│   ├── modules/cmd_analyzer.py (CommandAnalyzer, MitreMapper)
│   └── modules/comms_scanner.py (CommsScanner)
│
├── WINDOWS-SPECIFIC
│   ├── modules/evtx_parser.py (EVTXParser)
│   ├── modules/registry_explorer.py (RegistryExplorer)
│   ├── modules/registry_altered.py (RegistryAlteredDetector)
│   └── modules/scheduled_tasks.py (ScheduledTasksScanner)  [also Linux/macOS]
│
├── REPORTING
│   ├── modules/html_report.py (HTMLReportGenerator)
│   │   └── utils/json_converter.py
│   └── modules/elk_export.py (ELKExporter)
│       ├── modules/process_dumper.py
│       └── utils/json_converter.py
│
├── SCANNING
│   └── modules/yara_scanner.py (YARAScanner)
│       └── modules/volatility.py
│
└── UTILITIES
    ├── modules/auto_hash.py (AutoHash)
    ├── modules/export_pack.py (ExportPack)
    └── modules/installer.py (Installer)
```

---

## Data Flow

```
Memory Image (.lime / .raw / .dmp)
        │
        ▼
[1] VolatilityWrapper.auto_detect() / .run_all()
        │  Runs Vol2/Vol3 plugins → json/ directory
        │
        ├── json/linux_pslist_PsList.json
        ├── json/linux_psaux_PsAux.json
        ├── json/linux_lsof_Lsof.json
        ├── json/linux_sockstat_Sockstat.json
        ├── json/linux_malfind_Malfind.json
        ├── json/linux_kernel.json           (custom, from linux_resolver)
        └── json/<plugin_name>.json...
                │
                ▼
[2] load_json_by_pattern(json_dir, pattern)  [utils/json_converter.py]
        │  Substring match: "psaux" → linux_psaux_PsAux.json
        │  Returns: List[Dict]
        │
        ├── ProcessDumper.load_processes()   → self._procs list
        ├── Correlator.load_data()           → self._procs dict
        ├── NetworkMap.load()                → self._connections list
        ├── Timeline.load()                  → self._events list
        └── HTMLReportGenerator.generate()   → embeds raw JSON in HTML
                │
                ▼
[3] Analysis & Detection
        │
        ├── ProcessDumper.detect_suspicious() → dispatches by vol.os_type
        │     linux  → _detect_suspicious_linux()
        │     mac    → _detect_suspicious_mac()
        │     windows→ _detect_suspicious_windows()
        │
        ├── Correlator.generate_report()     → correlation_report.txt + .json
        ├── NetworkMap.write_report()        → network_map.txt + .json
        └── Timeline.write_report()          → timeline.csv + timeline.txt
                │
                ▼
[4] Reporting
        ├── HTMLReportGenerator → report.html (single self-contained file)
        ├── ELKExporter → elk/<prefix>-*.ndjson + import_to_elk.sh
        └── ExportPack → results.zip
```

---

## OS Detection & Dispatch

### How os_type is set
1. **Fresh extraction**: `VolatilityWrapper.auto_detect()` or `run_all()` sets `vol.os_type` based on which plugins succeed
2. **From existing output**: `_init_vol_from_existing()` reads `SUMMARY.txt` line `OS: linux/mac/windows`
3. **Fallback**: defaults to `"windows"` if nothing found

### Plugin selection by OS (Vol3)
| OS | Process list | Network | Files | Memory dump |
|---|---|---|---|---|
| Windows | `windows.pslist.PsList` | `windows.netscan.NetScan` | `windows.filescan.FileScan` | `windows.memmap.Memmap` |
| Linux | `linux.pslist.PsList` + `linux.psaux.PsAux` | `linux.sockstat.Sockstat` + `linux.lsof.Lsof` | `linux.pagecache.Files` + `linux.lsof.Lsof` (REG/DIR) | `linux.proc_maps.ProcMaps --dump` |
| macOS | `mac.pslist.PsList` + `mac.psaux.PsAux` | `mac.netstat.Netstat` | `mac.list_files.List_Files` | `mac.proc_maps.Maps --dump` |

---

## JSON Field Name Reference

### Linux psaux (`linux_psaux_PsAux.json`)
```
ARGS    — full command line (UPPERCASE, not "Arguments" or "args")
COMM    — process name
PID     — process ID (int)
PPID    — parent PID (int)
```

### Linux lsof (`linux_lsof_Lsof.json`)
```
Path      — file path (not "Name")
Type      — string: "REG", "DIR", "SOCK", "FIFO", "CHR", "BLK", None
PID       — process ID (int)
Process   — process name
FD        — file descriptor number (int)
Accessed  — ISO timestamp (epoch-0 for sockets = meaningless)
Modified  — ISO timestamp
Changed   — ISO timestamp
Inode     — inode number
Device    — device string
```

### Linux sockstat (`linux_sockstat_Sockstat.json`)
```
Source Addr        — local IP (not "LocalAddr")
Source Port        — local port (not "LocalPort")
Destination Addr   — remote IP (not "ForeignAddr")
Destination Port   — remote port (not "ForeignPort")
Socket Type        — protocol type
State              — connection state
PID                — process ID
Process            — process name
```

### Linux pslist (`linux_pslist_PsList.json`)
```
COMM          — process name
PID           — process ID
PPID          — parent PID
CREATION TIME — ISO timestamp
OFFSET (V)    — virtual offset
```

### macOS equivalents
- `mac_psaux_PsAux.json`: same field names as Linux psaux (ARGS, COMM, PID, PPID)
- `mac_netstat_Netstat.json`: LocalAddr, LocalPort, ForeignAddr, ForeignPort, State, Proto, PID
- `mac_list_files_List_Files.json`: "File Path" or "Path", PID, Process

---

## `load_json_by_pattern()` Behavior

Located in `utils/json_converter.py`:
```python
def load_json_by_pattern(json_dir: Path, pattern: str) -> List[Dict[str, Any]]:
```

Uses **substring matching**: `pattern.lower() in filename.lower()`

| Pattern | Matches |
|---|---|
| `"pslist"` | `linux_pslist_PsList.json`, `mac_pslist_PsList.json`, `windows_pslist_PsList.json` |
| `"psaux"` | `linux_psaux_PsAux.json`, `mac_psaux_PsAux.json` |
| `"lsof"` | `linux_lsof_Lsof.json` |
| `"sockstat"` | `linux_sockstat_Sockstat.json` |
| `"netstat"` | `mac_netstat_Netstat.json`, `windows_netstat*.json` |
| `"netscan"` | `windows_netscan_NetScan.json` |
| `"list_files"` | `mac_list_files_List_Files.json` |
| `"malfind"` | `linux_malfind_Malfind.json`, `mac_malfind_Malfind.json`, `windows_malfind*.json` |

---

## CLI Reference

```
crescent_toolkit.py [command] [options]

Commands:
  menu          Interactive menu (default if no command)
  full          Full extraction + all analysis (both modes)
  extract       Run Volatility plugins only → json/
  dump-files    Interactive file extraction menu
  dump-procs    Interactive process dump menu
  strings       Extract strings from image
  correlate     Run correlator on existing output
  iocs          Extract IOCs from existing output
  report        Generate HTML report from existing output
  timeline      Build timeline from existing output
  evtx          Parse EVTX logs (Windows only)
  export        Package results into ZIP
  elk           Generate ELK/Elasticsearch export
  core          Core analysis only (no strings/browser/comms)

Key options:
  --image / -i    Path to memory image
  --output / -o   Output directory
  --mode / -m     fast | full | malware | network | persistence | registry
  --vol2          Force Volatility 2
  --vol3          Force Volatility 3
  --profile       Vol2 profile (e.g. Win7SP1x64)
  --jobs / -j     Parallel jobs (2–16)
  --speed         normal | fast | fastest
  --timeout       Plugin timeout in seconds
  --quiet / -q    Suppress console output
```

---

## Module API Quick Reference

### VolatilityWrapper (`modules/volatility.py`)
```python
vol = VolatilityWrapper(logger)
vol.find_volatility() -> bool          # locate vol2/vol3 on system
vol.auto_detect(image) -> str          # detect OS, set vol.os_type
vol.run_all(image, output_dir, mode)   # run all appropriate plugins
vol.os_type: str                       # "windows" | "linux" | "mac"
vol.vol_version: str                   # "vol2" | "vol3"
vol.vol3_cmd: str                      # path to vol3 executable
vol.vol2_cmd: str                      # path to vol2 executable
vol.profile: str                       # Vol2 profile name
```

### ProcessDumper (`modules/process_dumper.py`)
```python
pd = ProcessDumper(vol, logger)
pd.load_processes(output_dir)          # load procs from json/
pd.detect_suspicious() -> List[Dict]  # OS-aware: linux/mac/windows
pd.search_processes(pattern) -> List[Dict]
pd.dump_process_exe(image, pid, dump_dir) -> bool
pd.dump_process_exe_verbose(image, proc, dump_dir) -> bool
pd.dump_process_memory_verbose(image, proc, dump_dir) -> bool
pd.dump_suspicious(image, dump_dir, dump_memory=False) -> dict
# proc dict keys: pid, name, ppid, cmdline, threads, flags
```

### NetworkMap (`modules/network_map.py`)
```python
nm = NetworkMap(logger, dns_timeout=2.0)
nm.load(output_dir) -> int             # returns connection count
nm.resolve_dns() -> Dict[str, str]     # IP -> hostname
nm.write_report(output_dir) -> Path
nm.connections: List[Dict]
nm.external_ips: Set[str]
nm.get_by_process() -> Dict[str, List]
nm.get_external_only() -> List[Dict]
```

### Correlator (`modules/correlator.py`)
```python
corr = Correlator(logger, redact_hashes=True)
corr.load_data(output_dir)
corr.generate_report(output_dir) -> Path
# corr._procs: Dict[pid_str, {"name", "ppid", "cmdline", "connections", "suspicious"}]
```

### Timeline (`modules/timeline.py`)
```python
tl = Timeline(logger)
tl.load(output_dir)
tl.write_report(output_dir) -> Path
tl.get_events(start=None, end=None, source=None) -> List[Dict]
# event keys: timestamp, source, type, detail, pid, process
```

### HTMLReportGenerator (`modules/html_report.py`)
```python
hr = HTMLReportGenerator(logger)
hr.generate(output_dir) -> Path        # writes report.html
```

### ELKExporter (`modules/elk_export.py`)
```python
elk = ELKExporter(logger, index_prefix="crescent")
elk.export_all(output_dir, elk_dir=None) -> Dict[str, int]
# Returns: {index_name: doc_count}
# Outputs: {prefix}-processes.ndjson, -timeline.ndjson, -iocs.ndjson,
#           -malfind.ndjson, -files.ndjson, -browser.ndjson, -suspicious.ndjson
```

### FileDumper (`modules/file_dumper.py`)
```python
fd = FileDumper(vol, logger)
# Windows:
fd.parse_filescan(path) -> int
fd.dump_by_extension(image, ext, dump_dir) -> int
fd.dump_by_pattern(image, pattern, dump_dir) -> int
# Linux:
fd.parse_linux_files(image) -> int    # runs linux.pagecache.Files via Vol3
fd.linux_file_count: int              # property
fd.search_linux_files(pattern) -> List[Dict]
fd.dump_linux_by_pattern(image, pattern, dump_dir) -> int
fd.dump_linux_by_extension(image, ext, dump_dir) -> int
fd.dump_linux_file_by_inode(image, entry, dump_dir) -> bool
fd.list_linux_extensions() -> Dict[str, int]
# macOS:
fd.dump_mac(image, dump_dir) -> int   # runs mac.list_files + mac.macho_dump
```

### SystemInfo (`modules/system_info.py`)
```python
si = SystemInfo(logger)
si.load(output_dir) -> Dict           # returns info dict directly
si.write_report(output_dir) -> Path
# info keys: hostname, domain, os_version, os_build, architecture,
#            boot_time, usernames, ip_addresses
```

### ScheduledTasksScanner (`modules/scheduled_tasks.py`)
```python
sts = ScheduledTasksScanner(logger)
sts.scan(output_dir) -> List[Dict]    # Windows tasks + Linux cron + macOS launchd
sts.write_report(output_dir, tasks) -> Path
```

### EVTXParser (`modules/evtx_parser.py`) — Windows only
```python
ep = EVTXParser(logger)
ep.find_evtx_files(output_dir) -> List[Path]
ep.parse_all(output_dir) -> List[Dict]
ep.get_interesting_events(events, event_ids=None) -> List[Dict]
ep.write_report(output_dir, events) -> Path
```

### YARAScanner (`modules/yara_scanner.py`)
```python
ys = YARAScanner(logger)
ys.scan(image, rules_path=None) -> List[Dict]
```

### BrowserHistoryScanner (`modules/browser_history.py`)
```python
bh = BrowserHistoryScanner(logger)
bh.scan_strings_file(strings_path) -> Dict
bh.scan_output_dir(output_dir) -> Dict
bh.write_report(output_dir, results) -> Path
# result keys: urls, url_count, searches, search_count, downloads, download_count
```

### CommandAnalyzer (`modules/cmd_analyzer.py`)
```python
ca = CommandAnalyzer(logger)
ca.analyze(output_dir) -> Dict
# result keys: flags, chains, mitre, os_type
```

### CommsScanner (`modules/comms_scanner.py`)
```python
cs = CommsScanner(logger)
cs.scan_strings_file(strings_path) -> Dict
cs.enrich_from_processes(output_dir, results) -> None
cs.write_report(output_dir, results) -> Path
# detects: Slack/Teams/Discord tokens, Telegram bots, API keys, crypto wallets, etc.
```

### IOCExtractor (`modules/ioc_extractor.py`)
```python
ioc = IOCExtractor(logger)
ioc.extract_from_file(input_file, output_dir) -> Dict
ioc.extract_from_directory(input_dir, output_dir) -> Dict
ioc.scan_single_string(text) -> List[Dict]
# categories: ipv4, ipv6, domain, url, email, md5, sha1, sha256, registry_key, etc.
```

### PopularFilesScanner (`modules/popular_files.py`)
```python
pf = PopularFilesScanner(logger)
pf.scan(output_dir) -> Dict
# keys: total_files_scanned, os_heuristic, buckets, suspicious_paths,
#       executables_in_user_dirs, total_findings
```

### ExportPack (`modules/export_pack.py`)
```python
ep = ExportPack(logger)
ep.list_available(output_dir) -> List[str]
ep.generate(output_dir, archive_path=None, items=None) -> Path
```

### AutoHash (`modules/auto_hash.py`)
```python
ah = AutoHash(logger)
ah.hash_directory(directory) -> Dict[str, Dict]  # filename → {md5, sha1, sha256}
```

---

## Suspicious Process Detection

### Linux (`_detect_suspicious_linux()`)
Checks:
1. **Known offensive tools** (whole-word match): nc, ncat, socat, nmap, masscan, chisel, ligolo, frpc, meterpreter, mettle, mimipenguin, pspy, linpeas, reptile, diamorphine, azazel, kovid, bash/sh/python (when suspicious), fscan
2. **Known malware names**: direct name match against list
3. **Execution from writable paths**: /tmp/, /dev/shm/, /var/tmp/
4. **LD_PRELOAD or LD_LIBRARY_PATH**: env injection
5. **AT_ environment variable tricks**: `AT_` prefix in envvar name (whole-word)
6. **Base64 decode in cmdline**
7. **Network listener** (`-l` flag with nc/ncat/socat)
8. **Unexpected parent**: loginshell from kworker, etc.
9. **Multiple systemd**: >1 non-`--user` systemd instance
10. **Zero threads** (can indicate hollowing)
11. **Hidden from pslist** (psscan-only = DKOM)

### macOS (`_detect_suspicious_mac()`)
Checks:
1. **Known macOS offensive tools**: osascript, osacompile, empyre, apfell, mythic, dylib_hijack, nc, ncat, socat, etc.
2. **Known macOS malware names**: empyre, apfell
3. **Execution from writable paths**: /tmp/, /var/tmp/, /private/tmp/, /private/var/tmp/
4. **Base64 decode in cmdline**
5. **DYLD_INSERT_LIBRARIES** (macOS dylib injection equivalent of LD_PRELOAD)
6. **Network listener** (`-l` flag with nc/ncat/socat)
7. **Unexpected parent** (loginwindow/securityd/sshd not from launchd)
8. **Multiple launchd** (should always be exactly 1)
9. **Zero threads**
10. **Hidden from pslist** (psscan-only)

### Windows (`_detect_suspicious_windows()`)
Standard Windows checks: PPID spoofing, hollow processes, masquerading, path anomalies, known attacker tools.

---

## Analysis Modes

| Mode | Plugins Run | Use Case |
|---|---|---|
| `fast` | pslist, psscan, netscan, malfind, cmdline | Quick triage, 5–15 min |
| `full` | All available plugins for OS | Complete forensics, 20–60 min |
| `malware` | pslist + malfind + lsof/netscan + yara | Malware-focused |
| `network` | pslist + netscan/sockstat + lsof + dns | Network-focused |
| `persistence` | pslist + scheduled tasks + registry + startup | Persistence-focused |
| `registry` | Windows registry plugins only | Registry forensics |

---

## Output Directory Structure

```
output_dir/
├── SUMMARY.txt              # Run metadata (OS, mode, duration, plugin counts)
├── report.html              # Self-contained interactive HTML report
├── correlation_report.txt   # Text cross-reference report
├── network_map.txt          # Network connections grouped by process
├── process_tree.txt         # ASCII process hierarchy
├── timeline.csv             # Chronological event timeline
├── suspicious_processes.txt # Flagged process observations
├── system_info.txt          # OS, hostname, users, boot time
├── scheduled_tasks.txt      # Scheduled tasks / cron / launchd
├── strings_ascii.txt        # ASCII strings from image
├── strings_unicode.txt      # Unicode strings from image
├── strings_all.txt          # All strings combined
├── browser_history.txt      # URLs/searches from strings
├── comms_report.txt         # Comms artifacts (tokens, API keys)
├── popular_files.txt        # Notable file paths
├── crescent_toolkit.log     # Full log file
├── json/                    # All Volatility JSON output
│   ├── linux_pslist_PsList.json
│   ├── linux_psaux_PsAux.json
│   ├── linux_lsof_Lsof.json
│   ├── linux_sockstat_Sockstat.json
│   ├── linux_malfind_Malfind.json
│   ├── linux_kernel.json          (OS/kernel info from linux_resolver)
│   ├── correlation_report.json
│   ├── network_map.json
│   ├── timeline.json
│   └── system_info.json
├── iocs/                    # IOC extraction results
│   ├── ioc_results.json
│   ├── ioc_summary.json
│   └── ioc_summary.txt
├── comms/                   # Comms scanner detailed results
├── dumped_files/            # Files extracted from memory
│   ├── *.dat / *.exe / *.dll (Windows filescan dumps)
│   └── *.lime_extract (Linux pagecache dumps)
└── elk/                     # ELK export (if requested)
    ├── import_to_elk.sh
    ├── crescent-processes.ndjson
    ├── crescent-timeline.ndjson
    ├── crescent-iocs.ndjson
    ├── crescent-malfind.ndjson
    ├── crescent-files.ndjson
    ├── crescent-browser.ndjson
    └── crescent-suspicious.ndjson
```

---

## Known Limitations & Edge Cases

### Linux
- **sockstat on idle systems**: `linux.sockstat.Sockstat` produces 0 rows if no active connections at capture time. This is correct; lsof SOCK entries are used for process-connection correlation but lack IP details.
- **lsof SOCK timestamps**: All epoch-0 (`1970-01-01T00:00:00`), filtered from timeline automatically.
- **pagecache.Files**: Requires running the toolkit live (not from existing JSON). Use `dump-files` command.
- **psaux ARGS field**: Uppercase `ARGS`, not `Arguments`. Code handles this via `_gv()` case-insensitive fallback.

### macOS
- Supported via Vol3 only (no Vol2 macOS plugins)
- `mac.proc_maps.Maps --dump` used for both exe and memory dumps
- `mac.list_files.List_Files` used as file list source

### Windows
- Registry analysis requires `windows.registry.*` plugins (Vol3 only for most)
- EVTX parsing requires dumped `.evtx` files in output_dir

---

## Linux Symbol Resolution

Handled by `modules/linux_resolver.py`. Automatically downloads ISF (Intermediate Symbol File) for the kernel version detected in the image.

Process:
1. Detect kernel banner from image strings
2. Search Volatility symbol index for matching ISF
3. Download and install to `~/.local/lib/python3/dist-packages/volatility3/symbols/linux/`
4. Write `json/linux_kernel.json` with kernel version + os_type

---

## Testing

```bash
# Syntax check all modules
python3 -m py_compile crescent_toolkit.py
for f in modules/*.py; do python3 -m py_compile "$f"; done

# Quick functional test (requires existing output at /home/kali/Desktop/kalilinux_lime/)
python3 -c "
from pathlib import Path
from modules.volatility import VolatilityWrapper
from modules.process_dumper import ProcessDumper
import logging
log = logging.getLogger('test')
vol = VolatilityWrapper(log)
vol.os_type = 'linux'; vol.vol_version = 'vol3'
pd = ProcessDumper(vol, log)
pd.load_processes(Path('/home/kali/Desktop/kalilinux_lime'))
sus = pd.detect_suspicious()
print(f'{len(sus)} suspicious processes detected')
"
```

---

## Changes Made in Last Session (2026-06-14)

### Linux Compatibility Fixes
- `correlator.py`: Added sockstat (Source/Destination Addr) and lsof (Path/Type) loops; added psaux cmdline backfill loop (fixes all-empty cmdlines bug)
- `network_map.py`: Added sockstat and lsof socket loops
- `timeline.py`: Added sockstat and lsof socket loops; added psaux cmdline loading
- `process_dumper.py`: Added Linux constants, fixed `"nc"` false positive with whole-word tokenization, fixed multiple-systemd false positive
- `html_report.py`: Added psaux JS cmdline fallback in processBundle
- `elk_export.py`: Added sockstat to network export, lsof fallback for files export
- `file_dumper.py`: Added `linux_file_count` property

### macOS Compatibility Fixes
- `process_dumper.py`: Added macOS constants (`_KNOWN_TOOLS_MAC`, `_SUSPICIOUS_NAMES_MAC`, `_UNIQUE_PROCS_MAC`, `_EXP_PARENTS_MAC`), added `_detect_suspicious_mac()` method, added macOS dispatch in `detect_suspicious()`, `dump_process_exe_verbose()`, `dump_process_memory_verbose()`, `dump_process_exe()`, `dump_suspicious()`, added `_try_mac_proc_maps_dump()` helper
- `correlator.py`: Added macOS process names to `_INTEREST_PROCS`
- `elk_export.py`: Added macOS `list_files` fallback in `_export_files()`
- `crescent_toolkit.py`: Added `_linux_filedump_menu()` function for interactive Linux file dumping

### Bug Fixes
- `correlator.py` psaux cmdline backfill: psaux entries were silently skipped because PIDs were already in `_procs` dict; fixed by adding a second pass
- `process_dumper.py` nc false positive: `"nc" in "kworker/R-sync_"` matched via substring; fixed with `re.split(r"[\W_/\-]", name)` whole-word tokenization
- `process_dumper.py` multiple-systemd: `systemd --user` (PID ~1191) was counted as a duplicate of system `systemd` (PID 1); fixed by only counting non-`--user` instances
