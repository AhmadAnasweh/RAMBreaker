# CresCentC v6.0 — Architecture & Future Session Context

## What Is v6

CresCentC v6 is a refactored version of v5.0 where all modules handling multiple operating systems have been split into OS-specific files. The goal is clearer code ownership, per-OS customization, and explicit OS dispatching.

**Key difference from v5.0:**
- v5.0: One extractor.py handles Windows, Linux, macOS plugin lists internally
- v6.0: `extractor.windows.py`, `extractor.linux.py`, `extractor.mac.py` each contain only their OS's plugins; `extractor.py` is a thin dispatcher

## Location

```
/home/kali/Desktop/CresCentC_v6/          ← Active v6 codebase
/home/kali/Desktop/CresCent_Toolkit_v5.0/ ← v5.0 (read-only reference)
```

---

## The importlib.util Dispatcher Pattern

Python can't `import` files with dots in their name (like `extractor.windows.py`) via normal `from modules.extractor.windows import ...`. Instead, each dispatcher uses:

```python
import importlib.util
import pathlib

def _load_os_module(os_type: str):
    _DIR = pathlib.Path(__file__).parent
    _MAP = {'linux': 'extractor.linux', 'mac': 'extractor.mac'}
    name = _MAP.get(str(os_type).lower(), 'extractor.windows')
    path = _DIR / (name + '.py')
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod
```

Then provide a factory function with the same name as the v5.0 class:

```python
def Extractor(vol, logger, jobs=4, speed='normal'):
    os_type = getattr(vol, 'os_type', 'windows') or 'windows'
    mod = _load_os_module(os_type)
    return mod.Extractor(vol, logger, jobs, speed)
```

The calling code in `crescent_toolkit.py` doesn't change — `Extractor(vol, ...)` still works.

---

## Directory Structure

```
CresCentC_v6/
├── crescent_toolkit.py          # Main entry point (v6-updated)
├── ARCHITECTURE_V6.md           # This file
├── CHANGES.md                   # What changed from v5.0 → v6
│
├── modules/
│   │
│   ├── # OS-SPLIT MODULES (dispatchers + 19 OS-specific files)
│   │
│   ├── extractor.py             # DISPATCHER → loads extractor.{os}.py
│   ├── extractor.windows.py     # Windows PLUGINS (vol3-windows-*, vol2-windows-*)
│   │                            #   + _run_targeted_printkey()
│   │                            #   + _run_vol2_exclusive() (cmdscan/consoles/etc)
│   ├── extractor.linux.py       # Linux PLUGINS (vol3-linux-*, vol2-linux-*)
│   ├── extractor.mac.py         # macOS PLUGINS (vol3-mac-* only)
│   │
│   ├── html_report.py           # DISPATCHER → loads html_report.{os}.py
│   ├── html_report.windows.py   # VERSION="6.0-windows"
│   ├── html_report.linux.py     # VERSION="6.0-linux"
│   ├── html_report.mac.py       # VERSION="6.0-mac"
│   │
│   ├── cmd_analyzer.py          # DISPATCHER → loads cmd_analyzer.{os}.py
│   ├── cmd_analyzer.windows.py  # 42 Windows CMD_PATTERNS (PS, LOLBins, credential tools)
│   ├── cmd_analyzer.linux.py    # 38 Linux CMD_PATTERNS (shell, wget/curl, privesc)
│   ├── cmd_analyzer.mac.py      # 44 macOS CMD_PATTERNS (osascript, launchctl, xattr, spctl)
│   │
│   ├── scheduled_tasks.py       # DISPATCHER → loads scheduled_tasks.{os}.py
│   ├── scheduled_tasks.windows.py  # Windows task analysis (registry, .job files, schtasks)
│   ├── scheduled_tasks.linux.py    # Linux cron analysis (cron, at, systemd)
│   ├── scheduled_tasks.mac.py      # macOS launchd analysis (LaunchAgents, LaunchDaemons)
│   │
│   ├── popular_files.py         # DISPATCHER → loads popular_files.{os}.py
│   ├── popular_files.windows.py # Windows file buckets (_WIN_BUCKETS)
│   ├── popular_files.linux.py   # Linux file buckets (_LIN_BUCKETS)
│   ├── popular_files.mac.py     # macOS file buckets (_MAC_BUCKETS)
│   │
│   ├── linux_resolver.py        # DISPATCHER → linux_resolver.linux.py or .mac.py
│   ├── linux_resolver.linux.py  # Linux Vol3 ISF symbol resolver
│   ├── linux_resolver.mac.py    # macOS Vol3 ISF symbol resolver
│   │
│   ├── registry_explorer.py     # DISPATCHER → registry_explorer.windows.py (Windows-only)
│   ├── registry_explorer.windows.py  # Windows registry hives, printkey, persistence
│   │
│   ├── evtx_parser.py           # DISPATCHER → evtx_parser.windows.py (Windows-only)
│   ├── evtx_parser.windows.py   # Windows .evtx event log parser
│   │
│   ├── # CROSS-PLATFORM MODULES (unchanged from v5.0, no split needed)
│   │
│   ├── volatility.py            # VolatilityWrapper — OS detection + plugin runner
│   ├── correlator.py            # Cross-reference all data → correlation report
│   ├── network_map.py           # Network connection map (handles all OS sources)
│   ├── ioc_extractor.py         # IOC extraction (OS-agnostic patterns)
│   ├── browser_history.py       # Browser history from strings (OS-agnostic)
│   ├── comms_scanner.py         # comms scanner: Teams/Discord/Zoom/Slack/Telegram/
│   │                            #   WhatsApp/Skype/Webex/Signal/Meet/VooV/Flock
│   │                            #   (strings + process/network correlation)
│   ├── process_tree.py          # ASCII process tree
│   ├── system_info.py           # System info from Vol output
│   ├── process_dumper.py        # Process analysis + exe/mem dumping
│   ├── file_dumper.py           # File extraction (Windows filescan / Linux pagecache)
│   ├── timeline.py              # Unified chronological event timeline
│   ├── registry_altered.py      # Windows registry anomaly detection
│   ├── strings_extractor.py     # Strings from memory image
│   ├── memory_grep.py           # Grep patterns across already-dumped files
│   ├── ioc_extractor.py         # IOC extraction
│   ├── auto_hash.py             # MD5/SHA hashing of dumped files
│   ├── yara_scanner.py          # YARA rule scanning of already-dumped files
│   ├── string_hunt.py           # LIVE memory string search via Volatility YARA plugins
│   ├── export_pack.py           # Package results into ZIP
│   ├── elk_export.py            # Elasticsearch/ELK NDJSON exporter
│   ├── installer.py             # Dependency installer
│   └── logger.py                # Logging service
│
└── utils/
    ├── ui.py                    # VERSION="6.0", console UI helpers
    └── json_converter.py        # Vol2 text → JSON; load_json_by_pattern()
```

---

## OS Detection Flow

OS detection happens in `VolatilityWrapper.auto_detect()` (in `volatility.py`, unchanged from v5.0):

1. Try `banners.Banners` (Vol3) — fastest broad-spectrum OS scanner
2. Try `windows.info.Info` (Vol3) — confirms Windows if banners ambiguous
3. Try Vol2 `imageinfo` — Win7/XP/Vista fallback
4. Raw string scan — last resort

Result stored in `vol.os_type` (values: `'windows'`, `'linux'`, `'mac'`, `'unknown'`).

The dispatcher modules receive `vol.os_type` and load the right OS-specific implementation.

---

## crescent_toolkit.py Changes (v6 vs v5.0)

| Location | v5.0 | v6 |
|----------|------|-----|
| Banner | "v5.0" | "v6.0" |
| `CommandAnalyzer(...)` | Windows-only guard | All OSes, passes `vol.os_type` |
| `MitreMapper(...)` | Windows-only guard | All OSes, passes `vol.os_type` |
| `ScheduledTasksScanner(...)` | Single call | Passes `vol.os_type` |
| `PopularFilesScanner(...)` | Single call | Passes `vol.os_type` |
| `HTMLReportGenerator(...)` | Single arg | Passes `vol.os_type` |

---

## CLI Surface (verified against crescent_toolkit.py)

**Positional command** (default `menu`):
`menu  extract  dump-files  dump-procs  strings  correlate  iocs  report  timeline  evtx  export  elk  core  full  hunt`

**Flags:**
| Flag | Meaning |
|------|---------|
| `-i, --image` | memory image path (NOT `-f`) |
| `-o, --output` | output directory |
| `-m, --mode` | plugin profile: `fast full malware network persistence registry` (default `full`) |
| `--vol2` / `--vol3` | force a Volatility engine |
| `--profile` | force a Vol2 profile (e.g. `Win7SP1x64`) |
| `--speed` | `normal` (default) / `fast` / `fastest` |
| `-j, --jobs` | parallel jobs (default 4) |
| `--timeout` | base per-plugin timeout, seconds (default 600) |
| `--pattern` | file-dump pattern (e.g. `evtx`, `exe`) |
| `--strings-mode` | `all ascii unicode both` |
| `--hunt-strings` / `--hunt-pid` / `--hunt-case-sensitive` / `--hunt-no-wide` | String Hunt options |
| `-q, --quiet` / `--log` | logging controls |

`VALID_MODES = ("fast", "full", "malware", "network", "persistence", "registry")` — defined in `extractor.windows.py` and re-exported via `extractor.py`.

---

## Running v6

```bash
cd /home/kali/Desktop/CresCentC_v6

# Full analysis (Windows Vol3 image, fast mode)
python3 crescent_toolkit.py full -i "/path/to/Windows.raw" -o /output/ -m fast -j 2

# Full analysis (Windows 7 Vol2 image, needs profile)
python3 crescent_toolkit.py full -i Windows2.raw -o /output/ -m fast --profile Win7SP1x64

# Full analysis (Linux VMware image)
python3 crescent_toolkit.py full -i linux.vmem -o /output/ -m fast -j 2

# Full analysis (macOS image)  
python3 crescent_toolkit.py full -i MAC -o /output/ -m fast -j 2

# Just extraction (no full pipeline)
python3 crescent_toolkit.py extract -i image.raw -o /output/ -m fast

# File dump after extraction
python3 crescent_toolkit.py dump-files -i image.raw -o /output/

# Process dump after extraction
python3 crescent_toolkit.py dump-procs -i image.raw -o /output/

# HTML report after extraction
python3 crescent_toolkit.py report -o /output/
```

---

## Bugs Found and Fixed During v6 Testing

### Bug #4 — Vol2 cmdline JSON has 0 extractable PIDs (FIXED 2026-06-20)

**Files:** `utils/json_converter.py`

**Symptom:** For Vol2 images (Windows2.raw), the Shell Commands tab showed no process command lines. `cmd_analyzer` found 0 flags/chains. `load_json_by_pattern(jd, "cmdline")` returned 72 entries but 0 usable PIDs.

**Root cause:** `_parse_std_table` mistook the first process line (`System pid:      4`) for a table header, producing wrong column names (`"System pid:"`, `"4"`) instead of `"Process"`, `"PID"`, `"CommandLine"`. The Vol2 cmdline output uses paired lines (`<Name> pid: <PID>` / `Command line : <args>`), not a standard table.

**Fix:** Added `_parse_cmdline()` in `json_converter.py` and routed `plugin_name == "cmdline"` to it via `parse_vol2_table()`. New parser uses regex to match `<Name> pid: <PID>` and `Command line : <args>` pairs.

**Result:** 37/37 entries parse correctly with `Process`, `PID`, `CommandLine` fields.

---

### Bug #5 — cmdscan/consoles first record polluted with *** error messages (FIXED 2026-06-20)

**Files:** `utils/json_converter.py`

**Root cause:** `_parse_block_format()` filtered only lines starting with `*****` (5 asterisks). Vol2 `*** Failed to import...` distorm3 warnings start with `*** ` (3 asterisks), so they were parsed as key-value pairs and became the first JSON record.

**Fix:** Changed the filter from `line.startswith("*****")` to `line.startswith("*")`. The `***...***` process separator lines and `*** Failed...` warnings are all filtered. Separator lines between process blocks already trigger the "flush cur" path via the blank-line handling.

**Result:** cmdscan now has 1 clean entry (was 2 including error record); consoles has 3 clean entries (was 4).

---

### Bug #6 — cmd_analyzer misses pslist-failed processes (pstree fallback) (FIXED 2026-06-20)

**Files:** `modules/cmd_analyzer.windows.py`

**Root cause:** If Vol3 pslist fails (exit-0 bug), `cmd_analyzer.analyze()` built an empty `processes` dict and analyzed 0 cmdlines. `process_dumper.py` already had a pstree fallback but `cmd_analyzer` did not.

**Fix:** Added `_flatten_pstree()` static method and pstree fallback in `analyze()`, mirroring the fix in `process_dumper.py`.

---

### Module: string_hunt.py — Live Memory String Search (ADDED 2026-06-21)

**File:** `modules/string_hunt.py`  
**CLI:** `python3 crescent_toolkit.py hunt -i image.raw --hunt-strings "term1" "term2"`  
**Menu:** `[H]` in interactive menu

Searches a RAW memory image for user-specified strings using Volatility YARA plugins.
Reports PID, process name, virtual address, and matched context for each hit.
No pre-dumping required.

**Plugin map:**
- Vol3 Windows: `windows.vadyarascan.VadYaraScan` (`--yara-file <tmp.yar>`)
- Vol3 Linux:   `linux.vmayarascan.VmaYaraScan`
- Vol3 Mac:     `yarascan.YaraScan`
- Vol2 (any):   `yarascan` (text output parsed by `_parse_vol2_hits`)

**VadYaraScan JSON output fields** (confirmed 2026-06-21 on Win2012_activity.mem):
`PID` (int), `ImageFileName` (str), `Component` (str, e.g. `$s0`), `Offset` (int),
`Rule` (str), `Value` (hex string), `CreateTime`, `PPID`, `SessionId`, `Threads`, `__children`

**Flags:** `--hunt-strings`, `--hunt-pid`, `--hunt-case-sensitive`, `--hunt-no-wide`

**Output files:** `json/string_hunt.json`, `string_hunt.txt`

**Performance note:** Scans all VAD regions in every process. On a 2+GB image with
100+ processes this can take minutes. Use `--hunt-pid` to restrict to specific PIDs.

**Test:** 123 hits in 3.0s on Win2012_activity.mem (3 terms, PIDs 548+460 only).

---

### Bug #7 — cmdscan/consoles interactive command history never analyzed (FIXED 2026-06-20)

**Files:** `modules/cmd_analyzer.windows.py`

**Root cause:** `cmd_analyzer` only read `pslist` + `cmdline` (active process cmdlines). `cmdscan`/`consoles` capture historically-typed commands in CMD windows — even after the process exits — and these were never pattern-matched against CMD_PATTERNS.

**Fix:** Added extraction of `Cmd #N @ 0x...` fields from cmdscan and `Input#N` / `OriginalTitle` from consoles. All extracted strings are run against CMD_PATTERNS and appear in `shell_history` list in the returned results dict.

---

### Bug #1 — ProcessDumper loads 0 processes from pslist (FIXED)

**File:** `modules/process_dumper.windows.py` (process_dumper is OS-split; `process_dumper.py` is the dispatcher)

**Symptom:** "Loaded 0 unique processes" when running `dump-procs` on Windows.raw.

**Root cause:** `windows_pslist_PsList.json` was 380 bytes of error text ("Unsatisfied requirement plugins.PsList.kernel.symbol_table_name") not valid JSON. Vol3 exit-0 bug — Vol3 returned rc=0 even though pslist failed. The `load_processes()` function loaded 0 processes and stopped.

**Fix:** Added `_flatten_pstree()` static method and pstree fallback. If pslist is empty, the function now loads `windows_pstree_PsTree.json` and flattens its nested `__children` tree structure:

```python
@staticmethod
def _flatten_pstree(nodes: list) -> list:
    """Flatten Vol3 pstree nested __children into a flat list."""
    result = []
    for n in nodes:
        result.append(n)
        children = n.get("__children") or n.get("Children") or n.get("children") or []
        if children:
            result.extend(ProcessDumper._flatten_pstree(children))
    return result

def load_processes(self, output_dir: Path) -> int:
    # ... pslist load ...
    if not pslist:
        raw_tree = load_json_by_pattern(jd, "pstree")
        if raw_tree:
            pslist = self._flatten_pstree(raw_tree)
            self.log.info("pslist empty — loaded %d procs from pstree", len(pslist))
```

**Result:** 67 processes loaded from pstree, 5 suspicious detected, 2 dumped.

---

### Bug #2 — Challenge.raw misdetected as Linux (FIXED)

**File:** `modules/volatility.py` line 444

**Symptom:** Challenge.raw (Windows 7 image) ran as Linux and all 8 Linux plugins failed with "This command does not support the profile WinXPSP2x86".

**Root cause (chain of failures):**
1. Vol3 not found in first test run (running from wrong working directory context)
2. Vol2 `imageinfo` timed out at 120s — Win7 KDBG search on a 1.5GB image takes ~180-240s
3. `auto_detect()` received `None` from imageinfo and fell through to raw string scan
4. Raw string scan found Linux-like strings → returned `'linux'`
5. Vol2 internally auto-selected `WinXPSP2x86` (the actual profile) but this wasn't surfaced
6. All linux_ plugins failed because the image IS Windows

**Fix applied:**
```python
# volatility.py line 444 — was 120, now 300
rc, out, err = self._run_raw(self.vol2_cmd, image, "imageinfo", 300)
```

**Re-run result:** Vol3 found, `windows.info.Info` detected Windows correctly, 11 Windows plugins running.

---

### Bug #3 — Per-OS method calls in scheduled_tasks variants (FIXED)

**Files:** `modules/scheduled_tasks.windows.py`, `modules/scheduled_tasks.linux.py`, `modules/scheduled_tasks.mac.py`

**Symptom:** Each OS variant was calling all 6 scan methods including cross-OS ones (e.g., Windows variant calling `_scan_linux()`).

**Fix:** Each variant now calls only OS-relevant methods:
- Windows: `_scan_registry`, `_scan_filescan`, `_scan_processes`, `_scan_cmdlines`
- Linux: `_scan_linux`, `_scan_filescan`, `_scan_processes`, `_scan_cmdlines`
- Mac: `_scan_mac`, `_scan_filescan`, `_scan_processes`, `_scan_cmdlines`

---

### Bug #8 — OS misdetection + Vol3 cache stall + false ISF reject (FIXED 2026-06-30)

Full write-up: **`UBTEST_VMEM_DETECTION_CACHE_FIX_HANDOFF.md`**. Four issues hit
on a bare Ubuntu `.vmem`; three were code bugs (fixed dynamically), one is an image limitation.

**Files:** `modules/linux_identify.py`, `modules/volatility.py`,
`modules/linux_resolver.linux.py`, `modules/extractor.{linux,windows,mac}.py`.

1. **Ubuntu `.vmem` misdetected as macOS.** `fast_format_detect`/`raw_os_detect` used
   `decode("ascii", errors="ignore")` which deletes non-ASCII bytes and collapses binary into
   a contiguous run — a coincidental 4-char `xnu-` matched → "mac". **Fix:** match on **raw
   bytes** (`bytes.lower()`), require `xnu-` + digit, drop weak `mac os x`/`com.apple`.
2. **Vol3 symbol-cache never warms.** First cold run indexes ALL ISFs (~6,151 files — Windows
   pack stored twice: `windows.zip` + extracted `windows/*.pdb/`), ~700 s, committed to SQLite
   `~/.cache/volatility3/identifier.cache` table `cache` in one transaction. Fixed timeouts
   killed it mid-build (never commits → repeats forever); parallel vol.py raced/corrupted it;
   the old `extractor._warm_cache` checked *file presence* (always true → skipped warming).
   **Fix (dynamic):** new `linux_identify` helpers — `isf_cache_is_warm()` (SQLite row count),
   `run_vol_until_done()` (progress-aware: temp files + stall detection, NO fixed timeout),
   `warm_isf_cache()`. Wired into `auto_detect` banners step, resolver verify + `resolve_symbols`,
   and all three `extractor._warm_cache`.
3. **Correct ISF falsely rejected** when pslist is empty. **Fix:** `_scan_finds_processes()`
   confirms via `linux.psscan.PsScan` (raw scan) before declaring symbols broken.
4. **(Image, not a bug) bare `.vmem` with no `.vmss`/`.vmsn`** → Vol3 maps memory flat →
   pslist/pstree/psaux walk 0 processes (psscan still works). Companion file required.
   Validated: `memory.vmem` (has `memory.vmsn`) → pslist = 344 procs; `UBtest.vmem` (none) →
   pslist empty, psscan-only.

---

### Bug #9 — macOS `list_files` RecursionError + netstat 'path' + mac field mapping (FIXED 2026-07-06)

Full write-up: **`SESSION_2026-07-06_MAC_LISTFILES_NETSTAT_FLOCK.md`**. Found via a
`chall(1).raw` (Darwin 15.6.0) run where "files failed".

- **`mac.list_files` RecursionError** — stock Vol3 `_walk_vnode` recursed per
  parent level (974+ deep → over Python's 1000 limit) → empty file list → Popular
  Files 0. Fixed with an **iterative** walk; bundled at `vol_plugins/mac/list_files.py`.
- **`mac.netstat` UnboundLocalError 'path'** — shared helper
  `symbols/mac/__init__.py::files_descriptors_for_process` yielded `path` unbound
  when a fd's glob-type was falsy. Fixed (init `path=None` + guard VNODE deref).
  Framework file → not bundleable as a plugin; re-applied by new idempotent
  **`installer.apply_framework_fixes()`** (`_FRAMEWORK_FIXES`, guarded on exact
  buggy text, wired into `install_vol3()`).
- **mac netstat/pslist field-name mapping** — `Local IP`/`Remote IP`/`Remote Port`,
  no `PID` column (PID in `Process="Name/pid"`), pslist `NAME` uppercase. Added
  aliases + PID-from-`Process` + `NAME` across `network_map`, `correlator.mac`,
  `html_report.mac`, `timeline`, `comms_scanner`, `cmd_analyzer.mac`, `elk_export`.
  Result: 77 conns / 3 external (Flock Helper PID 486 → 34.199.4.67/34.107.204.85/
  54.84.224.164:443), correlation + system_info populated.

### Feature — Flock (Flock Team Messaging) added to comms (2026-07-06)

`comms_scanner.py` now recognises **Flock** (`p["flock"]`: flock.com URL / API
token / deeplink / CDN, anchored to avoid FPs) + running-process & network
correlation (`flock`/`flock helper` in `exe_map`). New `CommsScanner._DISPLAY_NAMES`
renders it as "Flock Team Messaging". Verified on chall(1).raw: PIDs 481/486, the 3
external 443 conns, 872 flock.com URLs in strings.

---

### Bug #10 — Windows Vol3 cold-start kernel-symbol race + fragile detection on large images (FIXED 2026-07-08)

Found on `Devil.mem` (8.5 GB Windows 10, Vol3). Three linked defects; all three
are now handled dynamically (progress-aware / serial-warm / self-healing), not by
guessing timeouts.

**Symptom chain in the log:**
1. `[!] Vol3 silent for 180s — aborting (stall).` during banners detection.
2. `windows.info` detection didn't confirm → fell through to Vol2 (no profile) →
   `Detected: Windows (via raw string scan)` (weakest path).
3. During extraction the **first four plugins launched** —
   `windows.info.Info`, `windows.pslist.PsList`, `windows.psscan.PsScan`,
   `windows.pstree.PsTree` — all FAILED with
   `Unable to validate the plugin requirements: ['plugins.*.kernel.symbol_table_name']`,
   while **every plugin launched after them succeeded** (cmdline, dlllist,
   handles, netscan, …). That "first batch fails, rest pass" pattern is the tell.

**Root causes:**

- **(A) Banners probe passed `-q`.** `volatility.py` step 1 ran
  `banners.Banners` with `-q`, which silences Vol3's progress bar — the exact
  stream `run_vol_until_done` watches for liveness. On a big image the FileLayer
  scan runs >stall_grace with no output → falsely killed as a stall.
  `warm_isf_cache` already documented "do NOT pass `-q`"; the lesson hadn't been
  applied to detection. **Fix:** drop `-q`, widen `stall_grace` to 300.

- **(B) `windows.info` probe used a fixed 45 s timeout.** Three sites called
  `_run_raw(..., "windows.info.Info", 45)`. On an 8.5 GB cold image, building the
  kernel symbol table (kernel-base scan → PDB → ISF) exceeds 45 s → the probe
  timed out, detection dropped to the raw-string path, and **kernel symbols were
  never established**. **Fix:** new `VolatilityWrapper._probe_windows_info()`
  uses `run_vol_until_done` (progress-aware, no fixed cap) at all three sites; it
  both detects Windows AND leaves the kernel symbols warm.

- **(C, root) Cold kernel-symbol table built concurrently by the first parallel
  batch.** `_warm_cache` only warmed Vol3's generic *ISF file-index* (via
  `banners`, which needs no symbols). The *per-image kernel PDB symbol table* is
  built lazily by the first symbol-dependent plugin. With 4 parallel jobs the
  first 4 all trigger that build at once; Vol3's Windows kernel-symbol automagic
  is **not concurrency-safe on a cold image**, so they race — all fail the
  requirement while one wins and writes the cache. This is the Windows twin of
  the Linux ISF race in Bug #8, which got a serial warm-up; Windows never did.

**Fixes (files):**
- `modules/linux_identify.py` — new `windows_symbols_ready()` and
  `warm_windows_kernel_symbols()` (serial, progress-aware, idempotent, never
  raises; bails early if symbols are genuinely missing so the existing
  `_try_symbol_download` fallback still fires).
- `modules/volatility.py` — banners `-q` removed (A); `_probe_windows_info()`
  replaces the three fixed-45 s `windows.info` probes (B).
- `modules/extractor.windows.py` — `_warm_cache` now calls
  `warm_windows_kernel_symbols()` after the ISF warm, **serially before** the
  parallel batch (C). Plus a **self-healing net**: any plugin that still fails on
  a `symbol_table_name` / `symbol table requirement` error is collected and
  **re-run serially** after the batch (symbols are warm by then), folding
  recoveries back into the OK/fail counts and clearing `_failed_parents`.

**Why "dynamic":** none of the three fixes hard-codes a timeout. (A)/(B) wait on
real Vol3 progress and adapt to image size and box speed; (C) establishes symbols
once and lets every later plugin be a cache hit, with a serial retry that only
fires if a race somehow still happens. Behaviour is identical on a warm cache
(the warm-up is a fast confirm) and on small images (progress-aware runner
returns as soon as the plugin finishes).

**Expected result on re-run:** banners no longer false-stalls; `windows.info`
detection confirms Windows/Vol3 up front; extraction shows one serial
`windows.info` warm line, then **0 symbol_table_name failures** — all 33 plugins
(incl. pslist/pstree/psscan) succeed, so the Processes tab and System Info are
populated. (Prior run silently lost the process list even though 28/33 plugins
"passed".)

---

## Known Gotchas (inherited from v5.0)

1. **Vol3 exits 0 on failure** — success = rc=0 AND output>10 bytes AND no "unsatisfied requirement" / "translation layer requirement" / "symbol table requirement"
2. **`--parallelism threads` is DISABLED** — Vol3 in-process threading breaks Windows plugins. Parallelism = separate ThreadPoolExecutor jobs
3. **Linux/macOS ISF symbols** — Auto-downloaded from Abyss-W4tcher/volatility3-symbols with jsDelivr CDN fallback
4. **linux.bash.Bash on LiME format** — LiME byte scanner fails; expected. On VMware vmem format (linux.vmem), bash WORKS (485s)
5. **linux.sockstat on linux.vmem** — Times out at 300s cap (VMware vmem, not LiME). Expected
6. **mac.bash.Bash on MAC image** — Consistently fails this image
7. **windows.connections/connscan on Win7+** — XP-era plugins, fail on Win7/2012/Win10. Use netscan instead
8. **RAM bottleneck** — `safe_jobs = max(1, int((avail_GB - 1.0) / per_job_GB))`, per_job_GB=1.5 normal / 1.0 fast
9. **linux.vmem is slow (two phases)**:
   - Extraction: ~22.7 min (psaux/bash 485s each, proc.Maps 448s, lsof 264s, sockstat TIMEOUT 300s)
   - Post-extraction IOC scan: scans 17.8M string lines × 32 patterns — can take 20-30 more min
   - Total full pipeline: 45-60 min. Use `-j 2` and plan for long wait
10. **First Vol3 run on a COLD symbol cache pays a one-time ~700 s cache build** ("Updating caches for N files…", N≈6151 because the Windows pack is stored twice). It now runs to completion (progress-aware, `run_vol_until_done`) and commits to SQLite `~/.cache/volatility3/identifier.cache` (table `cache`); every later run reuses it (`isf_cache_is_warm()` checks row count, NOT file presence). A run that *looks* frozen at "banners detection" or symbol verification is usually this silent scan — it is NOT stuck. To halve it, delete the duplicate extracted Windows symbols `volatility3/volatility3/symbols/windows/*.pdb/` (keep `windows.zip`). Never run multiple toolkit/vol.py instances at once — concurrent writers corrupt the half-built SQLite cache (it stays 0 rows and never warms).
11. **macOS Vol3 JSON uses different field names than Windows/Linux — audit every
    `_gv`/alias list when touching a mac path.** mac **netstat** rows are
    `Local IP` / `Local Port` / `Remote IP` / `Remote Port` / `Proto` / `State` /
    `Process` (= `"Name/pid"`) — **there is NO `PID` column** (PID is inside
    `Process`). mac **pslist** uses `NAME` (uppercase), `PID`, `PPID`, `UID`,
    `GID`, `Start Time`. `_gv` (and the report's JS `gv`) are exact-match, so a
    missing alias silently returns "". This bit `network_map`, `correlator.mac`,
    `html_report.mac`, `timeline`, `comms_scanner`, `cmd_analyzer.mac`,
    `elk_export` (all fixed 2026-07-06 — see
    `SESSION_2026-07-06_MAC_LISTFILES_NETSTAT_FLOCK.md`).
12. **`mac.list_files` can hit `RecursionError` on large images** — the stock Vol3
    plugin walked the vnode parent chain recursively (1 frame/level). CresCentC
    now ships an **iterative** patched copy at `vol_plugins/mac/list_files.py`
    (bundled like `mac.pagecache`). If a fresh Vol3 clone ever reverts it, the
    installer re-copies it. If mac Popular Files shows 0 entries, check that
    `mac_list_files_List_Files.json` isn't a 2-byte `[]` (the crash signature).
13. **Bare VMware `.vmem` needs its `.vmss`/`.vmsn` companion** (same base name, same dir). Without it Vol3 stacks only `FileLayer` (flat) and the virtual→physical walk fails on ≥4 GB VMs (PCI hole) — `pslist`/`pstree`/`psaux`/`lsof` return 0 processes even with the correct ISF and a found DTB. `linux.psscan` (raw scan) still works and proves it's a layout issue, not an ISF issue. The resolver's symbol verification falls back to psscan so it won't falsely reject the ISF, but the toolkit's plugin set is all list-walk, so process tabs stay empty until the companion file is present.
14. **Windows Vol3 kernel symbols must be warmed SERIALLY before the parallel batch** — the per-image kernel symbol table (kernel-base scan → PDB → ISF) is built lazily by the first symbol-dependent plugin, and Vol3's Windows automagic is **not concurrency-safe on a cold image**. If ≥2 plugins hit it at once (they always do — the first parallel batch is `info`/`pslist`/`psscan`/`pstree`) they race and all fail `['plugins.*.kernel.symbol_table_name']` while one wins and warms the cache; every plugin after them passes. The "first batch fails, everything else passes" pattern in the log IS this race — not missing symbols. Fixed 2026-07-08 (Bug #10): `extractor.windows._warm_cache` calls `linux_identify.warm_windows_kernel_symbols()` once, serially, up front, plus a self-healing serial retry of any `symbol_table_name` casualty after the batch. **Never diagnose this as "windows.zip missing" when later plugins succeed** — the symbols are present, they were just built mid-race. Also: probes for `windows.info` / `banners` on large images must be progress-aware (`run_vol_until_done`), never a fixed short timeout, or detection self-aborts (`Vol3 silent for 180s`) / times out at 45 s and drops to the raw-string path.
15. **Free disk space before a big run.** A full run on an 8.5 GB image writes hundreds of MB (strings, dumps, per-plugin JSON) and Vol3 spills temp files. Watch `df -h /`. A stealth space-eater on VMware guests: dragging the image into the VM leaves a **full duplicate** under `~/.cache/vmware/drag_and_drop/<rand>/` — safe to delete (`rm -rf ~/.cache/vmware/drag_and_drop/*`). `sudo apt clean` reclaims `/var/cache/apt/archives`. An `ENOSPC` mid-run corrupts nothing here (JSON writes are atomic-ish) but can truncate the report.

---

## Test Images

Location: `/home/kali/Desktop/Ramdumps for testing/`

| File | Size | OS | Notes |
|------|------|----|-------|
| `Windows.raw` | 2.1GB | Windows 10 | Vol3 primary |
| `Windows2.raw` | 2.1GB | Windows 7 | Vol2 (Win7SP1x64), has EVTX |
| `Win2012_activity.mem` | 512MB | Windows Server 2012 | Vol3, smallest/fastest |
| `linux.vmem` | 4.1GB | Linux 6.5.0-41-generic | Vol3, VMware format, slow |
| `MAC` | 1.1GB | macOS | Vol3, mac.bash.Bash expected fail |
| `Challenge.raw` | 1.5GB | Windows 7 (Win7SP1x64) | Vol3 detected via windows.info |
| `linux.vmsn` | 5.4MB | VMware snapshot | Not a full RAM image — skip |

---

## v6 Test Results (2026-06-15)

All tests run from `/home/kali/Desktop/CresCentC_v6/` with outputs at `/home/kali/Desktop/test_runs/`.

### Windows.raw — Vol3 Windows (PASS)
```
Output dir:   /home/kali/Desktop/test_runs/v6_windows_raw/
Engine:       vol3   Profile: N/A   Duration: 226.8s
Plugins:      10/11 OK, 1 failed (pslist — Vol3 exit-0 bug, empty JSON)
Fallback:     pstree loaded 67 processes (bug fix #1)
EVTX:         97 files, 26,946 events
Report:       6.2MB HTML
Dump-files:   168 files extracted (134 types: 1622 DLL, 246 EXE, 97 EVTX)
Dump-procs:   5 suspicious detected, 2/5 dumped
Status:       PASS
```

### Windows2.raw — Vol2 Win7 (PASS)
```
Output dir:   /home/kali/Desktop/test_runs/v6_windows2_raw/
Engine:       vol2   Profile: Win7SP1x64   Duration: 150.5s
Plugins:      14/16 OK, 2 failed (connections/connscan — XP-era, not Win7)
EVTX:         66 files, 191 events
Report:       2.69MB HTML
Dump-files:   working   Dump-procs: working
Status:       PASS (2 failures expected — connections/connscan XP-only)
```

### Win2012_activity.mem — Vol3 Windows Server 2012 (PASS)
```
Output dir:   /home/kali/Desktop/test_runs/v6_win2012/
Engine:       vol3   Profile: N/A   Duration: 57.3s
Plugins:      11/11 OK
EVTX:         127 files
Dump-files:   working   Dump-procs: working
Status:       PASS (perfect run)
```

### MAC — Vol3 macOS (PASS)
```
Output dir:   /home/kali/Desktop/test_runs/v6_mac/
Engine:       vol3   Profile: N/A   Duration: 56.6s
Plugins:      8/9 OK, 1 failed (mac.bash.Bash — expected on this image)
ISF symbols:  auto-downloaded from Abyss-W4tcher/volatility3-symbols
Report:       5.7MB HTML
Dump-files:   17,407 file entries listed (mac content recovery not supported)
Dump-procs:   working
Status:       PASS (1 expected failure)
```

### linux.vmem — Vol3 Linux 6.5.0-41-generic (PASS)
```
Output dir:   /home/kali/Desktop/test_runs/v6_linux/
Engine:       vol3   Profile: N/A   Jobs: 2   Total duration: 38m 3s (2283.8s)
ISF symbols:  already cached (kernel 6.5.0-41-generic)
Processes:    344 (systemd, kthreadd, and 342 more)
Plugins:      9/10 OK, 1 failed (sockstat timeout — 300s cap on VMware)
Plugin timings (actual measured):
  linux.pslist.PsList          141.4s
  linux.pstree.PsTree          142.1s
  linux.psaux.PsAux            485.8s  ← pairs with bash
  linux.bash.Bash              485.3s  ← pairs with psaux (bash WORKS on vmem format)
  linux.lsmod.Lsmod             21.4s
  linux.check_modules           12.3s
  linux.sockstat.Sockstat   TIMEOUT (300s cap — VMware image issue, expected)
  linux.lsof.Lsof              264.4s
  linux.pagecache.Files        145.2s
  linux.proc.Maps              448.4s
Total extraction: 1362.2s (~22.7 min)
Strings (4.1GB image): ASCII 327MB / 17.8M lines, took 84s
IOC scan: ~17 min on 17.8M lines × 32 patterns (large; linux kernel symbols match many patterns)
Report:       7.5MB HTML (7,566,923 bytes)
Popular files: 206 entries, 66 suspicious
Commands:     0 flags, 1 suspicious chain, 1 MITRE technique (linux)
Scheduled:    2 findings (cron processes)
Dump-files:   215 files from lsof (81 none-ext, 46 .sublime-package, 19 .sqlite, 14 .db, 11 .log)
Dump-procs:   344 processes, 1 flagged (cron PID 6420 — unexpected parent PID 859, not systemd)
Status:       PASS
```

### Challenge.raw — Vol3 Windows 7 (PASS — was FAIL, now fixed)
```
Output dir:   /home/kali/Desktop/test_runs/v6_challenge/
First run:    FAILED — 0/8 plugins (misdetected as Linux — bug #2)
Root cause:   Vol3 not found in first test run; Vol2 imageinfo timed out at 120s;
              raw string scan falsely detected Linux; Vol2 auto-chose WinXPSP2x86 
              internally; all linux_ plugins failed with "profile not supported"
Fix applied:  imageinfo timeout 120s → 300s in volatility.py:444
Re-run:       Vol3 found, windows.info.Info detected Windows in 58s
Engine:       vol3   Profile: N/A (Vol3 autodetect)   Duration: 133.3s
Plugins:      11/11 OK (perfect run)
Report:       5.5MB HTML
Dump-files:   3218 files, 155 extensions (842 DLL, 239 TTF, 99 SYS, 54 EXE, 38 EVTX)
Dump-procs:   53 processes, 2 suspicious (csrss.exe × 2 = multi-instance flag), both dumped
Note:         VirtualBox Win7 image — VBoxService.exe visible, IP 10.0.2.15 (VBox NAT)
Status:       PASS
```

### Output Directory Structure
```
v6_windows_raw/
├── json/                    # All plugin JSON files
│   ├── windows_info_Info.json
│   ├── windows_pslist_PsList.json
│   └── ...
├── iocs/                    # popular_files.json, scheduled_tasks.json
├── txt/                     # Human-readable text versions
├── dumped_files/            # (after dump-files command)
├── dumped_processes/        # (after dump-procs command)
├── report.html              # Interactive 11-tab HTML report
├── SUMMARY.txt
├── correlation_report.txt
├── network_map.txt
├── process_tree.txt
└── crescent_toolkit.log
```

---

## Plugin Key Scheme

Plugins are keyed as `f"{vol_version}-{os_type}-{mode}"`:

| Key | Example plugins |
|-----|-----------------|
| `vol3-windows-fast` | pslist, pstree, cmdline, netscan, malfind, svcscan, hashdump, hivelist, printkey, filescan |
| `vol3-windows-full` | + dlllist, handles, dumpfiles, memmap |
| `vol3-windows-malware` | + ssdt, callbacks, driverirp, bigpools |
| `vol2-windows-fast` | imageinfo, pslist, pstree, psscan, cmdline, cmdscan, consoles, netscan, connections, connscan, malfind, svcscan, hashdump, hivelist, printkey, filescan |
| `vol3-linux-fast` | pslist, pstree, psaux, bash, lsmod, check_modules, sockstat, lsof, proc.Maps, pagecache.Files |
| `vol3-mac-fast` | pslist, pstree, psaux, bash, netstat, lsmod, malfind, list_files, proc_maps |

VOL2_EXCLUSIVE plugins (Windows Vol2 only): `cmdscan consoles hashdump shellbags shimcache iehistory clipboard deskscan atoms atomscan timers messagehooks eventhooks apihooks`

---

## Quick Reference for Future Sessions

### First thing to check
```bash
ls /home/kali/Desktop/CresCentC_v6/modules/*.py | head -30
# Verify all dispatchers and OS-specific files exist
```

### Run tests
```bash
cd /home/kali/Desktop/CresCentC_v6

# Windows Vol3 test
python3 crescent_toolkit.py full -i "/home/kali/Desktop/Ramdumps for testing/Windows.raw" \
  -o /home/kali/Desktop/test_runs/v6_windows_raw -m fast --speed normal -j 2

# Windows Vol2 test (Win7)
python3 crescent_toolkit.py full -i "/home/kali/Desktop/Ramdumps for testing/Windows2.raw" \
  -o /home/kali/Desktop/test_runs/v6_windows2_raw -m fast --speed normal -j 2

# Windows Server 2012 test (fastest Windows, 512MB)
python3 crescent_toolkit.py full -i "/home/kali/Desktop/Ramdumps for testing/Win2012_activity.mem" \
  -o /home/kali/Desktop/test_runs/v6_win2012 -m fast --speed normal -j 2

# macOS test
python3 crescent_toolkit.py full -i "/home/kali/Desktop/Ramdumps for testing/MAC" \
  -o /home/kali/Desktop/test_runs/v6_mac -m fast --speed normal -j 2

# Linux test (slow — 30-90 min)
python3 crescent_toolkit.py full -i "/home/kali/Desktop/Ramdumps for testing/linux.vmem" \
  -o /home/kali/Desktop/test_runs/v6_linux -m fast --speed fast -j 2

# Challenge.raw (detected as Windows 7 via windows.info.Info)
python3 crescent_toolkit.py full -i "/home/kali/Desktop/Ramdumps for testing/Challenge.raw" \
  -o /home/kali/Desktop/test_runs/v6_challenge -m fast --speed normal -j 2
```

### Run dump-files on a completed output (interactive)
```bash
cd /home/kali/Desktop/CresCentC_v6
# Option 3 = Show statistics (non-destructive)
printf "3\nQ\n" | python3 crescent_toolkit.py dump-files \
  -i "/home/kali/Desktop/Ramdumps for testing/Challenge.raw" \
  -o /home/kali/Desktop/test_runs/v6_challenge

# Option 4 = Dump all files (with confirmation 'y')
printf "4\ny\nQ\n" | python3 crescent_toolkit.py dump-files \
  -i "/home/kali/Desktop/Ramdumps for testing/Challenge.raw" \
  -o /home/kali/Desktop/test_runs/v6_challenge
```

### Run dump-procs on a completed output (interactive)
```bash
cd /home/kali/Desktop/CresCentC_v6
# Option 3 = Show suspicious processes
printf "3\nQ\n" | python3 crescent_toolkit.py dump-procs \
  -i "/home/kali/Desktop/Ramdumps for testing/Challenge.raw" \
  -o /home/kali/Desktop/test_runs/v6_challenge
```

### Check the HTML report
```bash
ls -lh /home/kali/Desktop/test_runs/v6_challenge/report.html
# Open in browser: firefox /home/kali/Desktop/test_runs/v6_challenge/report.html
```

---

## Dispatcher Implementation Pattern (for adding new OS-split modules)

To add a new module split (e.g., `foo.py` → `foo.windows.py`, `foo.linux.py`, `foo.mac.py`):

1. Create `modules/foo.windows.py`, `modules/foo.linux.py`, `modules/foo.mac.py` with the class `Foo`.
2. Create `modules/foo.py` as the dispatcher:

```python
import importlib.util
import pathlib

_DIR = pathlib.Path(__file__).parent
_OS_MAP = {'linux': 'foo.linux', 'mac': 'foo.mac'}

def _load(os_type: str):
    name = _OS_MAP.get(str(os_type).lower(), 'foo.windows')
    spec = importlib.util.spec_from_file_location(name, _DIR / (name + '.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def Foo(logger, os_type, *args, **kwargs):
    return _load(os_type).Foo(logger, *args, **kwargs)
```

3. Update any callers in `crescent_toolkit.py` to pass `vol.os_type`.

---

## ISF Symbol Locations

Linux/macOS Vol3 needs ISF (Intermediate Symbol Format) files:

```
/home/kali/Desktop/volatility3/volatility3/symbols/linux/
  └── ubuntu-6.5.0-41-generic-amd64.json.xz   # linux.vmem kernel

/home/kali/Desktop/volatility3/volatility3/symbols/mac/
  └── macOS_KDK_*.json.xz                       # macOS image symbols
```

If symbols are missing, `linux_resolver.linux.py` auto-downloads from:
- Primary: `https://github.com/Abyss-W4tcher/volatility3-symbols`
- CDN fallback: `https://cdn.jsdelivr.net/gh/Abyss-W4tcher/volatility3-symbols`

Kernel version is detected by reading the first 10MB of the image looking for `Linux version X.Y.Z-N-generic` strings.

For Linux images whose exact kernel banner isn't in the community repo (e.g. a Kali kernel built from a Debian source), `linux_resolver` downloads the closest ISF and runs `_patch_isf_banner()` — it rewrites the `linux_banner.constant_data` field inside the `.json.xz` to byte-match the image's actual banner, then re-verifies. Produces a `*_patched.json.xz` alongside the base ISF.

---

## HTML Report — 11 Tabs

1. Processes · 2. Network · 3. Shell Commands · 4. Malware · 5. Files · 6. Services · 7. Popular Files · 8. Scheduled Tasks · 9. Registry · 10. IOCs · 11. Summary

The report is a single self-contained `report.html` that opens offline. There is **no** "Directory Grep" tab (removed) and **no** ANASWEH mode / CresCent Eye (removed).

**Global cross-tab search (added 2026-07-06).** The header has a search box that
highlights matches across **every** tab at once (all pages render into the DOM at
load, so a `TreeWalker` over each `#page-*` container can wrap matches in
`mark.ghit`). Per-tab hit-count chips jump to a tab; ▲/▼ (or Enter / Shift+Enter)
cycle through all matches, switching tabs and scrolling as needed; `/` or Ctrl/⌘-K
focuses the box, Esc clears. Debounced 250 ms, capped at 3000 highlights, skips the
graph canvas (it has its own transform). The three OS templates
(`html_report.{windows,linux,mac}.py`) are ~99% identical; the search code
(CSS + header input + `gs*` JS) is byte-identical in all three — apply edits to all
three. Standalone JS is ES5; validate with `pyjsparser` since no JS engine is
installed (`pip install pyjsparser --break-system-packages`).

**Report OS-dispatch bug (FIXED 2026-07-06):** `crescent_toolkit._cmd_report`
hard-coded `HTMLReportGenerator(logger, None)` → the dispatcher fell back to the
**Windows** builder, so regenerating a Linux/macOS report via `report -o <dir>`
mislabelled it `6.0-windows` and used Windows-only field/label logic. Fixed to read
`_read_os_type(od)` (from `SUMMARY.txt`'s `OS:` line) and pass it. Verified across
26 report dirs: builders now match the image OS.

---

## Version Lineage

| Version | Location | Role |
|---------|----------|------|
| Original `CresCentC_Fixed` | `/home/kali/Desktop/CresCentC_Fixed` | baseline — never modify |
| v2 `CresCentC_Fixed_v2` | `/home/kali/Desktop/CresCentC_Fixed_v2` | Vol2 printkey + popular_files + scheduled_tasks + 11-tab HTML |
| v4.1 `CresCent_Toolkit_v4.1` | `/home/kali/Desktop/CresCent_Toolkit_v4.1` | 14 module quality fixes (see below) |
| v5.0 `CresCent_Toolkit_v5.0` | `/home/kali/Desktop/CresCent_Toolkit_v5.0` | merged v2 + v4.1 |
| **v6.0** | `/home/kali/Desktop/CresCentC_v6/` | **active** — OS-split dispatcher refactor of v5.0 |

---

## Inherited v4.1 Design Decisions (why present code looks the way it does)

These quality fixes were made in v4.1 and carried through to v6. They explain non-obvious code; do not "simplify" them away.

| Module | Decision |
|--------|----------|
| `ioc_extractor` | AWS secret-key regex is **context-anchored** (requires `aws_secret_access_key=` etc.) — a bare `\b[0-9a-zA-Z/+]{40}\b` matched every SHA1/JWT (9427 false hits on MAC). Hash low-variety filter (≥4 distinct hex chars) applies to MD5/SHA1/SHA256. TLD list deliberately includes modern C2 TLDs (.app .dev .sh .zip …). |
| `network_map` | `_is_private_ip()` uses Python's `ipaddress` module incl. an explicit CGNAT (100.64/10) check — a string-prefix check mislabeled 172.16/12 and CGNAT as external. |
| `comms_scanner` | `_is_plausible_discord_token()` base64-decodes the first segment and requires a 17–20 digit snowflake ID — raw JWTs were false-flagged as stolen Discord tokens. |
| `correlator` | NTLM hashes **redacted by default** (`redact_hashes=True`, `_mask_hash()` keeps first/last 4). Unredacted data stays in `json/hashdump_vol2.json`. |
| `process_tree` | Orphans tagged `[ORPHAN — missing PPID N]`, distinct from true OS roots. |
| `process_dumper` | "Hidden (psscan only)" flag only applied when pslist actually returned results; whole-word tokenization avoids `nc` matching `kworker/...`; `systemd --user` not counted as duplicate systemd. |
| `evtx_parser` | strings fallback marks each event `_low_fidelity: True` (BinXml can't be meaningfully parsed by `strings`). |
| `extractor` | resume validation checks 6 failure markers (traceback, exceptions, layer/symbol-table fulfilment) over a 2000-char window, not just file size. |
| `timeline` | filters placeholder epochs incl. FAT (1980-01-01) alongside FILETIME-zero / Unix-0 / .NET-min. |
| `browser_history` | URLs run through `urllib.parse.unquote` before reporting. |
| `auto_hash` | VirusTotal lookups throttled to 16s/call with explicit 429 back-off (public API = 4/min). |
| `html_report` | grep server tries ports 8765–8774 sequentially. |
| `linux_resolver` | ISF/banners downloads have mirror fallback (raw.githubusercontent → jsDelivr CDN → main branch). |
| `cmd_analyzer` | defensive lowercase at the SUSPICIOUS_CHAINS comparison site. |
| `popular_files` | bucket ordering matters: `/var/tmp` before `/tmp`, `/usr/bin` before `/bin` (substring-collision avoidance). |
