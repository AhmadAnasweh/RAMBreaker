# RAMBreaker / CresCent Toolkit — Testing Context for Claude Code

> **Read this whole file before testing.** It tells you what the tool is, how to invoke
> every part of it, what *correct* output looks like versus a *false failure*, and the
> Volatility quirks that will fool you into reporting bugs that aren't bugs. Several
> "failures" in this tool are actually expected Volatility behavior — this doc tells you
> which ones.

---

## 0. TL;DR for the test run

- This is a **Python CLI** that wraps **Volatility 2 and Volatility 3** to analyze
  **Windows, Linux, and macOS** memory images. It surfaces raw evidence + correlations;
  it deliberately makes **no automated threat verdicts**.
- Entry point: `crescent_toolkit.py`. Code lives in `modules/` and `utils/` packages.
- Test against every memory dump in the working tree. Treat dumps as **read-only**.
- **The #1 cause of false test failures is misreading expected Volatility behavior.**
  See §7 (Gotchas) before logging any bug.
- Run fully autonomously. Use generous timeouts. Keep a running log on disk. Write a
  final report. Do not ask questions.

---

## 1. What the tool does

Feed it a memory image; it auto-detects the OS, picks the right Volatility engine,
downloads symbols if needed (Linux/macOS), runs a battery of plugins in parallel,
extracts strings/IOCs/browser/chat artifacts in a single pass, reconstructs the process
tree and network map, correlates everything, builds a timeline, and emits one
self-contained interactive `report.html` (plus optional SIEM export and a zip pack).

Design principle, enforced everywhere: **present raw data, never label it malicious.**
If you see a "suspicious process" list, those are *observations* (unexpected parent,
multiple instances, hidden-from-pslist), not accusations. Don't "fix" that to add threat
scores — it's intentional.

---

## 2. Project structure (real layout)

```
<root>/
├── crescent_toolkit.py          # main entry: CLI, interactive menu, pipeline orchestration
├── modules/                     # all analysis + engine modules
│   ├── volatility.py            # Vol2/Vol3 wrapper, OS detection, plugin execution
│   ├── extractor.py             # parallel plugin runner, PLUGINS dict, adaptive jobs
│   ├── process_dumper.py        # process EXE + full-memory dumping
│   ├── file_dumper.py           # file recovery (Win/Linux/Mac)
│   ├── process_tree.py          # hierarchical process tree
│   ├── network_map.py           # external IPs + reverse DNS
│   ├── correlator.py            # cross-references many JSON sources
│   ├── timeline.py              # chronological merge
│   ├── registry_explorer.py     # hives, userassist, shellbags, persistence
│   ├── cmd_analyzer.py          # command-line analysis + MITRE ATT&CK mapping
│   ├── ioc_extractor.py         # regex IOC extraction
│   ├── browser_history.py       # URL/search/download recovery
│   ├── comms_scanner.py         # chat-app artifacts (Teams/Discord/Slack/…/Flock)
│   ├── system_info.py           # host/users/IPs/OS (cross-platform)
│   ├── strings_extractor.py     # parallel ASCII+Unicode strings
│   ├── evtx_parser.py           # Windows event log parsing
│   ├── html_report.py           # the self-contained report
│   ├── elk_export.py            # Elasticsearch/Kibana NDJSON
│   ├── export_pack.py           # zip all results
│   ├── linux_resolver.py        # Linux/macOS ISF symbol auto-download
│   ├── logger.py                # centralized logging
│   └── installer.py             # installs Vol2/Vol3 + symbols + deps
└── utils/
    ├── json_converter.py        # load_json_by_pattern() — used everywhere
    └── ui.py                    # msg_info/msg_ok/msg_fail/msg_warn, prompts, colors
```

> NOTE: if you uploaded this to a Claude Project, files appear flat there — but the real
> on-disk layout is the package structure above. Imports are absolute
> (`from modules.x import ...`, `from utils.x import ...`), so run from `<root>`.

Possibly-present extra modules not on the main import path: `yara_scanner.py`,
`memory_grep.py`, `auto_hash.py`. Test them only if the menu/CLI exposes them.

---

## 3. How to invoke it

### Interactive (primary UX)
```
python3 crescent_toolkit.py
```
Then choose a run mode or an individual tool from the menu (see §5).

### CLI flags
| Flag | Meaning |
|------|---------|
| `-i, --image` | memory image path (it is `-i`, **not** `-f`) |
| `-o, --output` | output dir (default: derived from image name) |
| `-m, --mode` | **plugin profile**: `fast`, `full`, `malware`, `network`, `persistence`, `registry` (default `full`) |
| `--vol2` / `--vol3` | force a Volatility engine |
| `--speed` | `normal` (RAM-safe, default), `fast` (tighter RAM budget, more jobs), `fastest` (max jobs, no RAM guard) |
| `-j, --jobs` | max parallel plugin jobs (default 4) |
| `--timeout` | base per-plugin timeout (seconds, default 600) |
| `--profile` | force a Vol2 profile |
| `--pattern` | file-dump pattern (e.g. `evtx`, `exe`) |
| `--strings-mode` | `all` / `ascii` / `unicode` / `both` |
| `--hunt-strings`, `--hunt-pid`, `--hunt-case-sensitive`, `--hunt-no-wide` | String Hunt options (for the `hunt` command) |
| `-q, --quiet`, `--log` | logging controls |

The **positional command** (verified against `crescent_toolkit.py`) is one of:
`menu, extract, dump-files, dump-procs, strings, correlate, iocs, report, timeline,
evtx, export, elk, core, full, hunt` (default `menu`). The individual analysis modules
(tree, network, registry, browser, comms, cmd, mitre, …) are reached through the
**interactive menu** (§5), not as positional commands.

### TWO different "mode" concepts — don't conflate them
1. **`--mode` = plugin profile** → selects which plugin *set* runs
   (`full` → `vol3-windows-full`, `malware` → `vol3-windows-malware`, etc.). See §6.
2. **CORE `[C]` / DEFAULT `[D]` = pipeline depth** (interactive menu):
   - **CORE** = the 8-step pipeline (no EVTX).
   - **DEFAULT** = CORE **+ Windows Event Log (EVTX) dump & parse.**
   Both prompt for a **speed mode** at launch.

---

## 4. The 8-step pipeline (what CORE/DEFAULT run)

1. **Volatility extraction** — run the plugin set in parallel → `json/*.json`
   - 1b. **System Info** — host/users/IPs/OS (now cross-platform; see §7.6)
2. **Strings + IOC + Browser + Comms** — a **single pass** over the strings file
   (the IOC extractor reads each line once and feeds the browser + comms scanners)
3. **Process Tree + Network Map**
4. **Process analysis + Command analysis + MITRE** (Windows)
5. **Correlation** — cross-reference many JSON sources
6. **Registry** (Windows)
7. **Timeline** — merge 7 timestamp sources
8. **HTML report**

Windows-only steps (4, 6, EVTX) auto-skip on Linux/macOS.

---

## 5. Interactive menu — every tool to test

| Key | Tool | Module |
|-----|------|--------|
| `C` | CORE mode (8-step pipeline) | pipeline |
| `D` | DEFAULT mode (CORE + EVTX) | pipeline |
| `1` | Extractor (run plugins, parallel) | extractor |
| `2` | File Dumper | file_dumper |
| `3` | **Process Dumper** (see §7.7 — this had the recent bug) | process_dumper |
| `4` | Strings | strings_extractor |
| `5` | Correlator | correlator |
| `7` | IOC Extractor | ioc_extractor |
| `8` | Process Tree | process_tree |
| `9` | Network Map | network_map |
| `10` | Registry | registry_explorer |
| `13` | Browser History | browser_history |
| `14` | Comms Scanner | comms_scanner |
| `15` | Command Analysis | cmd_analyzer |
| `16` | MITRE ATT&CK | cmd_analyzer |
| `11` | Timeline | timeline |
| `12` | EVTX Parser (Windows) | evtx_parser |
| `H` | **String Hunt** (live-memory YARA search for user strings) | string_hunt |
| `R` | HTML Report | html_report |
| `E` | Export Pack (zip) | export_pack |
| `K` | ELK/Kibana Export | elk_export |
| `I` | Installer (Vol2+Vol3+symbols+deps) | installer |

> **String Hunt** (`H` / `hunt` command) searches the raw image directly via Volatility
> YARA plugins (`windows.vadyarascan.VadYaraScan`, `linux.vmayarascan.VmaYaraScan`,
> mac/Vol2 `yarascan`) and reports PID + process + virtual address per match. No
> pre-dumping needed. Restrict with `--hunt-pid` on large images. See ARCHITECTURE_V6.md.

Test each standalone against already-extracted data, plus the output generators
(`R`, `E`, `K`). Validate each artifact (JSON parses, HTML opens, zip intact, NDJSON
well-formed).

---

## 6. Complete plugin inventory (the PLUGINS dict)

The extractor picks a key as `vol{2,3}-{os}-{profile}`. `--mode full` → the `-full` key.

**Windows / Vol3 (`vol3-windows-full`, 28):**
`windows.info.Info, pslist.PsList, psscan.PsScan, pstree.PsTree, cmdline.CmdLine,
dlllist.DllList, handles.Handles, getsids.GetSIDs, envars.Envars, privileges.Privs,
sessions.Sessions, ldrmodules.LdrModules, netstat.NetStat, netscan.NetScan,
malfind.Malfind, ssdt.SSDT, callbacks.Callbacks, registry.hivelist.HiveList,
registry.userassist.UserAssist, svcscan.SvcScan, driverscan.DriverScan, modules.Modules,
modscan.ModScan, filescan.FileScan, mftscan.MFTScan, vadinfo.VadInfo,
mutantscan.MutantScan, hashdump.Hashdump`

**Windows / Vol2 (`vol2-windows-full`, ~48):** imageinfo, pslist, psscan, pstree, psxview,
cmdline, cmdscan, consoles, dlllist, handles, getsids, envars, privs, sessions,
ldrmodules, netscan, netstat, connections, connscan, sockets, sockscan, malfind, ssdt,
callbacks, driverirp, driverscan, modules, modscan, filescan, mutantscan, symlinkscan,
hivelist, userassist, shellbags, shimcache, mftparser, svcscan, timers, atoms, atomscan,
clipboard, deskscan, messagehooks, eventhooks, thrdscan, vadinfo, iehistory, hashdump.
- `VOL2_EXCLUSIVE` (run alongside Vol3 on Win7-era): cmdscan, consoles, hashdump,
  shellbags, shimcache, iehistory, clipboard, deskscan, atoms, atomscan, timers,
  messagehooks, eventhooks, apihooks.
- `VOL2_XP_ONLY` (profile-gated, only when the profile matches XP/2003): connections,
  connscan, sockets, sockscan.

**Linux / Vol3 (`vol3-linux-full`, 14):**
`linux.pslist.PsList, pstree.PsTree, psaux.PsAux, bash.Bash, sockstat.Sockstat,
lsmod.Lsmod, check_modules.Check_modules, check_syscall.Check_syscall,
tty_check.tty_check, elfs.Elfs, envars.Envars, library_list.LibraryList, lsof.Lsof,
mountinfo.MountInfo`

**macOS / Vol3 (`vol3-mac-full`, 20):**
`mac.pslist.PsList, pstree.PsTree, psaux.PsAux, bash.Bash, netstat.Netstat,
ifconfig.Ifconfig, lsmod.Lsmod, malfind.Malfind, check_syscall.Check_syscall,
check_sysctl.Check_sysctl, check_trap_table.Check_trap_table, kauth_listeners.Kauth_listeners,
kauth_scopes.Kauth_scopes, kevents.Kevents, list_files.List_Files, mount.Mount,
proc_maps.Maps, socket_filters.Socket_filters, timers.Timers, trustedbsd.Trustedbsd`

Each OS also has `-fast`, `-malware`, `-network` variants (and Windows adds
`-persistence`, `-registry`). Test at least `full` per dump; test the other profiles on
at least one dump per OS.

---

## 7. CRITICAL GOTCHAS — read before logging any bug

These are the things that look like bugs but usually aren't. Misreading them is the main
risk to this test run.

### 7.1 Volatility 3 exits 0 even on failure
A Vol3 plugin can return **exit code 0** while having actually failed. **Do not judge
success by exit code alone.** The toolkit already handles this: in `volatility._run_vol3`,
a run counts as success only if `returncode == 0` **and** output length > 10 **and** the
output does **not** contain any of:
- `unsatisfied requirement`
- `a translation layer requirement was not fulfilled`
- `a symbol table requirement was not fulfilled`
- and doesn't start with `error`/`exception`/`traceback`.

When *you* validate output independently, apply the same rule. A 600-byte JSON that says
"Unable to validate the plugin requirements" is a **FAIL**, not a pass.

### 7.2 `--parallelism threads` is intentionally DISABLED — do not re-enable it
Isolation testing on this Vol3 build (2.28.x) showed the threads flag **breaks Vol3
plugins**: e.g. `windows.dlllist` **with** `--parallelism threads` → `rc=1`,
"unsatisfied requirement: kernel.layer_name"; **without** it → `rc=0`, full output.
Linux/macOS were already excluded for the same reason. So the flag is off for **all**
OSes by design (`volatility._run_vol3` adds no `--parallelism`).
- **If you think "threading would speed this up" — don't add it.** It will make plugins
  fail instantly (sub-second) with kernel.layer_name / symbol_table_name errors.
- Parallelism in this tool = **multiple plugins as separate jobs** (ThreadPoolExecutor),
  not in-process Vol3 threading. That works on all OSes.

### 7.3 Linux/macOS fail instantly if symbols aren't resolved
If you ever see **all** Linux/Mac plugins fail in <1s each with
`kernel.layer_name, kernel.symbol_table_name`, the cause is **missing/mismatched ISF
symbols**, NOT the plugins and NOT threading. Symbol resolution
(`modules/linux_resolver.py`) downloads a prebuilt ISF matching the kernel banner from
the Abyss-W4tcher community repo into `symbols/linux/` (or `symbols/mac/`).
- Detection that falls through to "raw string scan" (instead of "via banners") is a hint
  that banners/symbols didn't match — but detection can also just time out under load.
- To distinguish symbols-vs-other, run by hand:
  `python3 ../volatility3/vol.py -f <dump> linux.pslist.PsList`
  If that fails too, it's symbols. If it works, the toolkit path has a different issue.
- macOS symbols above 11.0 are often unavailable upstream (Apple doesn't ship every KDK);
  the tool warns. That's an upstream limitation, not a toolkit bug.

### 7.4 `windows.netscan` is often empty on Win10 crash dumps
Vol3's `WindowsCrashDump64Layer` has a known pool-scanning bug → `netscan` returns
nothing on Win10 `.dmp` crash dumps. This is **expected**. The toolkit compensates with
the strings-based IOC extractor and browser-history scanner (multi-source validation). An
empty netscan on a crash dump is **not** a bug; check whether IOCs still surfaced the IPs.

### 7.5 RAM is the real bottleneck; jobs scale to it
Vol3 memory-maps the image, so resident RAM per plugin is ~constant (~1.5 GB).
Adaptive-jobs formula (`extractor._adaptive_jobs`):
`safe_jobs = max(1, int((avail_GB − 1.0) / per_job_GB))`, where `per_job_GB` = 1.5
(normal) or 1.0 (fast); `fastest` ignores the guard and uses all requested jobs.
- With ~1.4 GB free vs a 4 GB image, it correctly drops to **1 job** — slow but not a bug.
- With 9 GB free → ~4 jobs. If you see "1 job" and lots of RAM, that's worth flagging.
- A heavy first run also warms Vol3's one-time symbol cache; "Updating caches for N
  files…" is expected and shouldn't repeat.

### 7.6 system_info is cross-platform (recently fixed)
`system_info` must run for **all** OSes and write `json/system_info.json`. For Linux/Mac
it pulls: hostname/USER from `linux.envars`, IPs from `linux.sockstat` (field
`Source Addr`), and OS version from the kernel banner in strings. The Windows-only
`windows.info`/`getsids` extractors are gated off for Linux (so `linux_mountinfo` can't
false-match the `info` pattern). **Test:** on a Linux dump the report's Device/System-Info
tab must show hostname + OS version, not be blank.

### 7.7 Process dumping: full memory vs PE — the recent fix
Two distinct operations, do not confuse:
- **Full process memory** (heap/stack — the big ~MBs–GBs file with the real data):
  Vol3 `windows.memmap.Memmap --pid X --dump` / Vol2 `memdump -p X`. Method:
  `dump_process_memory_verbose`. Output → `dumped_processes/process_memory/pid.<PID>.dmp`.
- **EXE only** (just the PE binary, ~hundreds of KB, no heap):
  Vol3 `windows.pslist.PsList --pid X --dump` / Vol2 `procdump`. Method:
  `dump_process_exe_verbose`.

In the menu's `_procdump_selectionprompt`, the **default** (a plain process number) must
do the **FULL MEMORY** dump; `E <number>` does EXE-only; `A` dumps all EXEs (triage).
- **Test:** dumping e.g. `notepad.exe` with a plain number must produce a large memory
  file, **not** a ~270 KB PE. A small `*_exe_0x....dmp` file (starts with `MZ`) means the
  EXE path ran when it shouldn't have — that's the regression to watch.

---

## 8. Output layout (what a run produces)

```
<output_dir>/
├── json/                    # every plugin's raw JSON — the source of truth
│   ├── windows_pslist_PsList.json ...   (Vol3 names use underscores)
│   └── system_info.json, timeline.json, ...
├── iocs/                    # IOC matches, per pattern
├── comms/                   # chat-app artifacts, per app
├── dumped_files/            # recovered files / EVTX (.evtx.dat)
├── dumped_processes/
│   ├── process_memory/      # FULL memory dumps (pid.<PID>.dmp)
│   └── process_exe/         # PE-only dumps
├── strings_ascii.txt        # 100–500 MB (delete after validating to save disk)
├── strings_unicode.txt
├── report.html              # self-contained, opens offline
├── SUMMARY.txt
└── (elk_export/, export pack .zip when those tools run)
```

Vol3 JSON filenames can vary in case — match case-insensitively when you look for them.

---

## 9. How to tell success from failure (per layer)

- **A plugin "passed"** iff: file exists, JSON parses, non-trivial content, and none of
  the §7.1 failure strings present. (Empty-but-valid is legitimate for some plugins, e.g.
  `netscan` on a crash dump — see §7.4 — or `malfind` on a clean image.)
- **A pipeline run "passed"** iff: it reaches step 8 and writes `report.html`, with the
  expected per-step artifacts for that OS (Windows-only steps absent on Linux/Mac is fine).
- **A module "passed"** iff: it produces its artifact and the artifact validates
  (tree is indented hierarchy; network map has external IPs + DNS where resolvable;
  timeline is chronologically ordered; report HTML opens and tabs populate).
- **Process dump "passed"** iff: §7.7 — plain selection yields a large memory dump.

Record duration and output size for every plugin so the report can show SLOW outliers.

---

## 10. Suggested test matrix

For **each dump** in the tree (own output dir per dump under `./test_runs/<name>/`):
1. OS detection — record OS, engine, and which detection step matched.
2. Symbol resolution (Linux/Mac) — confirm an ISF is found/installed.
3. **Every plugin** in that OS's `-full` set, individually — exit/duration/size/validity
   (apply §7.1). Test the custom `crescent_hashdump` plugin too if present.
4. **Profiles**: at minimum `full`; on one dump per OS also `fast`, `malware`, `network`
   (+ `persistence`, `registry` on Windows).
5. **CORE and DEFAULT** pipelines × **normal / fast / fastest** speed = up to 6 full runs.
   Verify: process tree is hierarchical; report has **no** "Directory Grep" tab; speed is
   honored; Vol3 commands contain **no** `--parallelism threads` (§7.2); Linux/Mac
   system-info tab is populated (§7.6).
6. **Process dumper** (§7.7): plain number → full memory (big file); `E n` → PE; confirm
   sizes and headers.
7. **Every standalone tool** (§5) against extracted data + the 3 output generators.
8. **Resume**: re-run an extraction → confirm it skips already-valid plugins.
9. **Edge cases**: a truncated junk file and a non-existent path → graceful failure, no
   crash, no hang.

Manage disk: after validating a run, delete its `strings_*.txt`; keep logs, JSON,
reports. Use generous timeouts (heavy plugins legitimately take many minutes); kill a
single command only if it exceeds ~45 min, and record it as a hang.

---

## 11. Recently fixed bugs (verify these stay fixed)

| Area | Old broken behavior | Correct behavior now |
|------|--------------------|----------------------|
| Vol3 threading | `--parallelism threads` on heavy/fast runs → plugins fail instantly (kernel.layer_name) | threading disabled for **all** OSes (§7.2) |
| Success detection | exit code 0 treated as success → silent empty JSON | checks content + the three "requirement" strings (§7.1) |
| Process tree | flat list, no indentation | hierarchical box-drawing tree |
| Directory Grep tab | present in HTML report | **removed** |
| Speed selection | only in settings | prompted in CORE & DEFAULT |
| Linux system info | Device tab blank (Windows-only extractor) | cross-platform; hostname/OS/users/IPs (§7.6) |
| Process dump default | plain number dumped PE only (~270 KB) | plain number → full memory (§7.7) |
| ANASWEH mode / CresCent Eye | present | **removed** |

If any of these regressed in the version you're testing, that's a high-priority finding.

---

## 12. What to deliver

Write `./test_runs/TEST_REPORT.md` with: environment (OS, RAM, disk, Python,
Vol2/Vol3 versions); dump inventory (size, detected OS, engine, detection path); full
per-plugin matrix (PASS/FAIL/SLOW + duration + size, failures unmissable); the
CORE/DEFAULT × speed matrix; standalone-tool results; **bugs** (minimal repro + root cause
citing file/line + suggested fix); **better ways to run** (flags/invocations/plugin
choices, with evidence); **performance** (slowest plugins/modes, RAM/disk pressure); and a
prioritized "fix first" list. Keep a live `./test_runs/PROGRESS.md` updated as you go.
You may fix trivial, obviously-safe bugs and record exactly what you changed; do not do
risky refactors — document those instead.
