# RAMBreaker v2 - Windows memory-forensics workstation

RAMBreaker automates Volatility 3 and Volatility 2 analysis of RAM images
(Windows, Linux, macOS) and presents the results in a desktop GUI and an
offline HTML report. v2 is a **port and upgrade** of the original Linux-only
RAMBreaker/CresCent toolkit (github.com/AhmadAnasweh/RAMBreaker, upstream commit
`fb467f3`): it runs natively on Windows 10/11 with no WSL or Docker, and is
shipped as one folder you start by double-clicking `RAMBreaker.exe`.

Nothing is ever uploaded. Network access is optional: it is only used to fetch
symbol tables for unknown kernels. Offline, the bundled symbols, the BTF
reconstruction, and Volatility 2 profiles still work.

- **Manual with screenshots of every screen:** https://ahmad.anasweh.com/#/notes/rambreaker
- **Download:** [latest release](https://github.com/AhmadAnasweh/RAMBreaker/releases/latest)

## Using it

1. Double-click `RAMBreaker.exe`. A guided tour runs on first start.
2. Drag a memory dump (`.raw .mem .vmem .lime .dmp .bin .img`) onto the window.
3. Pick a preset:

   | Preset | What it runs |
   |---|---|
   | Standard | Plugins, strings, IOCs, e-mail, Sigma, timeline and report. Right for most cases. |
   | Quick triage | Essential plugins only. |
   | Full DFIR | Standard plus EVTX carving and the slow Volatility 2 extras. |
   | Malware / Network / Persistence / Registry | A focused plugin set. |
   | DFIR + Threat Intel | Full DFIR, then every file and process executable is dumped, hashed and checked with YARA, offline threat feeds and (optionally) VirusTotal. See step 8. |

   A preset fills in two controls you can still change:
   - **Plugin category** (what the plugins look at): All categories, Malware, Network, Persistence, Registry.
   - **Fast mode** (how much runs): the quick plugin set, about a third of the plugins. It locks the category to All categories.

   Both map to the CLI `-m` switch (`full`, `fast`, `malware` ...). **RAM / jobs mode** (`--speed normal|fast|fastest`) is a separate setting: it controls RAM use and parallel jobs, not which plugins run. The **?** next to each of these opens a guide with annotated animations.

4. Optional:
   - **I already know this image:** set the OS, Volatility 2 profile, ISF symbol file, or a Volatility 2 Linux profile zip yourself, and skip detection.
   - **IOC list:** one indicator per line; CSV with a header is also accepted.
5. Press **Start**. The run monitor shows:
   - stage, overall progress and ETA;
   - a heartbeat;
   - every plugin's state and timeout;
   - the memory-map animation.

   The live log explains each step as it happens.

   **Retry a plugin (v2.3).** A plugin that failed, timed out, was skipped
   because a plugin it depends on failed, or never ran gets a retry button in
   the run monitor's **Retry** column. The button is also there for an old case
   opened with **Load results**, since the list is read from the case folder.
   Pressing it opens a confirm box with:
   - what went wrong;
   - the time limit for the retry. For a timeout it is pre-filled with double
     the limit the plugin was killed at, and **No time limit** is an option.
     The plugin runs once with that limit, with no automatic extended retry;
   - the plugins that were skipped because of it. They run right after it, with
     their own calibrated limits;
   - a warning that **the whole HTML report is recreated**, naming the analysis
     steps that read this plugin and are re-computed (for netscan: network map,
     correlation, timeline, Sigma).

   Every plugin-derived step is rebuilt. That takes about 30 s on a 2 GB dump.
   The strings/IOC scan, your IOC-list check, the EVTX dump and threat intel
   are not redone. If you press retry while an analysis is running, the retry
   is **queued** and starts by itself when the analysis finishes. CLI:
   `rambreaker-cli retry -o <case> -i <dump> --retry-plugins "windows.netscan.NetScan:1200,timers:0,windows.pstree.PsTree:auto"`
   (seconds, `0` = no limit, `auto` = calibrated).
6. Results open in the case navigator (summary, processes, network, findings,
   Sigma, injection, IOCs, e-mail, IOC check, timeline, every plugin table).
   **HTML report** opens the full offline `report.html`.

7. **Extract** (toolbar, Ctrl+E) opens the Extraction workspace for the loaded
   case. Every list comes from the finished analysis, so browsing is instant.
   Only the extraction itself runs Volatility, in the background.

   | Page | What you can do | Engine |
   |---|---|---|
   | Files | Search the dump's file list (name/path words, file type, "only recoverable"), tick files, extract | Windows `windows.dumpfiles` by file-object address (several per run); Linux page cache `linux.pagecache.InodePages --inode` (Vol2: `linux_find_file`); macOS `mac.pagecache` |
   | Processes | Tick processes (flagged ones highlighted) and extract the executable, the loaded DLLs and/or the full process memory | `pslist`/`dlllist --dump`, `memmap --dump`; Linux `linux.elfs`, `linux.proc.Maps`; Vol2 `procdump`/`dlldump`/`memdump`/`linux_procdump`/`linux_dump_map` |
   | Memory regions (VAD) | **Whole process**: every region of the ticked processes. **Selected regions only**: tick single regions (one button ticks the injection-flagged ones). A help card explains the difference with an example. | `windows.vadinfo --dump [--address]`, `linux.proc.Maps`/`mac.proc_maps --dump --address`, Vol2 `vaddump`/`linux_dump_map` |
   | String hunt | Your strings (one per line), optional PIDs, case/UTF-16 options; hits per process and address | Vol3 `VadYaraScan`/`VmaYaraScan`/`YaraScan`, Vol2 `yarascan`/`linux_yarascan` |
   | Export pack | Zip of the key results with a manifest | - |

   - **Save to:** choose the folder (default `<case>\extracted`). Each job gets its own sub-folder, for example `procs_20261112_153012`.
   - **Manifest:** every job writes `manifest.json` and `manifest.txt`, listing each item's status and, for each extracted file, its size, detected type (PE, ELF, EVTX, …), SHA-256, MD5 and **non-zero %**. A file whose pages were not in RAM is reported as **empty**, never as a fake success.
   - **Missing lists:** if a case has no file list or region list yet, "Build file list" and "List regions" create it once.
   - **Command line:** the same jobs run with `rambreaker-cli.cmd xjob --spec job.json`.

8. **DFIR + Threat Intel** (preset, new in v2.2) answers "is anything in this image
   known to be bad?". Its results go into **report.html, tab Threat Intelligence**,
   and into `<case>\threat_intelligence\`. The GUI only runs it.

   1. Full DFIR analysis.
   2. Dump **every recoverable file** and the **executable of every process**. Memory
      regions are not dumped, except the ones the injection correlator flagged HIGH or
      MEDIUM: fileless code never exists as a file.
      - Windows: `windows.dumpfiles`, 400 file objects per run.
      - Linux: `linux.pagecache.RecoverFs`, one pass.
      - macOS: `mac.pagecache --dump`.
   3. SHA-256, SHA-1 and MD5 of every object, and its **hash quality**:
      - *complete*: every page was present, so the hash should match the file on disk;
      - *partial*: pages were not in RAM;
      - *rebuilt*: an executable reassembled from memory, which never hashes like the disk file.
   4. **Local checks.** Nothing leaves the PC.
      - **YARA:** YARA Forge *core* (5,132 rules) or *extended* (10,886), plus your own
        rules from `yara_rules\custom\`.
      - **Offline feeds:** IPsum, Feodo, Maltrail, Spamhaus DROP, Emerging Threats, CINS,
        OpenPhish, and abuse.ch ThreatFox/URLhaus/MalwareBazaar with your own free key.
      - **What is compared:** every hash, the network connections, browser history, and
        the IPs, domains and URLs already extracted.
      - **Blocklist detection:** domains that sit inside a sorted list in memory (a
        hosts-file blocklist or antivirus data) are recognised as such.
   5. A scored **"look here first"** list. Each entry says why it is there.
   6. **VirusTotal**, only if you enter a key. Only the hashes, public IPs and domains on
      the short list are looked up.
      - Files are never uploaded.
      - Private IPs and internal names are never sent.
      - Every identifier that was sent is listed in `vt_sent.txt`.
      - Pace: 4 lookups per minute by default (free key). Answers are cached.
      - When the quota runs out: **Analysis > Continue VirusTotal lookups**.

   - **Existing cases:** **Analysis > Threat intel on this case** adds threat intel to a
     case that was analysed earlier.
   - **Command line:** `rambreaker-cli.cmd dfir-ti -i dump.raw`, or `ti -o <case>`. Options:
     `--no-vt`, `--vt-rate`, `--vt-max`, `--vt-only`, `--yara-set`, `--yara-dir`.

   **The databases go out of date.** New malware and attacker servers appear every day.
   The options window and **Settings > Threat-intel databases** show the age of each
   source and offer an **Update**. Updating is never automatic, and offline the
   bundled copies are used. Only freely redistributable sources are bundled: YARA
   Forge, IPsum and Feodo. Maltrail, Spamhaus, ET, CINS, OpenPhish and abuse.ch are
   downloaded to your PC when you choose Update, because their terms do not allow
   redistribution.

   The VirusTotal key is passed to the analysis process privately, never on the command
   line or in a log. It is stored, DPAPI-encrypted for your Windows user, only if you
   tick *Remember*.

Every control has a `?` help card. **Help mode** (F1) turns any click into an
explanation, and **Glossary** defines the forensic terms.

The command line is still available from the program folder:
`rambreaker-cli.cmd core -i dump.raw` (run with `--help` for every command,
including `ioc-check` and `sigma`).

## Folder layout (beside the exe)

| Path | Contents |
|---|---|
| `RAMBreaker.exe`, `_internal\` | The GUI: PyInstaller one-dir build, no UPX. |
| `app\` | Toolkit source (`crescent_toolkit.py` and modules), run by the portable Python. |
| `runtime\py3\` | Portable CPython 3.13 with all dependencies. `pythonw.exe` runs analyses without a console window. |
| `runtime\volatility3\` | Volatility 3 2.28.2. |
| `runtime\py27\` + `runtime\volatility2\` | Private Python 2.7.18 and Volatility 2.6.1. |
| `runtime\symbols\` | Volatility 3 symbol packs (`windows.zip`, `linux.zip`, `mac.zip`). |
| `runtime\bin\dwarf2json.exe` | Builds ISFs from kernel debug packages. |
| `output\` | One folder per case. |
| `logs\` | One GUI session log per run. |
| `cache\vol3` | Pre-built symbol index; relocates automatically when the folder moves. |
| `cache\vol2_profiles` | Volatility 2 Linux/Mac profile zips. |
| `sigma_rules\` | SigmaHQ rules (DRL 1.1) plus `custom\` for your own rules. |
| `yara_rules\` | `yara-forge\core.yar`, `extended.yar` (YARA Forge 20261108) and `custom\` for your own `.yar` files. |
| `threat_intel_db\` | `bundled\` (IPsum, Feodo) and `downloaded\` (feeds fetched by Update, with `_meta.json` ages). |
| `cache\vt`, `cache\yara` | VirusTotal answers (shared by all cases) and compiled YARA rules. |
| `config\` | `timeouts.json` (calibrated model), `timing_samples.jsonl`, `gui_settings.json`, `secrets.dat` (DPAPI-encrypted keys, only if you tick Remember). |

## What v2 adds or fixes (summary)

- **Windows port.**
  - Every Volatility call uses list arguments (paths with spaces work).
  - No `python3`, `strings`, `grep`, `dd`, `unzip`, `dpkg-deb`, `ar`, `rpm2cpio` or `cpio` is needed. Pure-Python replacements: `modules/pystrings.py` and `modules/pkg_extract.py`.
  - UTF-8 mode throughout, and `%APPDATA%`-safe cache handling.
  - No console windows appear during GUI runs.
- **Linux symbol ladder:**
  1. Community ISF repository (the GitHub-Releases URLs are now handled).
  2. Distro debug packages via dwarf2json.
  3. BTF-to-ISF reconstruction from inside the dump.
  4. Volatility 2 Linux profile, for pre-BTF kernels with no published debug symbols.
- **Dynamic timeouts** (`modules/timeout_model.py`): each plugin's timeout is computed per dump from the dump size, target OS and measured plugin cost. See below.
- **Sigma** (`modules/sigma_engine.py`): process, network, registry, image-load and EVTX events are rebuilt from memory and evaluated with a built-in Sigma engine. It supports modifiers, wildcards and full conditions, and reports evidence per hit.
- **IOC extraction:** 24 new types (JWT, cloud keys, provider tokens, bearer tokens, session cookies, NTLM / NetNTLMv2). False-positive filters were fitted on real dumps:
  - Bitcoin checksums
  - OID versus IPv4
  - IANA TLD check for e-mails
  - word-bounded PowerShell keywords
  - hash entropy
- **IOC checker** (`modules/ioc_checker.py`):
  - Searches the raw dump (ASCII and UTF-16, Aho-Corasick, multi-process), all plugin JSON and the hashes of dumped files.
  - Reports offsets, plugins and PIDs.
  - Process attribution comes from Volatility YARA scans.
- **E-mail artefacts:** RFC 822 headers and bodies, Outlook Web / Gmail / Yahoo JSON, `mailto:` links, SMTP/IMAP/POP traces and Outlook stores. Each item has a confidence level and duplicates are merged.
- **GUI** (PySide6): docks, a case navigator, sortable/filterable tables, the live log, the RAM animation, help on every control (checked automatically), a tour, a glossary, and dark and light themes.

## What v2.4 changes (2026-11-16)

v2.4 has no new screens. It makes the same analysis faster and fixes bugs found
by a live threat-intel test and a re-run of the samples. Measured on this PC
(i5-10400F, 16 GB RAM):

| What | v2.3 | v2.4 |
|---|---|---|
| Full DFIR preset, Windows2.raw (2 GB, Win7) | 34 min 47 s | 19 min 45 s |
| Strings/IOC/browser/e-mail scan, Windows2.raw | 96 s | 47 s |
| `linux.library_list`, dump.mem (1 GB, CentOS 7) | 807 s | 39 s |
| Threat-intel file dump, Windows2.raw | 200 s, 989 files | 135 s, 1,441 files |

- **Volatility 2 extras run side by side** (up to 3 at once) instead of one
  after another. `timers` and `apihooks` used to keep the Full DFIR preset
  waiting for half an hour.
- **Text scan in parallel.** The browser, chat-app and e-mail scanners each get
  their own process next to the IOC pattern scan. The output files are
  identical to the old single-process scan.
- **Strings in one pass.** ASCII and UTF-16 strings are read from the dump once.
- **Linux:** `linux.library_list` no longer rebuilds a symbol table for every
  memory region.
- **Threat intel recovers more files.** A file whose output path went over the
  Windows 260-character limit used to stop the dump, and every file after it in
  the batch was lost. Names are now shortened to fit, and a batch continues
  after any failing object.
- **Threat-intel databases removed by antivirus are reported.** Defender can
  quarantine downloaded lists (they hold malware addresses). The report now
  says "Missing after download" and names the database that was not checked;
  `DEFENDER.md` lists the folders to exclude if you want to keep them.
- **Memory-capture tools get a context note.** VirusTotal labels DumpIt,
  WinPmem and similar tools as malicious. The score stays; the report adds
  that such a tool is expected on a machine that was just imaged.
- **A failed strings step is shown as failed.** If the worker processes cannot
  start (PC short of memory), the scan runs in one process; if no strings come
  out at all, the run says so instead of "No IOCs found".

- **VMware .vmem without its .vmss/.vmsn.** VMware stores the RAM above the
  PCI hole (above 3 GB on a 4 GB VM) right after the lower RAM, and only the
  .vmss/.vmsn says so. Without that file the OS could not be detected and every
  plugin failed. RAMBreaker now finds the split from the guest's own page tables
  (one pass over the image, cached in `cache\vol3\vmem_maps`) and applies it to
  Volatility 3 and 2. The log shows e.g. `Memory map rebuilt: file 0-3.00 GB ->
  RAM 0-3.00 GB, file 3.00-4.00 GB -> RAM 4.00-5.00 GB`. If you do have the
  .vmsn/.vmss, put it beside the .vmem with the same name; it is then used.
- **No Vol2 probe for Windows builds Vol2 cannot know** (newer than its newest
  profile, e.g. Server 2022 / Windows 11): saves the 300 s imageinfo timeout.

**v2.4.1 (2026-11-18): plugin dependencies now work.** A plugin that reads
another plugin's structures (for example `cmdline`, `malfind` and `dlllist` read
the process list from `pslist`; `netstat` uses `netscan`'s tables; the registry
plugins need `hivelist`) waits until that plugin has finished. If it really
failed, they are skipped and marked "skipped (dependency)" with a Retry button,
instead of each failing the same way. Before, every plugin started at once and
nothing was ever skipped. A timeout, a process Windows could not start, or symbol
tables that were still being built do not skip anything: the dependents still
run. `psscan`, `psxview` and `modscan` never wait: they scan memory directly
and are what you need when the list walk fails.

**v2.5.0 (2026-11-18): extracted files are protected.** A file pulled out of a
memory dump can be live malware, for example ransomware. By default every
extracted file (Extraction workspace: files, process executables/DLLs/memory,
memory regions; the threat-intel dump) is written straight into its own
password-protected ZIP, `<name>.zip`, encrypted with AES-256, password
`infected` (the usual convention for exchanging malware; changeable). Volatility
3 writes the encrypted ZIP itself, so the plain file never touches the disk:
nothing can be started by a double-click and the virus scanner cannot quarantine
the evidence. The manifest and the results table still show the size, type and
SHA-256/SHA-1/MD5 of the file inside, and the threat-intel YARA scan decrypts
each object in memory only. Each extraction folder gets a
`PROTECTED_FILES_README.txt`.
To unpack a file, preferably inside an isolated analysis VM: open it with 7-Zip,
WinRAR or PeaZip, or use the `tar` built into Windows 10/11:
`tar -xf <name>.zip --passphrase infected`. Windows Explorer cannot open
AES-encrypted ZIPs, which is a safe default. Switch: "Protect extracted files"
in the Extraction workspace and in the Threat Intel dialog; CLI `--no-protect`
and `--zip-password`. Volatility 2 output (old images) is plain for the length
of its run and is zipped right after. A threat-intel dump from an earlier
version is zipped when it is reused. The older menu commands (`dump-files`,
`dump-procs`, `dump-vad`, `dump-all`) still write plain files.

**v2.5.1 (2026-11-22): the mouse wheel no longer changes settings by accident.**
Rolling the wheel over a drop-down or number box (in the Case setup panel:
Preset, Plugin category, Engine, Parallel jobs, RAM / jobs mode; and in
Settings, Threat Intel, Retry and the Extraction workspace) used to change its
value while you were only trying to scroll the panel. Now the wheel always
scrolls the panel and never changes a value. Change a value by clicking it,
typing, the arrow buttons or the keyboard; an open drop-down list still scrolls
with the wheel.

Tuning switches (environment variables, normally not needed):
`RAMBREAKER_VOL2_LANES`, `RAMBREAKER_TI_LANES` (number of parallel Volatility
runs) and `RAMBREAKER_SERIAL_SCAN=1` (old single-process text scan).

## Dynamic timeout model

Every plugin run is appended to `config\timing_samples.jsonl` (plugin, engine,
target OS, dump size, duration, ok/timeout). The model fits
`expected = base_s + per_gb_s * dump_GB` per plugin, engine and target OS, using
non-negative least squares. Timeouts are treated as right-censored samples. A
plugin that has never been measured falls back to the median of its cost class
for **that OS only**.

```
timeout = clamp(3 x expected + 60 s, 120 s, 4 h)
```

When a plugin times out it is killed and retried once with
`min(2.5 x timeout, timeout + 30 min)`. If it times out again it is marked
**TIMED OUT** in the report. The ETA shown before and during a run comes from
the same model. The calibration table and formula are in `config\timeouts.json`.

A plugin whose data can also be produced per process on demand
(`windows.vadinfo`) is skipped up front when the model predicts more than
30 minutes for the dump (about 12 GB and larger on an HDD). The log says so,
and the Extraction workspace lists any process's regions in seconds instead.
Extraction jobs use the same model: each Volatility run gets a model timeout,
is killed and retried once, and its runtime is recorded.

The model re-fits itself at the start of every analysis when new runtimes have
been recorded, so each run calibrates the next. A timed-out run is a lower bound:
inside the measured size range it raises the plugin's base cost, beyond it the
per-GB slope. There are no hard per-plugin caps on this path. `build.ps1` merges
the runtimes a shipped copy has learned (and the per-case logs) back into
`config\` before re-fitting, so a rebuild never discards calibration data
(`build_tools\backfill_timings.py`).

## Building from source

Requirements: Windows 10/11 x64, Git and Python 3.13. The `runtime\` folder is
created by step 1 below and is not stored in git.

```powershell
# 1. runtimes (once): see VERSIONS.md for exact versions/commits
git clone --branch v2.28.2 https://github.com/volatilityfoundation/volatility3 runtime\volatility3
py -3.13 -m venv runtime\py3
runtime\py3\Scripts\python -m pip install -e runtime\volatility3[full] pyside6-essentials pyinstaller playwright pyyaml pyahocorasick zstandard python-evtx
msiexec /a python-2.7.18.amd64.msi /qn TARGETDIR=%CD%\runtime\py27      # + distorm3/pycryptodome/yara wheels (VERSIONS.md)
git clone https://github.com/volatilityfoundation/volatility runtime\volatility2
# symbols: runtime\symbols\{windows,linux,mac}.zip ; dwarf2json: runtime\bin\dwarf2json.exe
# 2. build
powershell -ExecutionPolicy Bypass -File build_tools\build.ps1          # -> dist\RAMBreaker
# 3. tests
runtime\py3\Scripts\python src\tests\run_tests.py ; runtime\py3\Scripts\python src\tests\run_canary.py
dist\RAMBreaker\RAMBreaker.exe --selftest screenshots\gui <case output dir>
powershell -File build_tools\run_sample.ps1 -Dump <dump> [-IocList list.txt]   # real exe workflow + report checks
```

## Why PySide6 (Qt)

It produces native, mature Windows widgets: tables with sorting and filtering,
docks, and high-DPI support. It works well with PyInstaller, and
QPainter-drawn animation needs no GPU. The `QProcess` + JSON-event design keeps
the UI thread free during multi-hour analyses. A web-view GUI was rejected: a
second runtime and a larger attack surface for no benefit.

## Antivirus

See `DEFENDER.md` for exact exclusion steps if Defender flags the tool or
quarantines carved malware in `output\` or downloaded threat-intel lists in `threat_intel_db\`.

## Versions

See `VERSIONS.md`: Volatility 3 2.28.2, Volatility 2 2.6.1 (final commit),
Python 3.13.17 and 2.7.18, dwarf2json master `9f14607`, SigmaHQ `53b90df`, and
Lucide 1.70.0.

## Known limitations

- Extraction recovers only what was in RAM. Small files that were not cached
  (hosts, NTUSER.DAT, ...) come back empty, and that is reported. macOS
  libraries in the dyld shared cache cannot be extracted as files; dump the
  process memory instead.
- macOS: Volatility 3 `mac.malfind` flags almost every region (shown as LOW with
  a note), and IOC-checker hits cannot be tied to a process. The string hunt
  with PIDs can attribute them.
- Volatility 2 has no Windows 11 / Server 2022 profiles, so the Volatility 2
  extras are skipped on those images.
- IOC lists from memory are leads, not verdicts. Broad types (hex blobs, base64,
  domains) keep some noise, and a string cut at a memory boundary can give a
  partial value.
- Large dumps are slow on a spinning disk; copy the dump to an SSD (the log
  suggests it). A 35 GB Windows 11 image is a multi-hour job: `malfind` alone
  took about 1 h 50 min.
- Resuming a case re-runs the strings and IOC pass.
- SigmaHQ rules ship unmodified. One known false positive: the macOS
  history-file rule matches Safari `History.xpc`.
- The older menu commands (`dump-files`, `dump-procs`, `dump-vad`, `dump-all`)
  still write plain, unprotected files.
