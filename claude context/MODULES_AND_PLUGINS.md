# RAMBreaker (CresCentC v6.0) — How the Modules & Plugins Work

A detailed companion to `TOOL_OVERVIEW.md`. This explains the internal
architecture, the data flow through the pipeline, what every module does, which
Volatility plugins run and what each one surfaces, and **what you should expect**
at each stage. For the authoritative low-level architecture, dispatcher pattern,
and bug history, see `claude context/ARCHITECTURE_V6.md`.

---

## Part 1 — Architecture: the OS-split dispatcher

v6 splits every module that used to branch on OS internally into **three
OS-specific files** behind a **thin dispatcher** of the same name:

```
extractor.py            ← dispatcher: loads the right one below
extractor.windows.py    ← Windows plugin list + Windows-only logic
extractor.linux.py      ← Linux plugin list + Linux-only logic
extractor.mac.py        ← macOS plugin list + macOS-only logic
```

Because the OS-specific filenames contain dots (`extractor.windows.py`), they
can't be imported normally. The dispatcher loads them dynamically with
`importlib.util` and exposes a factory with the original v5.0 name, so **calling
code never changed**:

```python
def Extractor(vol, logger, jobs=4, speed='normal'):
    mod = _load_os_module(vol.os_type)      # extractor.windows / .linux / .mac
    return mod.Extractor(vol, logger, jobs, speed)
```

The OS is decided **once** in `volatility.py` (`VolatilityWrapper.auto_detect`)
and stored in `vol.os_type` ∈ {`windows`, `linux`, `mac`, `unknown`}. Every
dispatcher reads that value. Modules that are genuinely OS-agnostic
(`correlator` core, `network_map`, `ioc_extractor`, `browser_history`,
`comms_scanner`, `timeline`, …) are **not** split.

**Why it's built this way:** clearer per-OS ownership, no giant `if windows / elif
linux` ladders, and you can fix a macOS field-mapping bug without risking the
Windows path. The trade-off: a change to shared report/search code must be
applied to **all three** `html_report.{windows,linux,mac}.py` copies.

---

## Part 2 — The pipeline (data flow of a `full` run)

A `full` (or menu CORE/DEFAULT) run executes 8 steps. Each step reads the
artifacts the previous ones wrote to `<output>/json/` and `<output>/txt/`.

```
image ──► [auto_detect] ──► os_type + engine + (profile) + symbols
   │
   ├─ Step 1/8  Extractor        → json/*.json  (parallel Volatility plugins)
   ├─ Step 2/8  Strings + IOC/Browser/Comms  → strings, iocs/, browser, comms
   ├─ Step 3/8  Process Tree     → process_tree.txt
   ├─ Step 4/8  Process analysis → suspicious markers, cmd analysis, MITRE
   ├─ Step 5/8  Correlator       → correlation_report.txt (stitch everything)
   ├─ Step 6/8  Registry analysis→ registry findings (Windows)
   ├─ Step 7/8  Timeline         → unified chronological events
   └─ Step 8/8  HTML Report      → report.html (11 tabs)
```

Key properties to expect:

- **Step 1 is the long one** and the source of everything else. If a plugin fails
  here, the tab that depends on it is thin or empty downstream.
- **Steps 2–8 are cheap** relative to Step 1 on Windows, but Step 2 (strings +
  IOC scan) dominates on large Linux images.
- Steps are **resumable**: re-running skips plugins whose JSON already exists and
  passes a 6-marker validity check (not just "file exists"), so a crashed run
  continues instead of restarting.

---

## Part 3 — Module catalog

### 3.1 Engine & orchestration

| Module | Role | Notes |
|---|---|---|
| `volatility.py` | **The engine wrapper.** Finds Vol2/Vol3, `auto_detect()` OS+engine+profile, `run_plugin()` each plugin, success-checking. | Handles the "Vol3 exits 0 on failure" trap: success = rc 0 **AND** real output **AND** no unsatisfied-requirement / symbol-table error. Progress-aware probes for large images. |
| `extractor.{windows,linux,mac}.py` | Owns the **plugin lists per mode**, runs them in parallel (ThreadPoolExecutor), enforces dependencies, warms caches. | Windows also serially warms the **kernel symbol table** before the batch (fixes the cold-start race), plus Vol2-exclusive plugins in a background thread. |
| `installer.py` | Installs Vol2/Vol3, symbol packs, deps; applies non-bundleable **framework fixes** (`apply_framework_fixes`, e.g. the macOS `netstat` patch). | Idempotent; guarded on exact buggy text. |
| `workspace.py` | Central scratch/results config; points `TMPDIR` at a big on-disk workspace (not the small `/tmp` tmpfs). | `CRESCENT_WORK` / `CRESCENT_RESULTS` env overrides. Now defaults **inside the tool dir**. |
| `logger.py` | Logging service. | Writes `crescent_toolkit.log`. |

### 3.2 Symbol acquisition (Linux/macOS)

| Module | Role |
|---|---|
| `linux_identify.py` | Cold-cache-safe helpers: kernel-banner detection, `run_vol_until_done` (progress-aware, no fixed timeout), `warm_isf_cache`, `warm_windows_kernel_symbols`, psscan-based process confirmation. |
| `linux_resolver.{linux,mac}.py` | Downloads the matching ISF from the community repo (CDN mirror fallback); **patches** the closest ISF to byte-match the image's kernel banner when the exact one is missing. |
| `dbgsym_builder.py` | Builds an ISF from a `.ddeb`/DWARF (`dwarf2json`, bundled in `_isf_build/`) when nothing downloadable matches. |

### 3.3 Extraction & carving

| Module | Produces |
|---|---|
| `strings_extractor.py` | ASCII/Unicode strings from the image (one pass feeds IOC/browser/comms). |
| `ioc_extractor.py` | URLs, IPs, emails, hashes, crypto addresses — **context-anchored** regexes to cut false positives (e.g. AWS keys require `aws_secret_access_key=`). |
| `browser_history.py` | URLs / searches / downloads reconstructed from strings (URL-decoded). |
| `comms_scanner.py` | Chat-app traces (Teams/Discord/Zoom/Slack/Telegram/WhatsApp/Skype/Webex/Signal/Meet/VooV/**Flock**), correlated with running processes + network. |
| `file_dumper.{windows,linux,mac}.py` | Carves files from memory (Windows filescan, Linux/macOS page-cache). |
| `process_dumper.{windows,linux,mac}.py` | Dumps processes (PE/ELF/Mach-O) + memmaps; flags suspicious ones. |
| `memory_grep.py` | Grep patterns across already-dumped files. |
| `auto_hash.py` | MD5/SHA of dumped files; optional throttled VirusTotal lookups. |
| `yara_scanner.py` | YARA scan of dumped files. |
| `string_hunt.py` | **Live-memory** YARA search of the raw image (`hunt` command) — PID/process/address/context, no pre-dump. |

### 3.4 Analysis & correlation

| Module | Role |
|---|---|
| `process_tree.py` | ASCII process tree; tags true OS roots vs `[ORPHAN — missing PPID N]`. |
| `network_map.py` | External-IP map + reverse DNS; `ipaddress`-based private/CGNAT classification. |
| `correlator.{windows,linux,mac}.py` (+ core) | **The stitcher** — joins process ↔ network ↔ cmdline ↔ modules ↔ hashes into one story per process. NTLM hashes redacted by default. |
| `cmd_analyzer.{windows,linux,mac}.py` | Flags LOLBins, encoded PowerShell, download cradles, privesc — OS-specific pattern sets (42 Win / 38 Linux / 44 macOS). |
| `scheduled_tasks.{windows,linux,mac}.py` | schtasks/.job (Win), cron/at/systemd (Linux), launchd (macOS). |
| `popular_files.{windows,linux,mac}.py` | Files in high-signal buckets (Desktop/Downloads/tmp, `/usr/bin`, etc.); bucket order avoids substring collisions. |
| `registry_explorer.windows.py` | Registry hives, printkey, persistence keys (Windows-only). |
| `registry_altered.py` | Recently-modified registry keys (Windows anomaly view). |
| `evtx_parser.windows.py` | Parses Windows `.evtx` event logs (strings fallback marks low-fidelity events). |
| `system_info.py` | System info from the OS-info plugin. |
| `timeline.py` | Unified chronological timeline; filters placeholder epochs (FILETIME-0, Unix-0, FAT 1980, .NET-min). |

### 3.5 Reporting & export

| Module | Role |
|---|---|
| `html_report.{windows,linux,mac}.py` | Builds the self-contained 11-tab `report.html` with the global cross-tab search. Three near-identical copies (edit search code in all three). |
| `export_pack.py` | ZIP evidence pack. |
| `elk_export.py` | Elasticsearch/ELK NDJSON export. |
| `utils/json_converter.py` | Vol2 text → JSON; `load_json_by_pattern()` used everywhere to read plugin output. |
| `utils/ui.py` | Console UI / menu. |

---

## Part 4 — Plugin catalog (what actually runs)

Plugins are keyed `f"{engine}-{os}-{mode}"`. Below is what each set surfaces.
The report tab each feeds is in **bold**.

### 4.1 Vol3 Windows

**`vol3-windows-fast`** (first-pass essentials):
`info` (System Info) · `pslist` `pstree` (**Processes**) · `cmdline`
(**Shell Commands**) · `netscan` (**Network**) · `malfind` (**Malware**) ·
`svcscan` (**Services**) · `hashdump` · `registry.hivelist` `registry.printkey`
(**Registry**) · `filescan` (**Files**).

**`vol3-windows-full`** (≈33 plugins) adds: `psscan` (pool-scan processes —
catches hidden ones) · `dlllist` `handles` `ldrmodules` `vadinfo` (loaded
modules / handles / injected regions) · `getsids` `envars` `privileges`
`sessions` · `netstat` (established/listening) · `ssdt` `callbacks` `driverscan`
`driverirp` `modules` `modscan` (**Malware** / driver anomalies) ·
`registry.hivescan` `registry.userassist` · `mftscan` (MFT records) ·
`mutantscan` `symlinkscan` `thrdscan`.

**`vol3-windows-malware`** — the injection/rootkit subset: `malfind` `ssdt`
`callbacks` `driverirp` `driverscan` `modules` `ldrmodules` `handles` `hashdump`.

**`vol3-windows-network` / `-persistence` / `-registry`** — focused subsets for
those tabs (netscan/netstat; Run keys + services + drivers + tasks; hives only).

> **Dependencies:** `pslist` feeds pstree/psscan/cmdline/dlllist/handles/… ;
> `netscan`↔`netstat`; `hivelist` feeds userassist/printkey; `modules`→`modscan`.
> If a parent fails, dependents are skipped — which is why keeping `pslist`/`info`
> healthy (the cold-start symbol warm-up) matters so much.

### 4.2 Vol2 Windows (legacy: Win7/XP/2012 via profile)

`vol2-windows-fast/full` cover the classic set: `imageinfo pslist pstree psscan
psxview cmdline cmdscan consoles dlllist handles netscan connections connscan
malfind svcscan hashdump hivelist printkey filescan …`. **Vol2-exclusive**
plugins (no Vol3 equivalent) run in a background thread: `cmdscan consoles
hashdump shellbags shimcache iehistory clipboard deskscan atoms atomscan timers
messagehooks eventhooks apihooks`.

### 4.3 Vol3 Linux

`vol3-linux-fast`: `pslist pstree psaux` (processes + args) · `bash` (shell
history) · `lsmod check_modules` (modules / hidden-module check) · `sockstat`
(sockets) · `lsof` (open files) · `proc.Maps` (memory maps) · `pagecache.Files`
(cached files → file carving).

### 4.4 Vol3 macOS

`vol3-mac-fast`: `pslist pstree psaux` · `bash` · `netstat` · `lsmod` `malfind` ·
`list_files` (**patched, iterative** — bundled) · `proc_maps`. File-content
recovery uses the bundled **`mac.pagecache`** plugin.

---

## Part 5 — What to expect at each stage

### 5.1 Detection
On a large or cold image you'll see the banners/`windows.info` probes take a
while — they're **progress-aware** and wait on real Vol3 progress rather than a
fixed timeout, so a run that *looks* paused at "banners detection" is usually the
one-time symbol-cache build, not a hang.

### 5.2 Extraction (Step 1)
- **Windows:** kernel symbols are warmed **serially first** (one `windows.info`
  line), then the batch runs; expect essentially all plugins to succeed. A plugin
  failing on `kernel.symbol_table_name` while later ones pass is the cold-start
  race — now prevented, with a self-healing serial retry as backup.
- **Expected non-bug failures:** `connections`/`connscan` on Win7+ (XP-era),
  `mac.bash` on some images, Linux `sockstat` timing out on VMware `.vmem`.
- **Heavy plugins** get extended timeouts (dlllist, handles, netscan, malfind,
  mftscan, vadinfo). `malfind` on a large image can take several minutes.

### 5.3 Strings + IOC (Step 2)
Cheap on Windows; on a multi-GB **Linux** image the strings pass yields tens of
millions of lines and the IOC scan over them can add 20–30 minutes. Use `-j 2`
and be patient. IOC output is deliberately conservative (anchored regexes) to
avoid drowning you in false hits.

### 5.4 Correlation → Report (Steps 3–8)
Fast. The correlator produces `correlation_report.txt`; the report bundles
everything into `report.html`. Open it, press `/` to search across all tabs.

### 5.5 Rough timings (whole `full` pipeline)
| Image | Size | Expect |
|---|---|---|
| Windows Server 2012 | 512 MB | ~1–2 min |
| Windows 10 / 7 | ~2 GB | ~3–5 min |
| Windows 10 | ~8 GB | ~15–25 min |
| macOS | ~1 GB | ~1–2 min |
| Linux `.vmem` | ~4 GB | **45–90 min** (strings/IOC dominate) |

### 5.6 Symbols, companions & disk
- Linux/macOS need the right **ISF**; the resolver downloads/patches/builds it.
- A bare VMware `.vmem` needs its `.vmss`/`.vmsn` **companion** in the same dir,
  or list-walking plugins return 0 processes (psscan still works).
- Keep an eye on **free disk** for big images (strings + dumps + JSON). The
  toolkit routes scratch to `CresCentC_work/` to avoid the tiny `/tmp` tmpfs.

---

## Part 6 — Reading the output like an analyst

1. Open **`report.html`** → **Summary** tab for the shape of the system.
2. **Processes** → look for orphans, unexpected parents, multi-instance, or
   psscan-only (hidden) markers. Remember: these are **observations, not
   verdicts**.
3. Pivot on a PID: check **Network**, **Shell Commands**, **Malware**, and the
   **correlation report** for that same PID — the story should line up.
4. **IOCs / Browser / Comms** for external contact and app usage.
5. **Popular Files / Scheduled Tasks / Registry** for staging and persistence.
6. To **prove** any value, open the matching `json/<plugin>.json` — it's the raw,
   unmodified Volatility output.
7. Need something specific from raw memory? Use **String Hunt** (`hunt`) to YARA-
   search the live image by PID.

---

*See also: `TOOL_OVERVIEW.md` (what/why/how), `claude context/ARCHITECTURE_V6.md`
(authoritative architecture + bug history + gotchas), and the
`claude context/SESSION_*` docs for per-feature deep dives.*
