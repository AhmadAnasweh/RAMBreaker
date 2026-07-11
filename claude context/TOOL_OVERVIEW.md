# RAMBreaker (CresCentC v6.0) — What It Is, Why It Exists, and How to Use It

> A forensic **memory-analysis framework** that turns a raw RAM image into one
> self-contained, interactive HTML report — auto-detecting the OS, driving
> Volatility 2/3 for you, and correlating processes, network, files, registry,
> commands, browser/chat artifacts, IOCs and a timeline into a single evidence
> picture. **Windows, Linux, and macOS.**

---

## 1. What the tool is (in one paragraph)

You give it a memory image (`.raw`, `.mem`, `.lime`, `.dmp`, VMware `.vmem`, a
crash dump, etc.). It figures out which operating system the image came from,
picks the correct Volatility engine (v3 for modern systems, v2 for legacy
Windows), downloads the matching kernel symbols when needed (Linux/macOS ISF),
runs a curated battery of ~10–45 Volatility plugins **in parallel**, extracts
strings and pulls IOCs / browser history / chat-app traces out of them in one
pass, rebuilds the process tree and the external-network map, cross-references
everything, builds a chronological timeline, and writes a single
`report.html` you can open offline. It can also dump files and processes out of
memory, hunt live memory for specific strings with YARA, and export to
ELK/Kibana or a ZIP evidence pack.

It is a **workflow layer on top of Volatility**, not a replacement for it. Every
number in the report traces back to a raw Volatility plugin whose JSON is saved
alongside.

---

## 2. Why the tool exists (the problem it solves)

Volatility is powerful but **raw and manual**. A normal investigation looks like:

1. Guess the OS / profile. Fight with symbol tables.
2. Remember the exact plugin names and run them one at a time.
3. Copy/paste PIDs between `pslist`, `netscan`, `cmdline`, `malfind`…
4. Grep gigabytes of strings by hand for URLs, IPs, tokens.
5. Manually reconcile "process X had connection Y and command line Z."
6. Write up findings from a dozen text dumps.

This is slow, error-prone, and easy to do inconsistently. **RAMBreaker automates
the whole loop** and — crucially — **correlates** the outputs so you see, for one
process, its parent, its command line, its network connections, its loaded
modules, and any suspicious markers **in one place**. It also handles the parts
of Volatility that are genuinely fiddly:

- OS/engine auto-detection (including large-image and cold-cache edge cases).
- Linux/macOS **ISF symbol acquisition** (download the right one, or build/patch
  it to byte-match the image's kernel banner).
- Vol3's "exits 0 even on failure" trap, symbol-table cold-start races, and
  per-plugin timeouts that need to scale with image size — all handled so a run
  doesn't silently lose a whole tab.

The goal: **from image to a defensible evidence report in one command**, with the
raw Volatility output preserved for verification.

---

## 3. What it has that plain Volatility (and most wrappers) don't

| Capability | Why it matters |
|---|---|
| **One command, whole pipeline** | `full -i image -o out` runs extraction → strings/IOC → process tree → correlation → registry → timeline → HTML. No plugin-by-plugin driving. |
| **True OS auto-detection + engine choice** | Banners → windows.info → Vol2 imageinfo → raw-string fallback. Picks Vol3 vs Vol2 and the Vol2 profile automatically. |
| **Parallel plugin execution with a RAM guard** | ThreadPoolExecutor across plugins, with an adaptive job count based on free RAM (`normal`/`fast`/`fastest`). |
| **Automatic Linux/macOS symbols** | Downloads ISF from the community repo (with CDN mirror fallback); if the exact kernel banner is missing, **patches** the closest ISF to byte-match, or builds one from a `.ddeb`/DWARF. |
| **Cross-artifact correlation** | The correlator stitches process ↔ network ↔ command line ↔ modules ↔ hashes so you read one story per process, not six disconnected tables. |
| **Single self-contained HTML report** | 11 tabs, opens offline, **global cross-tab search** (`/` or Ctrl/⌘-K highlights matches across every tab). Nothing to install to read it. |
| **Strings mined for real artifacts** | IOCs (context-anchored, low false-positive), browser history, and **chat-app detection** (Teams, Discord, Zoom, Slack, Telegram, WhatsApp, Skype, Webex, Signal, Meet, VooV, **Flock**) with process/network correlation. |
| **Live-memory String Hunt (YARA)** | `hunt` searches the raw image for your strings via Volatility's YARA plugins — PID, process, address, context — without pre-dumping. |
| **File + process carving** | Dump files (Windows filescan / Linux pagecache / macOS page-cache) and processes (PE/ELF/Mach-O) straight out of memory, with hashing and YARA scanning of what's dumped. |
| **macOS content recovery** | Bundles patched Vol3 plugins (`mac.pagecache`, iterative `mac.list_files`) that stock Volatility lacks or crashes on. |
| **SIEM/handoff exports** | ELK/Kibana NDJSON export and a ZIP evidence pack. |
| **Evidence, not verdicts** | See §7 — deliberately makes **no** automated accusations. |

---

## 4. The design principle you should know up front

**The tool presents raw evidence and correlations. It makes NO automated threat
verdicts.**

Anything labelled "suspicious" is an **observation**, not an accusation — e.g.
"this process has an unexpected parent", "there are multiple instances of this
name", "this process is visible to psscan but not pslist (possible hiding)". The
reasoning is left to you, the analyst. This keeps the report defensible and
avoids the false-confidence problem of tools that shout "MALWARE" at a normal
system service. Sensitive data (NTLM hashes) is redacted by default in the
report; the unredacted source stays in the JSON for when you need it.

---

## 5. How to use it

### 5.1 Install / prep (once)

```bash
cd /home/kali/Desktop/RAMBreaker_toolkit
python3 crescent_toolkit.py        # opens the interactive menu
# In the menu: [I] Installer  → installs Vol2 + Vol3 + symbols + deps
```

Requirements: Python 3, Volatility 3 (and/or Volatility 2), `strings` (binutils);
optionally `yara` and `python-evtx`. The installer handles Volatility and
symbols for you.

### 5.2 The two ways to run it

**A) Interactive menu** — best for exploring:

```bash
python3 crescent_toolkit.py
```

Top-level modes: `[C]` CORE (full analysis, no EVTX), `[D]` DEFAULT (CORE +
EVTX), `[T]` only Vol plugins, `[F]` dump-everything (experimental). Below that,
every module has its own number (`[1]` Extractor … `[H]` String Hunt), plus
`[R]` HTML report, `[E]` ZIP pack, `[K]` ELK export, `[I]` installer,
`[S]` settings.

**B) CLI** — best for scripting / repeatability:

```bash
# Full pipeline (Windows Vol3 image)
python3 crescent_toolkit.py full -i /path/Windows.raw -o /out/ -m fast -j 2

# Windows 7 (Vol2 — needs a profile)
python3 crescent_toolkit.py full -i Windows2.raw -o /out/ -m fast --profile Win7SP1x64

# Linux VMware image (slow — plan for 30–90 min)
python3 crescent_toolkit.py full -i linux.vmem -o /out/ -m fast --speed fast -j 2

# Individual stages
python3 crescent_toolkit.py extract    -i image.raw -o /out/ -m fast
python3 crescent_toolkit.py report     -o /out/
python3 crescent_toolkit.py dump-files -i image.raw -o /out/
python3 crescent_toolkit.py dump-procs -i image.raw -o /out/

# Live-memory string hunt (YARA)
python3 crescent_toolkit.py hunt -i image.raw -o /out/ --hunt-strings "mimikatz" --hunt-pid 892
```

### 5.3 Flags that matter

| Flag | Meaning |
|---|---|
| `-i, --image` | the memory image (**note: `-i`, not `-f`**) |
| `-o, --output` | output directory |
| `-m, --mode` | plugin profile: `fast full malware network persistence registry` (default `full`) |
| `--speed` | `normal` (RAM-safe) · `fast` (tighter RAM, more jobs) · `fastest` (max jobs, no RAM guard — use with 16 GB+) |
| `-j, --jobs` | parallel plugin jobs (default 4) |
| `--vol2` / `--vol3` | force a Volatility engine |
| `--profile` | force a Vol2 profile (e.g. `Win7SP1x64`) |
| `--timeout` | base per-plugin timeout (default 600 s) |
| `--pattern` | file-dump filter (e.g. `evtx`, `exe`) |
| `--strings-mode` | `all ascii unicode both` |
| `--hunt-strings / --hunt-pid / --hunt-case-sensitive / --hunt-no-wide` | String Hunt options |

**Commands:** `menu extract dump-files dump-procs strings correlate iocs report
timeline evtx export elk core full hunt`.

### 5.4 Choosing a mode

- **`fast`** — the essentials (processes, network, malfind, services, registry
  basics, filescan). Best first pass.
- **`full`** — everything above plus dlllist/handles/ldrmodules/vadinfo/mftscan/
  driver & module scans, etc. (~33 Windows Vol3 plugins). The default.
- **`malware`** — malfind, ssdt, callbacks, driver IRP, ldrmodules, modules…
- **`network`** — connection-focused subset.
- **`persistence`** — registry Run keys, services, scheduled tasks, drivers.
- **`registry`** — registry hives only.

---

## 6. Where to find things (output layout + report map)

### 6.1 On disk (your `-o` output directory)

```
<output>/
├── report.html            ← START HERE. Self-contained, 11 tabs, offline.
├── json/                  ← every plugin's raw JSON (the source of truth)
│   ├── windows_pslist_PsList.json
│   ├── windows_netscan_NetScan.json
│   └── …
├── txt/                   ← human-readable text versions of each plugin
├── iocs/                  ← popular_files.json, scheduled_tasks.json, IOC data
├── dumped_files/          ← (after `dump-files`) carved files
├── dumped_processes/      ← (after `dump-procs`) carved PE/ELF/Mach-O + memmaps
├── SUMMARY.txt            ← quick run summary (OS, engine, counts)
├── correlation_report.txt ← the stitched process↔network↔cmd story
├── network_map.txt        ← external IPs + reverse DNS
├── process_tree.txt       ← ASCII process tree
└── crescent_toolkit.log   ← full run log (read this if something looks off)
```

**Rule of thumb:** the **HTML report** is for reading the story; the **`json/`
files** are for proving it. If a report value looks wrong, open the matching
`json/<plugin>.json` — it's the unmodified Volatility output.

### 6.2 Inside `report.html` — the 11 tabs

1. **Processes** — process tree, PIDs/PPIDs, command lines, suspicious markers.
2. **Network** — connections, external IPs, ports, owning process.
3. **Shell Commands** — cmdline + (Vol2) cmdscan/consoles history, LOLBin/encoded-PS flags.
4. **Malware** — malfind hits, injected regions, driver/callback anomalies.
5. **Files** — filescan / file listing.
6. **Services** — Windows services (svcscan) etc.
7. **Popular Files** — files in Desktop/Downloads/tmp and other high-signal buckets.
8. **Scheduled Tasks** — schtasks/.job (Win), cron/at/systemd (Linux), launchd (macOS).
9. **Registry** — hives, Run keys, UserAssist, targeted persistence keys.
10. **IOCs** — URLs, IPs, emails, hashes, crypto addresses mined from strings.
11. **Summary** — the at-a-glance overview.

**Finding something fast:** press `/` or **Ctrl/⌘-K** in the report to focus the
**global search box** — it highlights matches across *every* tab at once, shows a
per-tab hit count, and ▲/▼ (or Enter / Shift+Enter) cycle through all hits,
switching tabs as needed.

### 6.3 The toolkit's own working directories

- **`CresCentC_work/`** (now inside the tool folder) — scratch/temp, ISF build
  staging, downloaded debug packages, `cache`. The tool points `TMPDIR` here so
  large temp files don't fill the small `/tmp` tmpfs. Safe to delete when idle;
  it is recreated on demand. Override with `CRESCENT_WORK=/path`.
- **`CresCentC_RESULTS/`** (inside the tool folder) — default results base.
  Override with `CRESCENT_RESULTS=/path`.

---

## 7. What to expect on a run (realistic timings & quirks)

- **First Vol3 run on a cold cache pays a one-time symbol-cache build** (progress
  bar: "Updating caches for N files…"). It looks frozen but isn't — later runs
  reuse it.
- **Windows** images are usually the fastest (minutes). A 512 MB image ≈ 1 min; a
  2 GB image ≈ 3–4 min; an 8 GB image ≈ 10–15 min for extraction, longer for the
  full strings/IOC/report tail.
- **Linux `.vmem`** is the slow case — some plugins (`psaux`, `bash`, `proc.Maps`)
  take 5–8 min each, and the IOC scan over tens of millions of string lines can
  add 20–30 min. Budget **45–90 min** and use `-j 2`.
- **Some plugin "failures" are expected**, not bugs — e.g. `connections`/`connscan`
  on Win7+ (XP-era plugins; use netscan), `mac.bash` on certain images,
  `sockstat` timing out on VMware Linux. The report notes them.
- **Big images** need free disk (strings + dumps + JSON). Watch `df -h /`. On a
  VMware guest, dragging an image into the VM can leave a full duplicate under
  `~/.cache/vmware/drag_and_drop/` — safe to delete.

---

## 8. Version & lineage

This is **CresCentC v6.0** — an OS-split refactor of v5.0 where every
multi-OS module became `<name>.windows.py` / `.linux.py` / `.mac.py` behind a
thin dispatcher (see `claude context/ARCHITECTURE_V6.md` for the authoritative
architecture, bug history, and gotchas). For a module-by-module and
plugin-by-plugin walkthrough, see **`MODULES_AND_PLUGINS.md`**.
```
