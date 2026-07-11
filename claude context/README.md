# CresCentC v6.0 — RAM Forensics Toolkit

A modular memory-forensics framework over **Volatility 2 / 3**. Feed it a memory image
(`.raw`, `.mem`, `.lime`, `.dmp`, VMware `.vmem`); it auto-detects the OS, picks the right
Volatility engine, downloads ISF symbols if needed (Linux/macOS), runs a battery of
plugins in parallel, extracts strings/IOCs/browser/chat artifacts in a single pass,
reconstructs the process tree and network map, correlates everything, builds a timeline,
and emits one self-contained interactive `report.html` (plus optional ELK/SIEM export and
a ZIP pack). Targets **Windows, Linux, and macOS** images.

**Design principle (enforced everywhere):** present raw evidence + correlations, make
**no** automated threat verdicts. "Suspicious process" lists are *observations*
(unexpected parent, multiple instances, hidden-from-pslist), not accusations.

## What's new in v6

v6 is an architectural refactor of v5.0: every module that handled multiple operating
systems is split into OS-specific files (`extractor.windows.py`, `extractor.linux.py`,
`extractor.mac.py`, …) dispatched through thin `importlib.util` loaders. Calling code is
unchanged. v6 also adds the **String Hunt** module (live-memory YARA search, `hunt`
command / `[H]` menu). See `ARCHITECTURE_V6.md`.

**Recent additions (2026-07):** macOS file-content recovery (`mac.pagecache` plugin,
bundled in `vol_plugins/`), a fixed iterative `mac.list_files` (also bundled),
**Flock (Flock Team Messaging)** in the comms scanner, and a **global cross-tab
search** in the HTML report (search box highlights matches across every tab; `/`
or Ctrl/⌘-K to focus). See the `SESSION_2026-07-06_*` docs.

**Windows Vol3 cold-start fix (2026-07-08):** the per-image kernel symbol table
is now warmed **serially** before the parallel plugin batch, so the first four
plugins (`info`/`pslist`/`psscan`/`pstree`) no longer lose a race and fail with
`kernel.symbol_table_name` (they used to fail while every later plugin passed —
silently dropping the process list). OS-detection probes (`banners`,
`windows.info`) are now progress-aware instead of fixed-timeout, so large images
(8 GB+) no longer false-stall or time out at 45 s. See Bug #10 in
`ARCHITECTURE_V6.md` and `SESSION_2026-07-08_WINDOWS_KERNEL_SYMBOL_RACE.md`.

**Run-health + crash reporting (2026-07-11):** every extraction is now assessed
for *silent* failure — an empty Processes tab that looks like a clean system —
via `run_health.py` (process corroboration, empty-tab detection, failure
taxonomy; health banner in `SUMMARY.txt` + `run_health.json`). When a run
actually fails, `crash_report.py` also writes a **scrubbed, local**
`crash_report.json` failure-fingerprint (no image content; safe to hand to the
tool author) — Step 1 of the design in `FUTURE_CRASH_REPORTING.md`.

## Run

```bash
cd /home/kali/Desktop/CresCentC_v6

# Interactive menu
python3 crescent_toolkit.py

# Full pipeline (Windows Vol3 image)
python3 crescent_toolkit.py full -i /path/to/Windows.raw -o /output/ -m fast -j 2

# Windows 7 (Vol2 — needs profile)
python3 crescent_toolkit.py full -i Windows2.raw -o /output/ -m fast --profile Win7SP1x64

# Just extraction / report / dumps
python3 crescent_toolkit.py extract    -i image.raw -o /output/ -m fast
python3 crescent_toolkit.py report      -o /output/
python3 crescent_toolkit.py dump-files  -i image.raw -o /output/
python3 crescent_toolkit.py dump-procs  -i image.raw -o /output/

# String Hunt — live-memory search for specific strings
python3 crescent_toolkit.py hunt -i image.raw -o /output/ --hunt-strings "mimikatz" --hunt-pid 892
```

`-i` is the image (not `-f`). Modes: `fast full malware network persistence registry`.
Speed: `normal fast fastest`. Full flag/command reference in `ARCHITECTURE_V6.md`.

## Requirements

* Python 3
* Volatility 3 (and/or Volatility 2) — installable via the toolkit: menu option `I`
* `strings` (binutils); optionally `yara`, `python-evtx`

## Documentation (this directory)

| File | Purpose |
|------|---------|
| `ARCHITECTURE_V6.md` | **Authoritative** — v6 layout, dispatcher pattern, CLI surface, plugin lists, gotchas, bug history, ISF symbols, version lineage |
| `CLAUDE_CODE_TEST_CONTEXT.md` | Testing guide — how to invoke everything, success-vs-false-failure criteria, the Volatility gotchas that look like bugs but aren't |
| `ARCHITECTURE.md` | Module-by-module API reference + Vol JSON field names + suspicious-detection logic (layout section is v5.0-era; defer to ARCHITECTURE_V6 for structure) |
| `PACKAGING_AND_DEPS.md` | What's the tool vs a dependency vs scratch; how bundled Vol3 plugins survive a reinstall; what's in this zip |
| `SESSION_2026-07-05_*` | macOS page-cache plugin, new run modes, auto-ISF build / RHEL resolver |
| `SESSION_2026-07-06_MAC_LISTFILES_NETSTAT_FLOCK.md` | macOS `list_files` RecursionError fix, `netstat` fix + framework patcher, mac field-mapping fixes, Flock comms app |
| `SESSION_2026-07-06_HTML_GLOBAL_SEARCH.md` | HTML report global cross-tab search, report OS-dispatch fix, correlation-tab data/dedup fixes |
| `SESSION_2026-07-08_WINDOWS_KERNEL_SYMBOL_RACE.md` | Windows Vol3 cold-start kernel-symbol race (Bug #10): serial kernel-symbol warm-up, progress-aware detection probes, self-healing serial retry |
| `FUTURE_CRASH_REPORTING.md` | Crash/failure reporting design. **Step 1 (local `crash_report.json`) BUILT**; Step 2 (opt-in transport) planned. Privacy rules, scrub traps, log-signature cheat-sheet |
| `SESSION_2026-07-11_CRASH_REPORT_LOCAL.md` | Local scrubbed failure-fingerprint artifact (`modules/crash_report.py`): schema, privacy guarantees, extractor integration, tests |
