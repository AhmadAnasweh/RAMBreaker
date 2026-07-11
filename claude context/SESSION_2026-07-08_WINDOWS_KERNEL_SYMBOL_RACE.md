# Session 2026-07-08 — Windows Vol3 cold-start kernel-symbol race (Bug #10)

## Trigger

Full run on `Devil.mem` (8.5 GB, Windows 10, Vol3, `-m full`, speed `fastest`,
4 jobs). Observed in the operator's log:

```
[!] Vol3 silent for 180s — aborting (stall).          # banners detection
[+] Trying Vol3 windows.info...                        # did not confirm
[!] Vol2 imageinfo did not suggest a profile
[+] Detected: Windows (via raw string scan)            # weakest detection path
...
[!] windows.pslist.PsList FAILED: ...['plugins.PsList.kernel.symbol_table_name']
[!] windows.info.Info  FAILED: ...['plugins.Info.kernel.symbol_table_name']
[!] windows.psscan.PsScan FAILED: ...['plugins.PsScan.kernel.symbol_table_name']
[!] windows.pstree.PsTree FAILED: ...['plugins.PsTree.kernel.symbol_table_name']
[+] windows.cmdline.CmdLine completed (46.6s)          # and everything AFTER passes
```

**The tell:** exactly the first four plugins *launched* fail; every plugin
launched after them succeeds (cmdline, dlllist, handles, netscan, malfind…).
28/33 "passed" — but the four that failed are `info`/`pslist`/`psscan`/`pstree`,
so the report silently lost the **process list** and **System Info**.

## Root causes (three linked defects)

### (A) Banners detection passed `-q` → false stall
`volatility.py` step 1 ran `banners.Banners` with `-q`. `-q` silences Vol3's
progress bar — the exact stderr stream `run_vol_until_done` watches for liveness.
On an 8.5 GB image the FileLayer scan runs past the stall grace with no output →
killed as a "stall." `warm_isf_cache` already documented "do NOT pass `-q`"; the
lesson had never been applied to the detection path.

### (B) `windows.info` probe used a fixed 45 s timeout
Three sites called `_run_raw(..., "windows.info.Info", 45)`. On a large cold
image, building the kernel symbol table (kernel-base scan → PDB → ISF) exceeds
45 s, so the probe timed out, detection fell through to the raw-string path, and
**the kernel symbol table was never established** before extraction.

### (C, ROOT) Cold kernel-symbol table built concurrently by the first batch
`_warm_cache` only warmed Vol3's generic *ISF file-index* cache (via `banners`,
which needs no symbols). The *per-image kernel PDB symbol table* is built lazily
by the first symbol-dependent plugin. With 4 parallel jobs, the first four all
trigger that build simultaneously; Vol3's Windows kernel-symbol automagic is
**not concurrency-safe on a cold image**, so they race — all fail the
`kernel.symbol_table_name` requirement while whichever wins writes the cache.
Every plugin after that is a cache hit. This is the Windows twin of the Linux ISF
race (Bug #8), which got a serial warm-up; Windows never did.

## Fixes (all dynamic — no hard-coded timeouts)

### `modules/linux_identify.py`
- `windows_symbols_ready(vol3_cmd, image, logger, stall_grace=120)` → runs
  `windows.info.Info` once via `run_vol_until_done`, returns
  `(ok, out, err)`; `ok` is True when NTBuildLab/Is64Bit/NTMajorVersion appears.
- `warm_windows_kernel_symbols(vol3_cmd, image, logger, retries=2)` → serial,
  progress-aware, idempotent. Confirms the kernel symbol table is built (and
  cached) before the parallel batch. Bails early if Vol3 reports genuinely
  missing/incompatible symbols (so the existing `_try_symbol_download` fallback
  still fires). Never raises.

### `modules/volatility.py`
- Step-1 banners: dropped `-q`, widened `stall_grace` to 300 (fix A).
- New `VolatilityWrapper._probe_windows_info(image)` → `run_vol_until_done`
  wrapper; replaces the three fixed-45 s `windows.info` probes in `auto_detect`
  (×2) and `detect_for_os` (fix B). Detects Windows AND warms kernel symbols.

### `modules/extractor.windows.py`
- `_warm_cache` now calls `warm_windows_kernel_symbols()` after the ISF warm,
  **serially before** the `ThreadPoolExecutor` batch (fix C).
- **Self-healing net:** during the batch, any plugin failing on
  `symbol_table_name` / `symbol table requirement` is collected into
  `symbol_retry`. After the batch (symbols now warm) they are **re-run serially**,
  and recoveries are folded back into the OK/fail counts and clear
  `_failed_parents`.

## Why "dynamic"

- (A)/(B) wait on **real Vol3 progress** and adapt to image size + box speed —
  no fixed cap to guess wrong.
- (C) establishes the kernel symbol table **once**, so every later plugin is a
  cache hit; the serial retry only fires if a race somehow still slips through.
- Warm cache → the warm-up is a fast confirm. Small images → the progress-aware
  runner returns the instant the plugin finishes. No regression for the
  previously-fast Windows images (`Windows.raw`, `Win2012_activity.mem`).

## Validation done this session

- `py_compile` clean on all three modules.
- Import smoke test: `linux_identify.{windows_symbols_ready,
  warm_windows_kernel_symbols}` present; `VolatilityWrapper._probe_windows_info`
  present; `extractor.windows.Extractor` loads via the dispatcher.
- **Not yet re-run end-to-end** on `Devil.mem` (8.5 GB → multi-minute run).
  Expected on re-run: no `Vol3 silent for 180s`; `windows.info` confirms
  Windows/Vol3 up front; one serial `windows.info` warm line; **0
  `symbol_table_name` failures**; all 33 plugins succeed → Processes tab + System
  Info populated.

## Incidental: disk was 100% full

Root cause of a mid-session `ENOSPC` on file writes: a **full 8.5 GB duplicate**
of `Devil.mem` left by VMware drag-and-drop at
`~/.cache/vmware/drag_and_drop/pdAEBi/Devil.mem`. Deleted (safe cache) → freed
8.5 GB. `/var/cache/apt/archives` held another ~12 GB (`sudo apt clean`). Added
as Gotcha #15.

## Re-run command

```bash
cd /home/kali/Desktop/RAMBreaker_toolkit
python3 crescent_toolkit.py full -i /home/kali/Desktop/Devil.mem \
  -o /home/kali/Desktop/Devil_mem -m full --speed fastest -j 4
# Watch for: "Windows kernel symbol table established (serial warm-up)"
# then zero '...kernel.symbol_table_name' failures.
```
