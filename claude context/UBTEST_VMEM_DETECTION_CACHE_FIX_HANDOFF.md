# UBtest.vmem — OS Misdetection + Symbol-Cache Stall — Session Handoff

**Date:** 2026-06-30
**Trigger:** User ran the toolkit on `/home/kali/Downloads/UBtest.vmem` (4.0 GB, VMware
`.vmem`, **Ubuntu 6.8.0-31-generic**). It was **misdetected as macOS**, then on a re-run
it **hung after downloading the ISF**.

Three distinct problems were found and fixed (code), plus one that is an **image/data
limitation, not a toolkit bug** (the vmem is missing its `.vmss`/`.vmsn` companion).

---

## PROBLEM 1 — Ubuntu image misdetected as macOS ✅ FIXED

**File:** `modules/linux_identify.py` — `fast_format_detect()` and `raw_os_detect()`.

**Root cause:** both functions did `chunk.decode("ascii", errors="ignore").lower()` over the
first 16 MB / 10 MB, then substring-searched. `errors="ignore"` **deletes every non-ASCII
byte and glues the remainder together**, so 16 MB of binary collapses into one contiguous
ASCII run where short needles appear by chance. The macOS needle **`xnu-` is only 4 chars**
and was checked *before* the Linux needle, so random bytes that happened to spell `xnu-`
(found at offset 4548907 in this image) returned `"mac"`. The real `Linux version` banner
sits deeper than the scanned window on a `.vmem`, so the Linux branch never fired.
`.lime` images dodged this because the `EMiL` magic short-circuits before the string search.

**Fix:** search **raw bytes** with `bytes.lower()` (folds only ASCII A–Z, keeps other bytes
in place — no collapsing), and require `xnu-` to be followed by a digit
(`re.search(rb"xnu-\d", low)`, real banners are `xnu-8020.140.41`). Dropped the weak
`mac os x` / `com.apple` needles from `raw_os_detect` (they appear in browser caches/plists
on Linux). Verified: `fast_format_detect → ''`, `raw_os_detect → 'linux'` on UBtest.vmem;
`Mint.lime → 'linux'` (via EMiL, no regression).

---

## PROBLEM 2 — Vol3 symbol-cache stall / never warms ✅ FIXED (dynamic)

**Symptom:** every run sat for minutes at "Trying Vol3 banners detection…" / symbol
verification and then fell through or "hung".

**Root causes (layered):**
1. **~6,151 ISF files to index.** The Windows symbol pack is present **twice**:
   `volatility3/volatility3/symbols/windows.zip` (3,019 files) **+** an extracted duplicate
   `windows/ntkrnlmp.pdb/`,`ntkrnlpa.pdb/`,`ntkrpamp.pdb/`,`ntoskrnl.pdb/` (~3,026 loose
   `.json`). Vol3 indexes both → cold-cache build ≈ **700–730 s** on this box.
2. **Fixed timeouts killed the build mid-way.** auto_detect banners cap was `min(300,…)`;
   resolver verify was image-scaled `min(600, max(180, gb*120))` = 480 s for 4 GB;
   `_symbols_already_work` was a hard 120 s. All < 730 s → killed before commit.
   Vol3 commits the identifier cache (a SQLite DB, `~/.cache/volatility3/identifier.cache`,
   table `cache`) in ONE transaction at the end, so a killed build leaves `cache` = **0 rows**
   → next run rebuilds from scratch → **never warms** (vicious cycle).
3. **Concurrent vol.py processes corrupt the half-built cache.** The toolkit runs 4 plugins
   in parallel; the user also had **3 stacked toolkit instances** (Ctrl-Z'd, state `T`, not
   killed) — all racing on the same SQLite cache → rollback → `cache` stays 0 rows.
4. **The existing extractor `_warm_cache()` was broken**: it decided "cache warm?" by
   `if any files exist in ~/.cache/volatility3/` — but `valid_isf.hashcache` is ALWAYS there,
   so it **always skipped warming** while the cache was cold, then launched the 4 parallel
   jobs onto the cold cache. It also used `capture_output=True` (64 KB pipe-buffer deadlock
   risk on Vol3's huge progress stream) and a fixed 1800 s.

**Fix (all dynamic — no magic numbers):** new helpers in `modules/linux_identify.py`:
- `isf_cache_is_warm()` — checks the actual SQLite `cache` table row count (>0 = warm), not
  mere file presence. Honours `XDG_CACHE_HOME`.
- `run_vol_until_done(cmd, …, stall_grace=180, hard_ceiling=3000)` — runs a Vol3 command via
  `Popen` with stdout/stderr to **temp files** (no pipe deadlock) and **waits on real
  progress**: it tracks output growth and only aborts on a genuine stall (no output for
  `stall_grace` s) or an absolute `hard_ceiling`. Adapts to machine/image instead of guessing.
- `warm_isf_cache(vol3_cmd, image, logger)` — if not already warm, runs one
  `banners.Banners` through `run_vol_until_done` so the cache finishes building and commits.

Wired in:
- `modules/volatility.py` `auto_detect()` — banners step now uses `run_vol_until_done`
  (removed the `min(300,…)` cap). Warms + detects in one pass.
- `modules/linux_resolver.linux.py` — `_symbols_already_work`, `_verify_works_strict`,
  and a `warm_isf_cache()` call at the top of `resolve_symbols()` all now progress-aware.
- `modules/extractor.{linux,windows,mac}.py` `_warm_cache()` — replaced the broken body
  with a delegation to `linux_identify.warm_isf_cache(...)`.

**Validated:** a single clean `banners.Banners` commits `cache` = **6151 rows**;
`isf_cache_is_warm()` → True; warm pslist runs in ~12 s (was timing out).
**One-time cost:** the first run on a cold cache still pays ~700 s to build the cache — that
is unavoidable Vol3 behaviour; it now COMPLETES and commits instead of being killed.

**Optional further speedup (NOT done):** delete the duplicate extracted Windows symbols
(`volatility3/volatility3/symbols/windows/*.pdb/` — keep `windows.zip`) to ~halve the file
count (730 s → ~365 s). Left alone to avoid touching the user's symbol store.

---

## PROBLEM 3 — Symbol verification falsely rejected the correct ISF ✅ FIXED (dynamic)

After Problems 1–2, detection→Linux and the right ISF
(`Ubuntu_6.8.0-31-generic_6.8.0-31.31_amd64.json.xz`) downloads fine, but
**`linux.pslist` returns 0 processes** on this image (see Problem 4). The resolver verifies
ISFs with pslist, so it would mark the correct ISF "broken" and loop/fail.

**Fix:** `modules/linux_resolver.linux.py` new `_scan_finds_processes()` — when the
list-walk plugin (pslist) is empty but the run was clean (rc 0, no "Unsatisfied"), confirm
via **`linux.psscan.PsScan`** (signature-scans physical memory, no page-table walk). Both
`_symbols_already_work` and `_verify_works_strict` now fall back to it. macOS skipped (no
scan equivalent). **Validated:** `_symbols_already_work(UBtest.vmem) → True` (184 s).

---

## PROBLEM 4 — pslist empty: MISSING .vmss/.vmsn companion ⚠️ IMAGE LIMITATION (not a bug)

**This is why processes don't show with pslist/pstree/psaux — and it is not fixable in code.**

`UBtest.vmem` is a bare VMware `.vmem` (raw guest RAM) with **no companion `.vmss`/`.vmsn`**
in `~/Downloads/`. Verbose Vol3 (`-vv`) shows:
```
Identified banner: Linux version 6.8.0-31-generic ... Ubuntu      ← ISF matched ✓
Values found in VMCOREINFO: KASLR=0x9ae00000 ASLR=0x1b800000 DTB=0x9e23c000   ← DTB found ✓
Stacked layers: ['primary', 'FileLayer']        ← FLAT file, no VmwareLayer
WARNING ...vmware: No metadata file found alongside VMEM file. A VMSS or VMSN file
        may be required to correctly process a VMEM file ...
```
For a 4 GB VM the **PCI memory hole** remaps high RAM; the layout map lives in the
`.vmss`/`.vmsn`. Without it Vol3 reads the vmem **flat**, so the kernel's virtual→physical
page-table walk (used by `pslist`/`pstree`/`psaux`/`lsof`/…) resolves to the wrong bytes and
finds nothing. **Proof it's a layout issue, not an ISF issue:** `linux.psscan.PsScan` (raw
physical scan, no translation) **DOES list processes** — systemd (PID 1), kthreadd (PID 2),
kworker, … at physical offsets ~0xc0890000 (≈3.2 GB).

**Real fix (user-side):** place `UBtest.vmss` (or `.vmsn`) next to `UBtest.vmem` (same base
name) — VMware writes it when the VM is suspended/snapshotted. Then `pslist` & friends work
normally. Alternatively re-capture as LiME (`EMiL`) or a proper crash dump.

**Note:** the toolkit's Linux plugin set (`vol3-linux-fast`/`-full` in
`modules/extractor.linux.py`) is **all list-walk** (pslist/pstree/psaux/…); it does **not**
include `linux.psscan`. So even though psscan works, the toolkit won't surface processes for
a metadata-less vmem. Possible future enhancement: add `linux.psscan.PsScan` to the pipeline
and have the process consumers (process_tree, correlator, html_report) fall back to its JSON
when pslist/pstree are empty. NOT done this session (scope; the proper fix is the .vmss).

---

## State at handoff (2026-06-30)
- Edited & syntax-checked: `linux_identify.py`, `volatility.py`, `linux_resolver.linux.py`,
  `extractor.linux.py`, `extractor.windows.py`, `extractor.mac.py`.
- Vol3 cache is **warm** (`cache` = 6151 rows). `~/.cache/volatility3/identifier.cache`.
- ISFs in `volatility3/volatility3/symbols/linux/`: `Ubuntu_6.8.0-31-generic_…amd64.json.xz`
  (clean, correct) + `…_patched.json.xz` (resolver-made; harmless here, both restored).
- No stray vol.py/crescent processes (the 3 stacked instances were killed).
- `UBtest.vmem` still has **no** `.vmss`/`.vmsn` — pslist-family will stay empty until one is
  provided; psscan confirms the data + ISF are correct.

## One-line summary
Misdetection (xnu- 4-char false match) and the cache stall (fixed timeouts killing the
cache build before it commits, + a broken warm-cache check, + parallel SQLite contention) are
**fixed dynamically**; the remaining empty-pslist is because `UBtest.vmem` lacks its
`.vmss`/`.vmsn` companion (Vol3 reads it flat) — psscan proves the ISF and data are fine.

---

## END-TO-END VALIDATION on a GOOD image — `memory.vmem` (2026-06-30) ✅ FULL PASS

`/home/kali/Desktop/memory/memory.vmem` (4.0 GB, Ubuntu **6.5.0-41-generic**) has its
companion **`memory.vmsn`** (5.5 MB) alongside it, so it exercises the fixes on an image
Vol3 can fully address. Interactive `[C]` CORE run, auto-detect, fastest:
- Detected **Linux** (no macOS misfire) — Problem 1 fix holds.
- Cache **warm** (`cache`=6152 rows) — no rebuild stall; Problem 2 fix holds.
- Correct ISF `Ubuntu_6.5.0-41-generic_…amd64.json.xz` downloaded, installed, **verified**;
  the run advanced straight into parallel extraction — Problem 3 fix holds (no false reject,
  no loop, no "hang").
- The verification pslist that *looks* frozen is just the progress-aware scan running
  silently (state `R`/`D`, ~50 s here on a warm cache), then the toolkit moved on.
- **`json/linux_pslist_PsList.json` = 344 processes** (systemd, kthreadd, rcu_gp, …) — a
  full list-walk, because the `.vmsn` lets Vol3 build the proper layer. This is the direct
  contrast to `UBtest.vmem` (no companion → pslist empty, psscan-only).

**Takeaway:** the toolkit code is correct end-to-end. Whether pslist-family populates is
decided entirely by whether the `.vmem` has its `.vmss`/`.vmsn` companion (Problem 4).

## Images on disk (2026-06-30)
- `/home/kali/Desktop/memory/memory.vmem` + `memory.vmsn` — Ubuntu 6.5.0-41 — **fully works**.
- `/home/kali/Downloads/UBtest.vmem` — Ubuntu 6.8.0-31 — **no companion** → pslist empty
  (psscan works). Needs `UBtest.vmss`/`.vmsn`.
- `/home/kali/Desktop/Mint.lime` — LiME (`EMiL`) — detects Linux via magic.
