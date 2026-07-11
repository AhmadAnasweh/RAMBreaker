# Kali LiME ISF + Detection-Speed Fix — Session Handoff

**Date:** 2026-06-26
**Target dump:** `/home/kali/Desktop/Ramdumps for testing/kali.lime` (8.5 GB, LiME format)
**Kernel:** `6.12.13-amd64`, build `6.12.13-1kali1`, PREEMPT_DYNAMIC (NOT `-rt`)
**Exact banner (matches dump byte-for-byte):**
`Linux version 6.12.13-amd64 (devel@kali.org) (x86_64-linux-gnu-gcc-14 (Debian 14.2.0-16) 14.2.0, GNU ld (GNU Binutils for Debian) 2.44) #1 SMP PREEMPT_DYNAMIC Kali 6.12.13-1kali1 (2025-02-11)\n\x00`

> **Why a new session:** the final pslist verification keeps getting killed by the 560s
> command timeout (EXIT=124). It is NOT confirmed broken — the run needs to complete
> uninterrupted. Reopen with full privilege / no sandbox / long timeouts and run the
> VERIFY step below to completion.

---

## TL;DR of the two problems

1. **Slow OS detection (~10 min)** — FIXED in code (verified, 14 ms now).
2. **All Linux plugins returned empty** — caused by missing/wrong ISF symbols. An exact
   ISF has now been BUILT and installed, but final verification (pslist showing processes)
   has not completed because the scan keeps timing out. **This is the one open item.**

The dump itself is fine: Vol3 reads it (VMCOREINFO gave `KASLR=0x223000000,
ASLR=0x2f600000, DTB=0x225c22000`; layers stacked `primary/LimeLayer/FileLayer`; banner
identified correctly).

---

## FIX 1 — Fast OS detection  ✅ DONE & VERIFIED

**File:** `/home/kali/Desktop/CresCentC_v6/modules/volatility.py`

- Added method `_fast_format_detect(self, image)` (next to `_raw_os_detect`): reads the
  file header + first 16 MB. Returns `"linux"` on LiME magic (`EMiL`) or a `linux version `
  banner; `"mac"` on `Darwin Kernel Version`/`xnu-`; else `""`.
- Added a **Step 0** block at the top of `auto_detect()` that calls it and, for linux/mac
  with Vol3 present, commits to Vol3 and returns immediately — skipping the slow
  `banners.Banners` scan (up to 300s) and the pointless Vol2 `imageinfo` probe (up to 300s).
- Windows still falls through to the full chain (it needs profile detection).
- **Verified:** `_fast_format_detect("…/kali.lime")` → `"linux"` in **13.9 ms**
  (was ~10 min of timeouts before).

Root cause of the old slowness (from the failed run's log): banners.Banners timed out
(~5 min) → windows.info (5s, fail) → Vol2 imageinfo timed out (~5 min) → raw string scan
finally returned Linux. ~10 min wasted before extraction even started.

---

## FIX 2 — Correct ISF symbols  ⚠️ BUILT & INSTALLED, VERIFICATION PENDING

### Why the repo download didn't work (this is important)
The toolkit downloads ISFs from `Abyss-W4tcher/volatility3-symbols`. For kernel 6.12.13 the
repo has ONLY these five — none match a standard Kali 6.12.13-amd64:
- `Debian/amd64/6.12.13/Debian_6.12.13-amd64_6.12.13-1_amd64.json.xz` (Debian build → different symbol addresses)
- `Debian_6.12.13-cloud-amd64` (cloud variant)
- `KaliLinux_6.12.13-cloud-amd64` (cloud variant)
- `Debian_6.12.13-rt-amd64` (realtime variant)
- `KaliLinux_6.12.13-rt-amd64` ← **the one originally downloaded by mistake** (realtime; wrong kernel)

There is **no** plain `KaliLinux_6.12.13-amd64` published anywhere. So the ISF must be
GENERATED from the exact kernel's debug symbols (the official Volatility method, via
`dwarf2json`). That's why we're not "just downloading it."

Tested and rejected:
- `KaliLinux_6.12.13-rt-amd64...` → wrong kernel variant → fails.
- `Debian_6.12.13-amd64` banner-patched to the Kali banner → **loads but walks 0 processes**
  (Debian and Kali are compiled separately → different symbol addresses; banner-patching only
  fixes the string match, not the addresses). NOTE: the toolkit's resolver `_patch_isf_banner`
  path produces exactly this false-positive — it "verifies" because pslist exits 0, but yields
  empty data.

### What was done
1. Removed both wrong ISFs from `/home/kali/Desktop/volatility3/volatility3/symbols/linux/`:
   - `KaliLinux_6.12.13-rt-amd64_6.12.13-1kali1_amd64.json.xz`
   - `Debian_6.12.13-amd64_6.12.13-1_amd64_patched.json.xz`
2. Downloaded the EXACT Kali debug-symbols package from the archive (current repo only has the
   6.19.14 rolling kernel; 6.12.13 is retired but archived):
   `http://old.kali.org/kali/pool/main/l/linux/linux-image-6.12.13-amd64-dbg_6.12.13-1kali1_amd64.deb`
   (~980 MB) → `/home/kali/Desktop/CresCentC_v6/_isf_build/kdbg.deb`, extracted with
   `dpkg-deb -x` to `_isf_build/x/`. Gives:
   - `_isf_build/x/usr/lib/debug/boot/vmlinux-6.12.13-amd64` (355 MB, has DWARF)
   - `_isf_build/x/usr/lib/debug/boot/System.map-6.12.13-amd64` (7.3 MB)
3. System `dwarf2json` is **v0.6.0 (2020) — too old** for a 6.12 kernel (its ISF loaded but
   gave 0 processes). Downloaded prebuilt **v0.9.0**:
   `https://github.com/volatilityfoundation/dwarf2json/releases/download/v0.9.0/dwarf2json-linux-amd64`
   → `_isf_build/dwarf2json_new`.
4. Built the ISF with v0.9.0:
   ```
   cd /home/kali/Desktop/CresCentC_v6/_isf_build
   ./dwarf2json_new linux \
     --elf x/usr/lib/debug/boot/vmlinux-6.12.13-amd64 \
     --system-map x/usr/lib/debug/boot/System.map-6.12.13-amd64 > kali_v9.json   # 52.5 MB
   xz -T0 kali_v9.json
   cp kali_v9.json.xz /home/kali/Desktop/volatility3/volatility3/symbols/linux/KaliLinux_6.12.13-amd64_6.12.13-1kali1_amd64.json.xz
   ```
5. **Confirmed the installed ISF is good:** banner byte-perfect match to the dump
   (`...(2025-02-11)\n\x00`), 240,569 symbols, 11,765 types, valid xz, contains `init_task`.

### Current open issue — verification keeps timing out
- After clearing a STALE banner cache (`~/.cache/volatility3/identifier.cache`, built while the
  broken ISFs were present — it had been returning "Unsatisfied requirement
  plugins.PsList.kernel.symbol_table_name"), the first pslist run must rebuild the banner cache
  (scan ALL ISFs incl. Windows — slow) AND scan the 8.5 GB image. Combined, this exceeds the
  560s command timeout → EXIT=124 (killed), empty output. **Inconclusive, not confirmed broken.**

---

## NEXT SESSION — VERIFY STEP (run to completion, long/no timeout)

```bash
# 1. Make sure the volatility.py fast-detect edit is intact (it is).

# 2. Clear Vol3 cache (stale entries from the earlier broken ISFs).
rm -rf ~/.cache/volatility3/*

# 3. Warm the banner cache WITHOUT the big image first (faster, no 8.5GB scan):
cd /home/kali/Desktop/volatility3
python3 vol.py isfinfo >/tmp/isfinfo.txt 2>/dev/null   # slow (~minutes), builds identifier.cache
grep -i "6.12.13-amd64.*kali\|KaliLinux_6.12.13" /tmp/isfinfo.txt   # should now list our ISF

# 4. Definitive test — NO timeout, just wait it out (first run also rebuilds cache):
cd /home/kali/Desktop/volatility3
python3 vol.py -q -f "/home/kali/Desktop/Ramdumps for testing/kali.lime" linux.pslist.PsList
#   EXPECT: a table with many process rows (systemd, kthreadd, …). If so → FIX COMPLETE.
```

### If it shows processes → done
- Re-run the toolkit normally; Linux plugins should populate.
- Clean up the temp build dir (~5 GB): `rm -rf /home/kali/Desktop/CresCentC_v6/_isf_build`
  (keep `kdbg.deb` or the ISF if you want to rebuild later).

### If it STILL shows 0 processes on a COMPLETE (non-timed-out, clean-cache) run
Then the ISF genuinely doesn't walk this dump. Try, in order:
1. Rebuild without `--system-map` (let DWARF provide everything):
   `./dwarf2json_new linux --elf x/usr/lib/debug/boot/vmlinux-6.12.13-amd64 > k.json`
2. Or split: `--elf-types vmlinux --system-map System.map`.
3. Re-confirm Vol3 reads the dump: `python3 vol.py -vv -f kali.lime banners.Banners`
   (we already saw VMCOREINFO + correct banner, so the dump is good).
4. As a sanity check, build an ISF for the CURRENTLY-RUNNING kernel from
   `/usr/lib/debug` if the dbg package were installed, or compare symbol addresses.

---

## SECONDARY — recommended toolkit code fixes (not yet done)

1. **`modules/linux_resolver.linux.py` — `_symbols_already_work()`**: it treats "Vol3 exits 0
   without 'Unsatisfied requirement'" (and a 120s timeout) as success. On a slow LiME image with
   a wrong-address ISF, pslist exits 0 with an EMPTY table → false "symbols working" → the whole
   pipeline runs and reports success with empty data. **Tighten it to require ≥1 actual process
   row**, and don't treat a bare timeout as success.
2. **Resolver re-runs banner detection** (`banners.Banners`, 360s) even right after auto_detect
   already had the banner. Pass the banner/kernel from `volatility.auto_detect` into
   `resolve_symbols` to skip the second slow scan.
3. The log banner still prints `v4.0` (cosmetic; logger header not bumped to 6.0).

---

## Files / artifacts state at handoff
- `modules/volatility.py` — fast-detect edit IN PLACE, compiles. ✅
- `volatility3/.../symbols/linux/KaliLinux_6.12.13-amd64_6.12.13-1kali1_amd64.json.xz` — installed (2.7 MB). ✅
- `_isf_build/` — kdbg.deb (1 GB), extracted `x/`, `dwarf2json_new` (v0.9.0), `kali_v9.json(.xz)`. Keep until verified, then delete to reclaim ~5 GB.
- Vol3 cache (`~/.cache/volatility3/`) — was cleared; will rebuild on next run.
- Wrong ISFs (`-rt`, Debian-patched) — removed. ✅
- Doc cleanup from earlier this session (separate task): context dir trimmed 8→4 files (ARCHITECTURE_V6, CLAUDE_CODE_TEST_CONTEXT, ARCHITECTURE, README kept; CHANGES/SESSION_CONTEXT/RAMBREAKER_VERSION_COMPARISON/CresCentC_Session_Summary deleted).
