# Kali_kerneltest.lime — Identifier Fix + ISF Build — Session Handoff

**Date:** 2026-06-28
**VM kernel (this machine):** `6.12.13-amd64`, build `6.12.13-1kali1`, **PREEMPT_DYNAMIC** (NOT `-rt`)
**Target dump:** `/home/kali/Desktop/Kali_kerneltest.lime` (2,146,951,262 bytes ≈ 2.1 GB, **LiME format**, header magic `EMiL`). It is a LiME memory dump of THIS exact running kernel.

**Exact kernel banner of this VM / the dump (must match the ISF byte-for-byte):**
```
Linux version 6.12.13-amd64 (devel@kali.org) (x86_64-linux-gnu-gcc-14 (Debian 14.2.0-16) 14.2.0, GNU ld (GNU Binutils for Debian) 2.44) #1 SMP PREEMPT_DYNAMIC Kali 6.12.13-1kali1 (2025-02-11)
```
(In the ISF the `linux_banner.constant_data` is this string + a trailing `\n\x00`.)

---

## Original task (two parts)

1. **Check the "linux identifier" (`modules/linux_identify.py`) and fix anything inside it.** ✅ DONE
2. **Generate ("create a symbol table") for this VM's kernel and test it on `Kali_kerneltest.lime`.** 🟡 BLOCKED on RAM (see below) — everything is staged; only the dwarf2json build + install + verify remain.

---

## PART 1 — Identifier fixes ✅ DONE (committed to disk)

**File:** `modules/linux_identify.py`. Two real bugs fixed:

### Fix 1 — `has_vol3_linux_isf()` looked in the WRONG symbols directory
- **Was:** `candidate = p.parent.parent / "symbols" / "linux"` where `p` is a `vol.py` path.
  For `/home/kali/Desktop/volatility3/vol.py` that resolves to `/home/kali/Desktop/symbols/linux` — one level too high. The real install dir (and the resolver-canonical one, see `linux_resolver.linux.py::_vol3_symbols_dir` = `vol3/"volatility3"/"symbols"/sub`) is `/home/kali/Desktop/volatility3/volatility3/symbols/linux`.
- **Effect of the bug:** the "is a matching ISF already installed?" check **always returned False** for properly-installed ISFs, so the toolkit would needlessly re-resolve/re-download symbols every run.
- **Now:** checks `p.parent/"volatility3"/"symbols"/"linux"` (cloned layout) **and** `p.parent/"symbols"/"linux"` (flat/pip layout), de-duped, plus the `~/.cache/volatility3/symbols/linux` fallback.
- **Verified:** `has_vol3_linux_isf(<-rt banner>)` now returns `True` (it finds and reads the real dir, which currently holds the `-rt` ISF). Before the fix it returned `False`.

### Fix 2 — `detect_linux_profile_vol2()` operator-precedence bug
- **Was:** `if l.startswith("Linux") and "x64" in l or "x86" in l:` → parses as `(startswith AND x64) OR x86`, so ANY `--info` line containing `x86` anywhere was treated as a Linux profile.
- **Now:** `if l.startswith("Linux") and ("x64" in l or "x86" in l):` (matches the correct sibling `detect_linux_profile_vol2_list`).

Both changes are syntax-checked and import-tested. Nothing else in `linux_identify.py` needed changing — LiME detection (`fast_format_detect`) already returns `"linux"` correctly on this dump (verified: header `EMiL` → `OS guess: linux`).

---

## PART 2 — ISF build 🟡 BLOCKED ON MEMORY (OOM), everything else staged

### Why we must BUILD (not download) the ISF
The toolkit downloads ISFs from `Abyss-W4tcher/volatility3-symbols`. For 6.12.13 the repo has only `-rt` (realtime), `-cloud`, and **Debian** builds — none match a plain Kali `6.12.13-amd64` PREEMPT_DYNAMIC kernel. There is **no** published `KaliLinux_6.12.13-amd64` ISF.
- The `-rt` ISF (`KaliLinux_6.12.13-rt-amd64...`) is the ONLY one currently installed — **WRONG kernel variant**, banner is `6.12.13-rt-amd64 ... PREEMPT_RT`, will not walk this dump.
- A banner-patched Debian ISF "verifies" (pslist exits 0) but **walks 0 processes** (Debian and Kali are compiled separately → different symbol addresses). Beware the resolver's `_patch_isf_banner` false-positive path (see prior `KALI_LIME_ISF_FIX_HANDOFF.md`).
So the ISF must be generated from the exact kernel's DWARF debug symbols via `dwarf2json` — the official Volatility method.

### What is ALREADY staged on disk (survives nothing — see "VM shutdown" note)
Everything is in `/home/kali/Desktop/CresCentC_v6/_isf_build/`:
- `dwarf2json` — prebuilt **v0.9.0** (schema 6.2.0), executable. ✅ (the system one is too old; do not use it)
- `kdbg.deb` — `linux-image-6.12.13-amd64-dbg_6.12.13-1kali1_amd64.deb` (1,027,913,536 B ≈ 1 GB) downloaded from `http://old.kali.org/kali/pool/main/l/linux/`. ✅
- `x/usr/lib/debug/boot/vmlinux-6.12.13-amd64` (355 MB, **has DWARF** — `.debug_info` etc. confirmed). ✅
- `x/usr/lib/debug/boot/System.map-6.12.13-amd64` (7.3 MB). ✅
- `kali_v9.json` (0 B) and `build.err` (0 B) — **leftovers from the failed/OOM-killed builds; delete them.**

So the next session can SKIP the 1 GB download and the deb extraction — go straight to the dwarf2json build.

### The blocker: OOM
This VM has only **~1.9 GB RAM + 1.0 GB swap** (swap already ~790 MB used by the desktop). dwarf2json's **live** working set to parse a 6.12 kernel's DWARF is **~1.4 GB+**. The build was OOM-killed twice (`dmesg`: "Out of memory: Killed process ... dwarf2json", anon-rss 1.14 GB then 1.36 GB). `GOMEMLIMIT`/`GOGC` tuning does NOT help — the memory is live data, not garbage. `dwz` (DWARF dedup) is not installed. **More memory is genuinely required.**

> ⚠️ **VM SHUTDOWN NOTE:** the existing 1 GB swap is a real `/swapfile`. If you add `/swapfile2` it will NOT persist across reboot unless it's in `/etc/fstab` — that's fine, just re-add it next session (command below). The `_isf_build/` artifacts on disk **do** persist across reboot.

---

## NEXT SESSION — RESUME STEPS (do these in order)

### Step 0 — Add swap so the build fits (needs sudo; run in the Claude prompt with `!`)
```
! sudo fallocate -l 8G /swapfile2 && sudo chmod 600 /swapfile2 && sudo mkswap /swapfile2 && sudo swapon /swapfile2 && free -h
```
Confirm `free -h` shows ~9 GB total swap. (Remove later: `sudo swapoff /swapfile2 && sudo rm /swapfile2`.)

### Step 1 — Build the ISF (artifacts already on disk; no download needed)
```bash
cd /home/kali/Desktop/CresCentC_v6/_isf_build
rm -f kali_v9.json build.err          # clear the empty OOM leftovers
# If _isf_build/x was deleted to reclaim space, re-extract first:
#   dpkg-deb -x kdbg.deb x/
./dwarf2json linux \
  --elf x/usr/lib/debug/boot/vmlinux-6.12.13-amd64 \
  --system-map x/usr/lib/debug/boot/System.map-6.12.13-amd64 > kali_v9.json 2> build.err
echo "exit=$? size=$(stat -c%s kali_v9.json)"     # expect exit=0, size ≈ 50+ MB (prior session got 52.5 MB)
```
(With ample swap, GC tuning is unnecessary; a plain run completes, just slowly via swap.)

### Step 2 — Compress + install with the CORRECT (non-rt) name
```bash
cd /home/kali/Desktop/CresCentC_v6/_isf_build
xz -T0 -k kali_v9.json                 # -> kali_v9.json.xz
cp kali_v9.json.xz \
  /home/kali/Desktop/volatility3/volatility3/symbols/linux/KaliLinux_6.12.13-amd64_6.12.13-1kali1_amd64.json.xz
```

### Step 3 — Sanity-check the banner is byte-exact (PREEMPT_DYNAMIC, NOT -rt)
```bash
python3 - <<'EOF'
import lzma,json,base64
p="/home/kali/Desktop/volatility3/volatility3/symbols/linux/KaliLinux_6.12.13-amd64_6.12.13-1kali1_amd64.json.xz"
d=json.load(lzma.open(p,'rt'))
b=base64.b64decode(d['symbols']['linux_banner']['constant_data'])
print(repr(b))                          # must contain 'PREEMPT_DYNAMIC' and '6.12.13-amd64', end with \n\x00
print("symbols:", len(d['symbols']), "types:", len(d.get('user_types',{})))
EOF
```

### Step 4 — Definitive test on the dump (clear stale cache first; NO short timeout)
```bash
rm -rf ~/.cache/volatility3/*           # prior cache was built with the wrong ISFs
cd /home/kali/Desktop/volatility3
python3 vol.py -q -f /home/kali/Desktop/Kali_kerneltest.lime linux.pslist.PsList
#   EXPECT: a table with many rows (systemd, kthreadd, ...). First run also rebuilds the
#   banner cache (scans all ISFs) AND scans the 2.1 GB image — let it run to completion,
#   do NOT kill it on a short timeout (prior sessions hit EXIT=124 at 560s = killed, NOT broken).
```
If it shows processes → **ISF is correct, Part 2 done.** Then re-test the identifier path:
```bash
cd /home/kali/Desktop/CresCentC_v6
python3 modules/linux_identify.py -i /home/kali/Desktop/Kali_kerneltest.lime   # -> OS guess: linux
python3 -c "import importlib.util as u; s=u.spec_from_file_location('li','modules/linux_identify.py'); m=u.module_from_spec(s); s.loader.exec_module(m); print('ISF found for dump banner:', m.has_vol3_linux_isf(open('/dev/stdin').read().strip()))" <<'B'
Linux version 6.12.13-amd64 (devel@kali.org) (x86_64-linux-gnu-gcc-14 (Debian 14.2.0-16) 14.2.0, GNU ld (GNU Binutils for Debian) 2.44) #1 SMP PREEMPT_DYNAMIC Kali 6.12.13-1kali1 (2025-02-11)
B
#   EXPECT: ISF found for dump banner: True   (proves Fix 1 + the new ISF work end-to-end)
```

### Step 5 — If pslist STILL shows 0 processes on a COMPLETE (non-timed-out) run
Try, in order (see prior `KALI_LIME_ISF_FIX_HANDOFF.md` for context):
1. Rebuild without `--system-map` (let DWARF provide symbols):
   `./dwarf2json linux --elf x/usr/lib/debug/boot/vmlinux-6.12.13-amd64 > kali_v9.json`
2. Or split: `--elf-types <vmlinux>` + `--elf-symbols <vmlinux>` (or `--system-map`).
3. Confirm Vol3 reads the dump at all: `python3 vol.py -f /home/kali/Desktop/Kali_kerneltest.lime banners.Banners` (should show VMCOREINFO + the correct banner).

### Step 6 — Cleanup once verified (reclaims ~5 GB)
```bash
rm -rf /home/kali/Desktop/CresCentC_v6/_isf_build/x        # 355 MB vmlinux + extract tree
# keep kdbg.deb + dwarf2json + kali_v9.json.xz if you want to rebuild later, or delete kdbg.deb (1 GB) too
sudo swapoff /swapfile2 && sudo rm /swapfile2              # remove the temp swap
```

---

## Current on-disk state at handoff (2026-06-28)
- `modules/linux_identify.py` — both fixes applied, syntax-checked, import-tested. ✅
- `_isf_build/dwarf2json` (v0.9.0), `_isf_build/kdbg.deb` (1 GB), `_isf_build/x/usr/lib/debug/boot/{vmlinux,System.map}-6.12.13-amd64` — all present. ✅
- `_isf_build/kali_v9.json` + `build.err` — 0 B leftovers, delete. 
- `volatility3/.../symbols/linux/` — has the WRONG `KaliLinux_6.12.13-rt-amd64...` ISF + old Alma/Centos/Debian ISFs. The correct `KaliLinux_6.12.13-amd64_...` is NOT YET built/installed.
- Disk: ~32 GB free on `/`. dwarf2json v0.9.0 confirmed. Vol3 at `/home/kali/Desktop/volatility3/` (vol.py at repo root, symbols at `volatility3/volatility3/symbols/`).
- Tasks: #1 (identifier fixes) DONE; #2 (build ISF) IN PROGRESS/blocked; #3 (verify on dump) PENDING.

## One-line summary for the next session
Identifier (`linux_identify.py`) is fixed. To finish: add swap (Step 0), then run dwarf2json on the already-extracted `_isf_build/x/.../vmlinux-6.12.13-amd64` (+ System.map), install the result as `KaliLinux_6.12.13-amd64_6.12.13-1kali1_amd64.json.xz`, and verify with `linux.pslist.PsList` on `Kali_kerneltest.lime`.
