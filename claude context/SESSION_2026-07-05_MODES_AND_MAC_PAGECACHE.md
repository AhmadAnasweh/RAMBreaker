# Session Handoff — Two New Pipeline Modes + macOS Page-Cache File Recovery

**Date:** 2026-07-05
**Scope:** Add two run modes ("Only Vol Plugins", "DFIR"); write a brand-new
Volatility 3 plugin that recovers **file content** from macOS RAM
(`mac.pagecache.Pagecache`); wire that plugin into CresCentC's macOS file dumper
so `dump-files` / DFIR on macOS recover bytes instead of only listing.

Companion docs (same folder):
- `MAC_PAGECACHE_PLUGIN.md` — deep technical reference for the plugin.
- `MAC_PAGECACHE_POC.md` — proof-of-concept write-up (recovered artifacts).
- `PACKAGING_AND_DEPS.md` — directory inventory (tool vs deps vs scratch), how the
  bundled `mac.pagecache` plugin survives a Vol3 reinstall, the delete+reinstall+
  retest procedure, and what's in the tool zip.

---

## 1. Executive summary

1. **Two new pipeline modes** in `crescent_toolkit.py`, alongside CORE/DEFAULT:
   - **"Only Vol Plugins"** — CORE minus the strings→IOC→browser→comms scan (fast,
     plugin-focused). CLI `plugins` (alias `ctf`), menu `[T]`.
   - **CresCent Eye** (EXPERIMENTAL) — CORE, then dump **all** processes + **all**
     files. CLI `eye` (alias `dfir`), menu `[F]`. Prints an experimental / "dumps
     everything" warning on launch. (Formerly named "DFIR" in this session.)
2. **`mac.pagecache.Pagecache`** — a NEW Vol3 plugin that carves file content out
   of the macOS Unified Buffer Cache. Vol3 previously had NO macOS content
   recoverer (only `mac.list_files`, paths only). Proven: recovered
   `SystemVersion.plist`, `dyld`, `.GlobalPreferences.plist`, an AddressBook
   app-state blob — all byte-verified.
3. **Integration** — `modules/file_dumper.mac.py` now recovers content via the
   plugin, so `dump-files` and `dfir`/`dump-all` on macOS pull real bytes. This
   overturns the long-standing "macOS = listing only" limitation.

---

## 2. New modes (crescent_toolkit.py)

### "Only Vol Plugins" (was proposed as "CTF")
- Runs the Volatility plugins + every fast, plugin-JSON-derived step (process
  tree, network map, process/command/MITRE analysis, correlation, popular files,
  scheduled tasks, registry, timeline, HTML report) but **SKIPS Step 2**
  (strings → IOC → browser → comms), the slow evidence-scan.
- Implemented by parameterizing CORE: `_cmd_core(args, skip_ioc=False, label="FULL")`.
  `_cmd_ctf(args)` calls `_cmd_core(args, skip_ioc=True, label="ONLY VOL PLUGINS")`.
- Wiring: CLI commands `plugins` **and** `ctf` (alias, kept for back-compat) →
  `_cmd_ctf`; interactive menu key **`[T]`**; both in argparse `choices` and the
  `dispatch` table.
- Name history: originally built as "CTF", renamed to "Only Vol Plugins" per
  request. `ctf` remains a working CLI alias.

### CresCent Eye  (EXPERIMENTAL — was "DFIR" earlier this session)
- `_cmd_dfir(args)` (function name kept) = prints an **experimental / "dumps
  everything" warning**, then `_cmd_core(args, label="CRESCENT EYE")`, then
  `_cmd_dump_all(args)`. CORE runs first (writes SUMMARY.txt + json/), so dump-all
  reuses that prior extraction (`_init_vol_from_existing`, no re-detection) and
  dumps every process as its native executable + every recoverable file into
  `<out>/dumped_all/`.
- Warning shown on launch: "CresCent Eye is EXPERIMENTAL — NOT fully stable. It
  DUMPS EVERYTHING … expect large output (many GB) and long runtimes."
- Wiring: CLI **`eye`** (alias `dfir` kept), menu key **`[F]`**
  (`[F] CresCent Eye … (experimental — dumps everything)`), argparse `choices`,
  `dispatch`. NB: the help epilog already had an `eye` example — now valid.

### Dump ordering — `--files-first`  (applies to dump-all AND dfir)
- `_cmd_dump_all` now factors its two phases into local `_dump_procs_phase()` /
  `_dump_files_phase()` and runs them in an order chosen by `args.files_first`:
  **processes-first by default; files-first with `--files-first`.**
- Why: on macOS especially, dump-all dumps every VMA of every process
  (`proc_maps`) — thousands of files / several GB / tens of minutes — BEFORE it
  ever reaches files. With file content the usual priority (page-cache recovery is
  smaller and faster), `--files-first` recovers files up front, then does the
  heavy process memory.
- Wiring: CLI `--files-first` (`dest=files_first`); interactive prompt
  `_prompt_files_first` in the `[6]` dump-all and `[F]` DFIR menu handlers
  (Enter = processes first, 'f' = files first).
- Usage: `crescent_toolkit.py dfir -i MAC -o out/ --files-first`

### Files touched
- `crescent_toolkit.py`:
  - `_cmd_core(args, skip_ioc=False, label="FULL")` — Step 2 gated behind
    `if not skip_ioc:`; completion banner uses `label`.
  - NEW `_cmd_ctf`, `_cmd_dfir`.
  - argparse `choices` += `plugins, ctf, dfir`; `dispatch` += same.
  - menu display lines `[T]`/`[F]` + handlers (mirror `[C]`/`[D]`: prompt image,
    OS, speed, run).

### Test results (all `-m fast --speed fast -j 4`)
| Mode | Image | Result |
|---|---|---|
| Only Vol Plugins | MAC | Step 2 SKIPPED, 9 plugins, report; **0 strings files**; 38.5 s |
| Only Vol Plugins | Challenge.raw | Step 2 SKIPPED, 32 json, report; 0 strings; 269 s |
| Only Vol Plugins | Mint.lime | Step 2 SKIPPED, 15 json, report; 0 strings; 363 s |
| DFIR | Challenge.raw | rc=0: CORE 320 s → **48/53 procs** as PE → **2,666/3,218 files** recovered; DUMP-ALL complete |
| DFIR | MAC | CORE OK → dump-all: process VM dumps (proc_maps) + **page-cache content-recovered files** (mac.pagecache) |

DFIR gotcha observed: OS auto-detection can stall if the box is under heavy load —
`banners.Banners` runs through `run_vol_until_done` (stall_grace=180 s); if another
heavy run starves it for 180 s, banners is aborted and detection falls through to
the Windows/Vol2 path (mis-detecting a mac image). Run heavy DFIR jobs one at a
time, or the mac banners detect can be starved. (Re-running with the box idle
detects macOS via banners in ~30–60 s as normal.)

`iocs/` may still exist under an "Only Vol Plugins" run — it is created by the
popular_files / scheduled_tasks steps, NOT by IOC extraction (which is skipped);
the real proof of skipping is **zero `strings_*.txt`**.

---

## 3. NEW plugin: `mac.pagecache.Pagecache`  (see MAC_PAGECACHE_PLUGIN.md)

- **Location:** `/home/kali/Desktop/volatility3/volatility3/framework/plugins/mac/pagecache.py`
- **Gap it fills:** Vol3 has `windows.dumpfiles` and `linux.pagecache.*` for file
  content, but **nothing for macOS**. `mac.list_files` stops at the vnode (paths).
- **What it does:** for each regular-file vnode, walks the Unified Buffer Cache to
  the file's resident pages and reassembles the content:
  ```
  vnode.v_un.vu_ubcinfo -> ubc_info.ui_control -> memory_object_control.moc_object
    -> vm_object.memq -> vm_page(offset, phys_page)
  ```
  reads each resident page from the physical layer (`phys_page * 4096`), writes it
  at `page.offset`, truncates to `ubc_info.ui_size` (sparse for non-resident pages).
- **The hard part (why it didn't exist):** XNU packs `memq` links into 32-bit
  `vm_page_packed_t`. The plugin resolves XNU's own packing constants
  (`vm_packed_pointer_shift`, `vm_min_kernel_and_kext_address`,
  `vm_packed_from_vm_pages_array_mask`, `vm_pages`) from **kernel globals by symbol**
  (KASLR handled) and implements `VM_PAGE_UNPACK_PTR` (dual array/zone scheme).
- **Key correctness gotcha:** pages whose `phys_page == 0` (or absent/fictitious)
  are placeholders with NO data — they must be skipped (`_page_has_data`). The
  `CachedPages` column counts only pages backed by a real physical frame, so the
  listing reflects what is *actually* recoverable.
- **Usage:**
  ```bash
  vol.py -f MAC mac.pagecache.Pagecache                    # list recoverable files
  vol.py -f MAC -o out/ mac.pagecache.Pagecache --dump     # recover all content
  vol.py -f MAC -o out/ mac.pagecache.Pagecache --dump --name "A.plist,/Users/"  # OR-filter
  ```
- **Proven on the MAC image (10.12.6):** 387 files with genuinely recoverable
  pages; `SystemVersion.plist` byte-exact (`10.12.6/16G29`), `dyld` valid Mach-O
  universal (multi-page + sparse holes), `.GlobalPreferences.plist` valid bplist,
  AddressBook `window_2.data` 40 KB / 10 pages full.
- **Scope:** verified macOS 10.12.6 Intel. Requires the ISF to carry the VM/UBC
  types (this KDK ISF does). Other XNU versions may need field-name tweaks; the
  packed-pointer base is read at runtime, so KASLR/version slide is handled.

---

## 4. Integration into CresCentC's macOS file dumper

### modules/file_dumper.mac.py
- NEW `dump_mac_content(image, dump_dir, name_filter=None, timeout=None)` — runs
  `mac.pagecache.Pagecache --dump` (`-o dump_dir`, optional `--name`), returns the
  count of reconstructed files. Generous timeout (≥1 h) since a full recovery
  walks all vnodes then carves.
- `dump_file_list(...)` — was a "not supported" stub; now builds a comma-separated
  `--name` from the selected files' paths and recovers just those (warns if a
  file's pages are not resident).
- Docstring / "not supported" log line updated.

### crescent_toolkit.py
- **`_cmd_dump_all` (mac branch):** writes the inventory (`dump_mac`) **and**
  recovers content (`dump_mac_content`) — so DFIR/dump-all on macOS now carve bytes.
- **`_cmd_dump_files` (mac branch):** `--pattern X` = one-shot content recovery of
  matching files; otherwise opens NEW `_mac_filedump_menu` (search→recover matches,
  recover-all, list, change dir), mirroring the Linux interactive flow, with a note
  that only RAM-resident files recover.

### Verified end-to-end through the tool
```
$ crescent_toolkit.py dump-files -i MAC -o <out> --pattern "GlobalPreferences.plist"
[+] Using prior results: vol3 (mac)                 # SUMMARY reuse, no re-detection
[+] Listed 17407 file entries ... mac_file_list.json
[+] mac.pagecache: recovered 1 file(s) (16.4s)
-> Library_Preferences_.GlobalPreferences.plist.dmp : 2888B, "Apple binary property list"
```

---

## 4b. Dump coverage — process & file dumping byte-verified on all 3 OSes

Both dumpers were confirmed this session to produce **genuine recovered bytes**
(not merely "ran"), on Windows, Linux, and macOS:

| | Windows | Linux | macOS |
|---|---|---|---|
| **Process** | PE (`windows.pslist --dump` / Vol2 `procdump`) | ELF (`linux.elfs --dump`) | per-VMA (`mac.proc_maps --dump`) |
| **File** | filescan → `windows.dumpfiles` | page cache → `linux.pagecache` RecoverFs/InodePages | UBC → **`mac.pagecache`** (NEW) |

Verification evidence:
- **Process / Windows** — Windows2.raw → `executable.<pid>.exe` valid PE; Challenge
  CresCent-Eye → 48/53 dumped.
- **Process / Linux** — kalilinux.lime → `zsh` (8 ELF segments) + `avml`, `\x7fELF`
  magic checked. (First attempt picked PIDs 2–4 = kernel threads → 0 dumped, which
  is *correct* — kernel threads have no userspace ELF; re-ran on real PIDs.)
- **Process / macOS** — MAC → per-VMA `.dmp`; CresCent-Eye files-first run → 1,000+
  VMA dumps.
- **File / Windows** — Windows2.raw → 31/31 recovered `.dat` confirmed genuine EVTX
  (`ElfFile` magic); Challenge CresCent-Eye → 2,666/3,218 files.
- **File / macOS** — `mac.pagecache` → `dyld`, `launchd`, `.GlobalPreferences.plist`,
  byte-verified (non-zero + correct magic).
- **File / Linux** — Mint.lime via `dump-files` → RecoverFs → `recovered_fs.tar.xz`
  (56.9 MB; 26,721 files in tree). **1,703 non-empty with real content**: `/etc/passwd`
  + `/etc/group` correct; `firefox/libxul.so` (150 MB), `libLLVM-13.so` (60 MB), etc.
  reassembled as valid ELF / Mozilla archives.

**Shared page-cache limitation (Linux + macOS):** only RAM-resident content
recovers. On Mint, 1,703 of ~27k files in the RecoverFs tree had real bytes; the
rest came back **EMPTY** because their content pages were not cached at capture
(RecoverFs writes the full path tree but only fills resident pages). This is the
same `phys_page == 0` / placeholder story as `mac.pagecache` — page-cache
forensics, not a bug.

**RecoverFs robustness observation (Linux bulk file dump):**
`linux.pagecache.RecoverFs --compression-format gz` **TIMED OUT (720 s)** on the
2 GB Mint image, but `modules/file_dumper.linux.py::dump_linux`'s
**gz → xz → bz2 fallback** then succeeded with `xz`. Keep that fallback — bulk
RecoverFs is slow/fragile on a multi-GB image; the targeted per-file
`linux.pagecache.InodePages` path (`dump_linux_file_by_inode`) is the alternative.

## 5. Where things live
- Plugin: `~/Desktop/volatility3/volatility3/framework/plugins/mac/pagecache.py`
- macOS ISF used: `~/Desktop/volatility3/volatility3/symbols/mac/macOS_KDK_10.12.6_build-16G29.json.xz`
- PoC folder (Desktop): `~/Desktop/MacRAM_PoC/` (4 recovered files + README + decoded plist)
- Mode/test outputs: `~/Desktop/mode_test/` and `~/Desktop/extraction_test/`

## 6. Open / next
- Optional: generalize the plugin's vnode/UBC field access for other macOS versions
  (10.13+ pack pointers differently in places; the base is already runtime-read).
- Optional: add a `mac.pagecache` timeliner or size/only-fully-resident filters.
- DFIR on macOS is heavy: it dumps every process's VM (proc_maps), which dominates
  runtime. **Mitigated:** `--files-first` (added this session) recovers files up
  front so the page-cache content is captured before the long process phase. A
  further option to *skip* full process-memory dumps (EXE/Mach-O headers only)
  could help more.
