# Session Handoff — Auto-ISF Build, Dump-All Mode, RHEL Resolver, Bug Fixes

**Date:** 2026-07-04 → 2026-07-05
**Scope:** Wire automatic ISF building into the Linux resolve flow, guarantee the
ISF-build toolchain, add a "dump everything" mode, redirect scratch off the tiny
`/tmp`, add a RHEL/CentOS debuginfo resolver, then run every RAM dump in
`/home/kali/Desktop/RAMDUMPS` and fix every issue found.

---

## 1. Executive summary

Starting point: the tool could DOWNLOAD prebuilt ISFs from the community CDN
(Abyss-W4tcher), but the code that DOWNLOADS a kernel's official debug package and
BUILDS an ISF (`modules/dbgsym_builder.py`) existed but was **orphaned** — never
called. This session wired it in, extended it to RHEL/CentOS, added a dump-all
mode, moved all scratch to the Desktop, and fixed ~10 real bugs surfaced by
running the full image set.

**Net result:** For a normal Ubuntu/Debian/Kali/CentOS image, you now run the tool
and it auto-detects the kernel → obtains/builds the matching ISF → installs →
verifies → runs the full analysis, hands-off. Proven end-to-end.

---

## 2. Features ADDED (the four original requests + RHEL)

### Req 1 — Auto-download official debug package + build ISF (WIRED IN)
- `modules/linux_resolver.linux.py`:
  - `_distro_from_banner(banner)` → `Ubuntu` / `Debian` / `Kali` / `RHEL` / `SUSE`.
  - `_try_dbgsym_download_build(image, kernel_ver, banner, arch, vol3, os_type)`
    — new resolver fallback. Routes **Debian-family → ddebs/Launchpad**
    (`dbgsym_builder.build_isf_from_dbgsym`), **RHEL → debuginfo RPM**
    (`build_isf_from_rhel_debuginfo`), **SUSE → skip (reduced results)**.
  - Wired into `resolve_symbols()` AFTER the prebuilt-ISF loop and the local-DWARF
    build, BEFORE the "manual steps" message. Tries the top 3 ranked banner
    candidates.
- Resolution order now: already-works → prebuilt CDN ISF → local DWARF build →
  **official debug-package build (NEW)** → reduced results (flagged).

### Req 2 — Guarantee ISF-build toolchain in the installer
- `modules/installer.py`:
  - `_find_dwarf2json()` — PATH, else the bundled `_isf_build/dwarf2json`.
  - `ensure_isf_build_tools(use_sudo=True)` — installs dwarf2json to
    `/usr/local/bin` (or `~/.local/bin`), and apt-installs `dpkg`(dpkg-deb),
    `binutils`(ar), `xz-utils`, `curl`, `rpm`(rpm2cpio), `cpio`.
  - Wired into `install_all()`; reported in `full_status()` + `print_status()`.

### Req 3 — Dump-everything mode
- New CLI command **`dump-all`** + interactive menu **[6]**.
- `crescent_toolkit.py::_cmd_dump_all(args)` — runs a full extraction first if no
  process data exists, then dumps EVERY process as its native executable and
  EVERY recoverable file.
- `dump_all_processes(image, dump_dir)` added to all three
  `modules/process_dumper.{windows,linux,mac}.py` — PE (Win) / ELF (Linux) /
  Mach-O (mac). Output → `<out>/dumped_all/processes/process_exe/` and
  `<out>/dumped_all/files/`.
- **Proven:** ubuntu image → 182 valid ELF process images dumped.

### Req 5 — Move scratch off /tmp (5 GB tmpfs) to the Desktop
- NEW `modules/workspace.py`: creates `~/Desktop/CresCentC_work/{scratch,cache,
  ddeb_cache,isf_build,images}` and `~/Desktop/CresCentC_RESULTS`, and points
  `TMPDIR` + `tempfile.tempdir` at the scratch dir so EVERY `tempfile.mkdtemp()`
  across all modules lands on the big disk. Override with env `CRESCENT_WORK` /
  `CRESCENT_RESULTS`.
- `crescent_toolkit.py::main()` calls `workspace.setup()` first thing.
- Installer's hardcoded `/tmp/get-pip.py` → `tempfile.gettempdir()`.

### NEW — RHEL / CentOS / Alma / Rocky / Fedora debuginfo resolver
RHEL-family kernels ship debug symbols as `kernel-debuginfo` **RPMs** (unstripped
vmlinux), not `.ddebs`. Added the RPM analogue of the ddeb builder:
- `modules/dbgsym_builder.py`:
  - `rhel_rpm_arch()`, `_rhel_release()` (parses `.elN`/`.fcN`),
    `rhel_debuginfo_urls(kernel_ver, arch, distro)` — candidate mirrors:
    **debuginfo.centos.org (validated 200), download.rockylinux.org (200)**,
    AlmaLinux (best-effort), Fedora koji.
  - `extract_vmlinux_from_rpm(rpm, workdir)` — `rpm2cpio | cpio`, find vmlinux.
  - `build_isf_from_rhel_debuginfo(kernel_ver, arch, install, distro, keep_rpm,
    dest_dir)` — full pipeline, reuses `build_isf()` + `install_isf()`.
- Wired into `_try_dbgsym_download_build` (RHEL branch).
- **Proven end-to-end** on `dump.mem` (CentOS 3.10.0-1062.el7): RPM (458 MB) →
  vmlinux → dwarf2json → ISF → install → **220 processes** recovered.

### NEW — "Bring Your Own ISF" picker (operator-supplied symbol table)
For operators who already have/built their own ISF. Mirrors the RAM-dump picker:
shows an example filename, lists every ISF already installed in the store as
numbered options, and lets them pick one or point at their own file.
- `modules/linux_identify.py`:
  - `list_installed_isfs(os_type=None)` — enumerates `.json`/`.json.xz` under
    `<vol3>/volatility3/symbols/{linux,mac}/`.
  - `install_local_isf(local_path, os_type)` — **validates** the file parses AND
    looks like a Vol3 ISF (`symbols`+`metadata`) before copying it into the store
    and registering it via the incremental cache update (~1 s). Rejects wrong
    ext / non-ISF json with a clear message.
- `crescent_toolkit.py`:
  - `_prompt_local_isf(args)` — the picker UI (example + installed list + `[P]`
    provide path + `[A]` auto).
  - Wired into `_prompt_os`: Linux/mac prompt is now `Enter=auto · 'i'=use your
    OWN/installed ISF · 'y'=browse repo catalogue · or type a build`.
  - `_resolve_linux_symbols` branches on `Path(chosen).is_file()`: local file →
    `install_local_isf` (copy); repo-relative catalogue path → the existing
    `install_symbol_by_path` (download).
  - NEW CLI flag `--symbol-isf PATH` for non-interactive use.
- Note: this is distinct from the pre-existing `_prompt_symbol_table` catalogue
  picker, which browses the community repo of ~10k build names to DOWNLOAD.

---

## 3. Bugs FOUND and FIXED

1. **Relative `vol.py` path broke Linux file recovery.** `vol3_cmd` was
   `python3 ../volatility3/vol.py`; `linux.pagecache.RecoverFs` runs with
   `cwd=dump_dir`, so the relative path resolved wrong → "can't open vol.py".
   Fix: `modules/volatility.py::_find_vol3/_find_vol2` resolve the vol.py path to
   ABSOLUTE.

2. **`driverscan` utf-8 decode crash.** Vol2 plugins can emit non-UTF-8 bytes;
   `subprocess.run(text=True)` decoded strict-utf8 and raised, losing all output.
   Fix: `errors="replace"` in `_run_vol2` AND `_run_vol3`. (Windows2 driverscan:
   crash → 118 driver rows.)

3. **`rc=1` at end of `full` runs.** After analysis, `_cmd_default` re-inits Vol
   (`_init_vol_from_existing`); under load the `vol.py -h` probe exceeded its 15 s
   timeout → "No Volatility installation found!" → `sys.exit(1)`. Fix:
   `_test_vol3/_test_vol2` timeout 15 s → **60 s** + `errors="replace"`.

4. **`JSONDecodeError` noise.** Failed plugins left 0-byte/error-text `.json`
   files that direct `json.load()` callers choked on. Fix: `_run_vol3` now writes
   `[]` when output isn't valid JSON. One-time cleanup normalized **57** stale
   invalid json files across `CresCentC_RESULTS`.

5. **`timeline` command hung non-interactively.** `_cmd_timeline` is an
   interactive menu; run via a script (no TTY) it looped forever on EOF →
   "timeout". Fix: non-interactive guard (`-q` or not a TTY) → build + save via
   `Timeline.write_report()` and return. (linux.vmem timeline: 600 s hang → 3 s,
   344 events.) NOTE: `_cmd_iocs`/`_cmd_correlate` have the same interactive
   pattern; `full`/`core` build those non-interactively so it only bit the
   standalone commands — guard them too if used standalone.

6. **`dump-all` loaded 0 processes.** It gated on `json/` dir existing, but the
   symbol resolver writes `linux_kernel.json` there without running plugins. Fix:
   check for actual process data (pslist/psscan/pstree globs).

7. **Verify false-negative after a fresh ISF build (the big one).** Two layers:
   - (a) Vol3's `identifier.cache` is built BEFORE the new ISF is installed and is
     never re-indexed → automagic reports "Unsatisfied" for a correct ISF. Fix:
     `linux_identify.clear_isf_cache()` + `warm_isf_cache(..., force=True)` called
     via `_refresh_isf_cache_after_install(vol3, image)` at every ISF install
     point (RHEL, ddeb, local build).
   - (b) The re-warm itself was killed: `warm_isf_cache` ran `banners.Banners`
     with `-q`, silencing the progress stream, so `run_vol_until_done` aborted it
     at 180 s "stall" while silently indexing the **3,026-ISF** store. Fix: drop
     `-q` (progress feeds the stall-detector) + `stall_grace=600`.
   - Proven: auto-built CentOS ISF → 0 procs (before) → **220 procs** (after).

11. **Cache re-warm was catastrophically slow (double full-index) — FIXED (#1+#3).**
    The bug-#7 fix above was *correct* but used a sledgehammer: `clear_isf_cache()`
    empties the SQLite cache, which makes ALL ~3,026 store files "new", so the
    forced re-warm re-parses every one (~11–35 min). And the flow warmed the
    cache TWICE (once at resolve start, once after install) → a CentOS build run
    took **1h 39m**, almost all cache-warming.
    - Key discovery: Vol3's `SqliteCache.update()` (in
      `volatility3/framework/automagic/symbol_cache.py`) is **incremental** — it
      diffs on-disk locations vs cached, so `files_to_process = new ∪ modified`.
      Adding ONE ISF and calling `update()` processes only that one file (**1.0 s
      measured**, vs 35 min for a clear+rebuild).
    - Fix #1: NEW `linux_identify.add_new_isf_to_cache(vol3_dir)` runs Vol3's own
      `SqliteCache.update()` via a `python3 -c` subprocess (needs only the Vol3
      package — no external tools). `_refresh_isf_cache_after_install` now uses
      this fast path; clear+rewarm remains ONLY as a fallback if it fails.
    - Fix #3: with the post-install step now ~1 s, the expensive SECOND full warm
      is gone. The initial warm still runs once (cold cache) but is reused
      (`isf_cache_is_warm()` short-circuits) on later runs.
    - **Proven end-to-end on dump.mem: 1h 39m → 15m 49s (~6.3×), rc=0,
      identical output (pslist 220, 21/26 plugins).** The ~15 min is now real
      analysis, not cache overhead.

8. **RHEL misdetected as Ubuntu.** Old code said "fetching Ubuntu debug package
   for 3.10.0-1062.el7" and wasted HEAD requests. Fix: `_distro_from_banner`
   detects `.elN/.fcN/red hat/centos/almalinux/rocky` → RHEL; SUSE → SUSE.

9. **Installer lacked ISF-build deps.** `install_all` claimed "Go, dwarf2json" but
   had no code. Added (Req 2). Also added `rpm2cpio`/`cpio` for the RHEL path.

10. **Local DWARF build required dwarf2json on PATH.** `_try_local_isf_build` used
    `shutil.which("dwarf2json")`; now uses `dbgsym_builder.find_dwarf2json()`
    (bundled fallback) and the resolved binary in the command.

---

## 4. Files touched

- **NEW** `modules/workspace.py`
- `modules/installer.py` — ISF-build deps, get-pip tmp fix
- `modules/linux_resolver.linux.py` — distro detect, dbgsym+RHEL build fallback,
  cache-refresh-after-install, local-build dwarf2json fix
- `modules/dbgsym_builder.py` — RHEL/CentOS resolver (`import re` + 6 funcs)
- `modules/linux_identify.py` — `clear_isf_cache()`, `warm_isf_cache(force=…)`,
  drop `-q` + 600 s stall grace, **`add_new_isf_to_cache()` (incremental update)**,
  **`list_installed_isfs()` + `install_local_isf()` (bring-your-own ISF)**
- `modules/volatility.py` — absolute vol paths, `errors="replace"`, valid-`[]`
  json write, probe timeout 60 s
- `modules/file_dumper.linux.py` — RecoverFs graceful degrade → file inventory
- `modules/process_dumper.{windows,linux,mac}.py` — `dump_all_processes()`
- `crescent_toolkit.py` — `workspace.setup()`, `dump-all` cmd/handler/menu,
  dump-all proc-data gate, timeline non-interactive guard, **`_prompt_local_isf()`
  bring-your-own-ISF picker + `_prompt_os` 'i' option + `_resolve_linux_symbols`
  local-vs-repo branch + `--symbol-isf` flag**

---

## 5. Test campaign — all RAMDUMPS (results in `~/Desktop/CresCentC_RESULTS/<img>/`)

| Image | OS / kernel | Result |
|---|---|---|
| MAC | macOS Darwin16 | ✅ 27 plugins, 0 failures |
| Challenge.raw | Win7 x64 (Vol3) | ✅ 56 plugins, rich |
| Windows2.raw | Win7 x64 (Vol3) | ✅ 58 plugins (driverscan fixed) |
| kalilinux.lime | Kali 6.12.13-amd64 | ✅ prebuilt **Debian** ISF + **banner-patch** (NOT a build) |
| ubuntu.20211208.mem | Ubuntu 5.4.0-1059-azure | ✅ prebuilt ISF; full pipeline (was only dump-all → re-ran `full`) |
| dump.mem | CentOS 3.10.0-1062.el7 | ✅ **built ISF from debuginfo RPM** → 220 procs |
| linux.vmem | Linux VMware (4 GB) | ✅ extraction + reports (timeline fixed) |
| victoria-v8.memdump.img | Debian 2.6.26 (2011) | ⚠️ **no DWARF published anywhere** — reduced results (correct) |
| Windows.raw | Win7-era, odd image | ⚠️ Vol3 can't symbolize, no valid KDBG — only scan plugins (mftscan 25300) |

**Environmentally limited (NOT tool bugs):** victoria-v8 (no `-dbg` package on
snapshot.debian.org, 2.6 kernel = Vol2-legacy), Windows.raw (kdbgscan finds no
KDBG; imageinfo >300 s no profile).

**IMPORTANT nuance — Kali needs NO build:** Kali kernels are Debian-sourced, so
the resolver uses the matching prebuilt **Debian** ISF and banner-patches it to
Kali. Only `dump.mem` (CentOS) exercises a real from-scratch dwarf2json build
among these images (mint's dbgsym is pruned upstream).

---

## 6. Where ISFs live

1. **Installed store (what Vol3 reads):**
   `/home/kali/Desktop/volatility3/volatility3/symbols/{linux,windows,mac}/`
   (linux/ had 16 ISFs; the ~3,026 count that makes cache-warm slow is ALL symbol
   files across every OS dir — Windows PDB pack dominates).
2. **Build workspace (built ISFs pre-install):**
   `/home/kali/Desktop/CresCentC_work/isf_build/`
3. **Downloaded debug-package cache (reused across builds):**
   `/home/kali/Desktop/CresCentC_work/ddeb_cache/`
   (kernel-debuginfo-…el7.rpm 458 MB, …dbgsym…ddeb 1.0 GB + 530 MB)

ISFs built/installed THIS session (Jul 4–5): `LinuxMint21_5.15.0-41…`,
`Ubuntu_5.15.0-179…` (fresh ddebs build), `Ubuntu_5.4.0-1059-azure…~18.04.1`
(prebuilt), `Debian_6.12.13-amd64…` + `…_patched` (Kali), `CentOS_3.10.0-1062.el7…`.

---

## 7. Proven capability highlights

- **Fresh official-page build:** `ddebs.ubuntu.com` → `linux-image-…5.15.0-179…
  dbgsym…ddeb` (1028 MB) → vmlinux (720 MB) → dwarf2json → install. 419 s.
- **RHEL build (fully autonomous, tool-driven):** run `full` on dump.mem with NO
  CentOS ISF present → tool detects el7 → downloads debuginfo.centos.org RPM
  (458 MB) → dwarf2json → install → incremental cache register (~1 s) → verify
  passed → 18-plugin analysis + full report suite. **15m 49s** end-to-end
  (pslist 220, 21/26 plugins). (Same run before the #1/#3 cache fix: 1h 39m.)
- **dump-all:** 182 ELF process images from the ubuntu LiME dump.
- All ISF-build tools are bundled (`dwarf2json` in `_isf_build/`) or apt-installed
  by `installer.ensure_isf_build_tools` (`rpm2cpio`,`cpio`,`dpkg`,`binutils`,
  `xz-utils`,`curl`); incremental cache update uses only the Vol3 Python package.

---

## 8. Known limitations / gotchas for next session

- **Post-install cache cost is now ~1 s** (was ~11–35 min) via the incremental
  `SqliteCache.update()` — see bug/fix #11. The ONE remaining full-index cost is
  the FIRST-ever warm on a cold cache (has to index all ~3,026 files once); it's
  cached and reused after. Trimming the store (mostly the Windows PDB pack) is
  the only lever left for that first warm, and is environmental (user's call).
- **Pruned upstream kernels** (old Ubuntu/mint) can't be built — Canonical deletes
  the dbgsym; rely on the prebuilt CDN or accept reduced results.
- **AlmaLinux debuginfo path** is version-specific and best-effort; CentOS + Rocky
  mirrors are validated. `download_resume` walks the URL list until one 200s.
- **`_cmd_iocs` / `_cmd_correlate`** still have the interactive-menu pattern — add
  the same non-interactive guard as `_cmd_timeline` if invoking them standalone in
  a batch (the `full`/`core` pipelines build those outputs fine).
- **RHEL/RHEL-proper** needs a subscription; the resolver substitutes the matching
  CentOS/Rocky RPM (same source build → same DWARF).
