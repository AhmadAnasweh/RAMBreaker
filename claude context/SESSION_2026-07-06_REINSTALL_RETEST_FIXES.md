# Session — Vol Reinstall Retest + system_info Fix + HTML Report Check

**Date:** 2026-07-06
**Scope:** Delete Vol3/Vol2 and reinstall via the tool to validate the fresh-install
flow (esp. the bundled `mac.pagecache` plugin), retest **every module** across
Windows/Linux/macOS (excluding the "full dump" `dump-all`/CresCent Eye), then fix
`system_info` host/user extraction and verify the HTML report.

Related: `PACKAGING_AND_DEPS.md`, `MAC_PAGECACHE_PLUGIN.md`,
`SESSION_2026-07-05_MODES_AND_MAC_PAGECACHE.md`.

---

## 1. Reinstall test (delete Vol3+Vol2 → reinstall)

- Backed up `~/Desktop/volatility3/volatility3/symbols` (1.6 GB: mac KDK 10.12.6 +
  14 linux ISFs + windows pack) via `mv` (the ISFs aren't easily re-obtainable),
  then `rm -rf ~/Desktop/volatility3 ~/Desktop/volatility`.
- Reinstalled with `VolatilityInstaller.install_vol3()` / `install_vol2()`.
- **Bundled plugin auto-installed on the fresh clone** — the exact fix from the
  prior session worked in a real reinstall:
  ```
  Volatility 3 installed at /home/kali/Desktop/volatility3
  Installed bundled Vol3 plugin: .../framework/plugins/mac/pagecache.py
  ```
- Restored symbols; verified: tool finds Vol3+Vol2, **Vol3 discovers
  `mac.pagecache.Pagecache`**, symbol cache warm, deps (yara/pefile) present.

Conclusion: a delete+reinstall keeps macOS content recovery working — no manual
step needed. (ISFs are re-download/re-build on demand; here restored from backup.)

## 2. Module-coverage retest (every module, not the full-dump)

Ran `full` on a **Windows** image, `plugins` (Only Vol Plugins) on **Mac** and
**Linux**, plus targeted `dump-files`/`dump-procs`/`hunt` and the standalone tools.
**Every module produced correct output on all three OSes.**

| Module | Windows | Mac | Linux |
|---|---|---|---|
| OS detect + extractor | ✅ | ✅ (banners) | ✅ (LiME) |
| system_info | ✅* | ✅* | ✅* |
| strings / ioc / browser / comms | ✅ (8257 URLs, 57 comms) | (n/a in plugins) | (n/a) |
| process_tree | ✅ 53 | ✅ 168 | ✅ 303 |
| network_map | ✅ 97/23 | ✅ 73 | ✅ 16566/12 |
| process_dumper (detect) | ✅ 2 flag | ✅ | ✅ 2 flag |
| cmd_analyzer + mitre | ✅ 3 tech | ✅ | ✅ 1 tech |
| correlator | ✅ | ✅ | ✅ |
| popular_files | ✅ 2307 | ✅ 12062 | ✅ 110 |
| scheduled_tasks | ✅ 100 | ✅ 5 | ✅ 2 |
| registry_explorer / registry_altered | ✅ 12 hives / 50 shim | — | — |
| timeline | ✅ 296 | ✅ 169 | ✅ 303 |
| html_report | ✅ 6.4 MB | ✅ 4.4 MB | ✅ 8.4 MB |
| evtx_parser | ✅ 2864 ev | — | — |
| file_dumper (content) | ✅ dumpfiles 136 | ✅ **mac.pagecache** 2 | ✅ **RecoverFs** 5013→74.9 MB |
| process_dumper (dump) | ✅ 3 PE | (proc_maps) | (elfs) |
| string_hunt | ✅ 107 hits | | |
| export_pack / elk_export | ✅ / ✅ 63k docs | | |

\* system_info was the one weak spot found (host/users "Unknown") — fixed below.

## 3. Fix — `system_info` host/user extraction  (`modules/system_info.py`)

**Root cause:** the primary host/user sources (`windows.envars`, `windows.getsids`,
`linux.envars`) are **only in `full`-mode plugin sets, not `fast`/`plugins`**, and
the strings-based hostname fallback runs before strings exist (and is skipped in
plugins mode). So in fast/plugins runs, host/users came back "Unknown".

**Fix (works in ANY mode — uses always-present plugins):**
- `_from_file_paths()` — usernames from home-dir paths in the file listings that
  every mode produces: `\Users\<name>\` (Windows filescan), `/home/<name>/` (Linux
  pagecache/lsof), `/Users/<name>/` (macOS list_files).
- `_from_hashdump()` — Windows users from hashdump, now **RID-validated** (a valid
  row has a numeric RID); this drops the Vol2 `*** Failed to import ...` distorm3
  banner lines that the text parser otherwise leaked in as fake usernames.
- `_from_registry_hostname()` — Windows hostname from a registry `ComputerName`
  value in the printkey/registry JSON.
- All wired into `SystemInfo.load()`, so every future run benefits.

**Verified (also flows into the regenerated HTML reports):**
- Windows: host=`VIRUS-PC`, users=`Administrator, Jaffa, g4rud4`, os=`Windows NT 15.7601`, ip=`10.0.2.15`.
- macOS: users=`admin`, os=`Darwin 16.7.0`, ip=`192.168.140.128`.
- Linux: users=`linuxmint`, os=`Linux 5.15.0-41-generic`, ip=`192.168.47.138`.

**Known limitation (honest):** Linux/macOS **hostname** stays blank in
`fast`/`plugins` mode — there is no Vol3 fast-mode source for it (macOS has no
`envars` plugin at all). `full` mode's `envars` provides it. Users/OS/IP are fixed
in every mode.

## 4. HTML report — checked, no bugs

- **Well-formed:** Python `html.parser` parses all three reports without
  exceptions; real DOM tags balanced; exactly **one** `</script>` — proof captured
  strings are properly escaped (no data string breaks out of the script block).
- **Flagged strings are benign:** `undefined` is real captured data (a Google
  browser-history URL literally contains `&em=undefined`) plus normal defensive JS
  (`if(v===undefined)v=''`); `NaN` is JS numeric-sort logic (`!isNaN(nx)`); the
  `<div>` "imbalance" is `'<div>'` *strings* inside JS template literals, not real
  tags (real DOM divs balance 4/4 outside `<script>`).
- The log's `[iocs] excluded encoding IOC category` is **intentional** (omits
  `base64_long`/`hex_blob` blobs from the HTML to avoid bloat), not an error.
- Data embeds as JS structures (`const PAGES/sections/procs/netRows …`); the fixed
  system_info renders (`VIRUS-PC`/`admin`/`linuxmint`).
- (Note: `node` isn't installed, so the JS wasn't executed/linted; the template is
  identical across all reports and has opened cleanly in prior sessions.)

## 5. Files touched
- `modules/system_info.py` — `_from_file_paths`, `_from_hashdump` (RID-validated),
  `_from_registry_hostname`; wired into `load()`.
- (No HTML-report code change — it was verified correct.)
