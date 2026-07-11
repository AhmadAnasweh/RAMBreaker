# Session — macOS list_files RecursionError, netstat 'path' bug, mac netstat field-mapping, + Flock comms app

**Date:** 2026-07-06 (later same day as `SESSION_2026-07-06_REINSTALL_RETEST_FIXES.md`)
**Trigger:** user asked why the `chall(1).raw` run "failed regarding the files".
Image: `/home/kali/Downloads/chall(1).raw` — macOS **Darwin 15.6.0** (OS X 10.11.6
El Capitan, xnu-3248), output at `/home/kali/Desktop/chall(1)_raw`.

One question ("why did files fail?") cascaded into a chain of related macOS bugs,
all fixed, plus a new comms app (Flock) added. Everything below is verified on
`chall(1).raw`.

Related: `mac-list-files-recursion-fix` memory; `MAC_PAGECACHE_PLUGIN.md`;
`ARCHITECTURE_V6.md` (gotchas). Companion earlier-today doc:
`SESSION_2026-07-06_REINSTALL_RETEST_FIXES.md`.

---

## 1. Bug — `mac.list_files.List_Files` RecursionError (the "files" failure)

**Symptom:** `mac.list_files.List_Files: RecursionError: maximum recursion depth
exceeded` → `json/mac_list_files_List_Files.json` = 2 bytes (`[]`). Cascaded to
**Popular Files = 0 entries**, Scheduled-tasks files = 0, and would also break
`mac.pagecache` / mac `dump-files` (they reuse `list_files.List_Files.list_files`).

**Root cause:** in `<vol3>/volatility3/framework/plugins/mac/list_files.py`,
`_walk_vnode` recursed once per parent-chain level (self-call at the old line 124),
one Python stack frame per level. On this image the vnode graph is 974+ deep →
over Python's default 1000 limit. `loop_vnodes` only prevents *revisiting* a vnode,
it does not bound recursion *depth*.

**Fix:** rewrote `_walk_vnode` as an **iterative work-list** (`pending` stack, no
self-recursion). Dedup still via `_add_vnode`'s offset key, so the collected vnode
set is identical. Result: **87,458 files** listed (was crash), Popular Files
**83,006 entries**.

**Durability:** `list_files.py` is a stock Vol3 *plugin*, so it's bundled the same
way as `mac.pagecache`: copied to **`vol_plugins/mac/list_files.py`** →
`installer.install_bundled_plugins()` (rglob copies every `vol_plugins/**/*.py`)
re-applies it over stock Vol3 on any reinstall.

## 2. Bug — `mac.netstat.Netstat` UnboundLocalError 'path'

**Symptom:** `mac.netstat.Netstat: UnboundLocalError: cannot access local variable
'path'` → network map = 0 connections.

**Root cause:** NOT the plugin — the shared helper
`<vol3>/volatility3/framework/symbols/mac/__init__.py`
`MacUtilities.files_descriptors_for_process`. It did:
```
if ftype == "VNODE": ... path = vnode.full_path()
elif ftype:         path = f"<{ftype.lower()}>"
yield f, path, fd_num       # <-- path unbound when ftype is falsy/unknown
```
A file descriptor with an empty/unknown glob type left `path` unset.

**Fix:** initialise `path = None` before the branches, and guard the VNODE
`full_path()` deref against `InvalidAddressException`. Result: **77 socket rows**.

**Durability (different mechanism — it's a *framework* file, not a plugin):** added
an idempotent post-clone patcher **`installer.apply_framework_fixes()`** driven by
`_FRAMEWORK_FIXES = [(relpath, buggy_snippet, fixed_snippet), …]`. It rewrites the
buggy block only if the exact buggy text is present → **no-op if upstream already
fixed it or it's already patched** (safe because the installer clones Vol3 *master*,
not a pinned tag, so blind whole-file overwrite would risk clobbering upstream).
Wired into `install_vol3()` at both the fresh-clone and already-exists paths.
Tested: applies once on a buggy copy, no-op on re-run, safe-skip on unknown upstream.

## 3. Bug class — mac netstat field-name mapping (many modules)

Once netstat produced rows, the data still didn't surface correctly. **macOS Vol3
JSON uses different field names than Windows/Linux** and this broke several
consumers that only knew the Windows/Linux aliases:

- **mac netstat fields:** `Local IP`, `Local Port`, `Remote IP`, `Remote Port`,
  `Proto`, `State`, `Process` (= `"Name/pid"`), `Offset`. **There is NO `PID`
  column** — the PID is embedded in `Process`.
- **mac pslist fields:** `PID`, `PPID`, `NAME` (**uppercase**), `UID`, `GID`,
  `Start Time`, `OFFSET`.

`utils.json_converter._gv` (and the report's JS `gv`) are **exact-match** alias
lookups, so a missing alias silently yields "".

Fixes (added `Local IP`/`Remote IP`/`Remote Port` aliases, and where relevant PID
from `Process` and mac pslist `NAME`):

| Module | What was wrong | Fix |
|---|---|---|
| `network_map.py` | blank IPs, 0 external | added `Local IP`/`Remote IP`/`Remote Port` aliases |
| `correlator.mac.py` | 0 external conns, blank names | aliases + PID-from-`Process` (added `import re`) + `NAME` in name alias |
| `html_report.mac.py` | Processes tab blank conn IPs / not attached | aliases + PID-from-`Process` fallback in the embedded netRow JS |
| `timeline.py` | blank foreign addr for mac (also gated by missing ts) | aliases |
| `comms_scanner.py` | mac process/net not matched | `NAME` (pslist) + `Process` (netstat) reads; see §4 |
| `cmd_analyzer.mac.py` | mac remote IP blank | `Remote IP` alias |
| `elk_export.py` | mac remote/local blank on export | aliases |

**Verified end-state on chall(1).raw:** network_map **77 conns / 3 external**;
correlation **network_processes=15, external_connections=3**, all attributed to
**Flock Helper (PID 486)** → `34.199.4.67` / `34.107.204.85` / `54.84.224.164` :443
(ESTABLISHED), with process names populated. system_info **users=[admin]**,
**ip=[192.168.25.114]**, os `Darwin 15.6.0` (was 0 users / 0 IPs before the
list_files fix, because mac system_info pulls users from `/Users/<name>/` in the
now-populated list_files).

**Note — the general lesson:** whenever touching a macOS code path, audit every
`_gv`/alias list. mac Vol3 uses `NAME`, `Local IP`, `Remote IP`, and has no `PID`
column in netstat.

## 4. Feature — Flock (Flock Team Messaging) added to the comms scanner

`modules/comms_scanner.py` now recognises **Flock** as an 8th chat app (was
Teams/Discord/Zoom/Slack/Telegram/WhatsApp/Skype/Webex/Signal/Meet/VooV).

- **Patterns** (`p["flock"]`, anchored to `flock.com`/`flock://` per the v4.1
  anti-false-positive rule): `flock_url`, `flock_api_token` (token in a flock.com
  URL → marked CRITICAL), `flock_deeplink` (`flock://…`), `flock_cdn`
  (`flockcdn.com`).
- **Process/network correlation** (`exe_map`): `flock` / `flock helper` →
  `flock`. To make this work on macOS, `enrich_from_processes` now reads mac
  pslist `NAME` and mac netstat `Process` (the §3 field lesson).
- **Display name:** new `CommsScanner._DISPLAY_NAMES` / `_display()` renders the
  app as **"Flock Team Messaging"** (others still default to `APP.upper()`).
  Added `"flock"` to `app_display_order`.
- **Verified on chall(1).raw:** running_processes → PID **481 (flock)**, **486
  (flock helper)**; network_connections → the 3 external TCP 443 connections;
  strings hold **872 flock.com URLs** (`admin.flock.com`, `apps.flock.com`,
  `flock.com/release-notes/mac`, …). The comms text report shows a **"Flock Team
  Messaging"** section.
- **HTML note:** the report has no rich per-app comms tab — comms JSON is shown
  raw under the **Other** tab (so Flock appears as a `flock` key there); the
  "Flock Team Messaging" label is in `comms_report.txt` and the per-category files.

## 5. Output audit (report + JSON) — clean

- All JSON valid; HTML well-formed (1 `<script>`/`<style>`, balanced, `html.parser`
  OK, doctype present); `collection_errors: []`.
- Report headline counts consistent (processes 215*, network 77/3-ext, files
  83,006, timeline 215, plugins 27).
- *`processes: 215`* counts kernel_task PID 0; process_tree/correlation report 214
  (kernel_task excluded) — a benign off-by-one, not a bug.
- **Not bugs (documented):** `hostname` blank in fast/plugins mode (macOS has no
  `envars` source; `full` provides it); `malfind: 23,509` regions is raw noisy
  `mac.malfind` output (design = raw evidence, no verdicts; capped in HTML payload).

## 6. Files touched (all in `CresCentC_v6/`)
- **Vol3 (dependency, not the tool):** `.../mac/list_files.py` (iterative walk),
  `.../symbols/mac/__init__.py` (path bind).
- **Bundled/durable copies in the tool:** `vol_plugins/mac/list_files.py` (new);
  `modules/installer.py` (`apply_framework_fixes()` + `_FRAMEWORK_FIXES`, wired
  into `install_vol3()`).
- **Tool modules:** `network_map.py`, `correlator.mac.py`, `html_report.mac.py`,
  `timeline.py`, `comms_scanner.py` (mac fields + **Flock**), `cmd_analyzer.mac.py`,
  `elk_export.py`.
