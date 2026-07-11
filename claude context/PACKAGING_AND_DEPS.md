# Packaging, Dependencies & Reinstall — what's the tool vs what's a dep

**Date:** 2026-07-06

Answers "what are these directories, and are they part of the tool or dependencies?"
and documents how a delete-Vol + reinstall + retest works cleanly.

---

## Directory inventory (in the tool folder `CresCentC_v6/`)

### Part of the TOOL (its own code/data — ships in the zip)
| Item | What it is |
|---|---|
| `crescent_toolkit.py` | Entry point (CLI + interactive menu). |
| `modules/` | All analysis modules (extractor, volatility wrapper, dumpers, resolver, dbgsym_builder, installer, …). |
| `utils/` | Tool code: `ui.py` (banner/colors/prompts), `json_converter.py` (Vol2 text→JSON + `load_json_by_pattern`), `__init__.py`. **Not a dependency — it's the tool.** |
| `data/linux_symbol_catalogue.json.xz` | Bundled offline catalogue of Linux ISF build names (`linux_identify.BUNDLED_CATALOGUE`). |
| `vol_plugins/mac/pagecache.py` | CresCentC's own Vol3 plugin (macOS page-cache file recovery), bundled so it survives a Vol3 reinstall. See §"Bundled Vol3 plugin". |
| `vol_plugins/mac/list_files.py` | **NEW (2026-07-06)** — patched (iterative) stock Vol3 `mac.list_files`; the upstream one hits `RecursionError` on large images. Bundled so `installer.install_bundled_plugins()` re-applies it over the stock clone. |
| `_isf_build/dwarf2json` (2.9 MB) | **Bundled dependency binary** — the ISF builder. Referenced by `dbgsym_builder.py` / `installer.py`; the installer copies it to PATH. **Keep it.** |

### Dependencies (external — the installer installs/reinstalls)
- **Volatility 3** (`~/Desktop/volatility3`) and **Volatility 2** (`~/Desktop/volatility`) — cloned fresh from GitHub by `installer.install_vol3()` / `install_vol2()`.
- **dwarf2json** → copied from `_isf_build/` to `/usr/local/bin` by `ensure_isf_build_tools()`.
- **apt packages**: `dpkg-deb`(dpkg)/`ar`(binutils), `xz-utils`, `curl`, `rpm2cpio`(rpm), `cpio` — apt-installed by `ensure_isf_build_tools()`.
- **pip packages**: Vol3 (`yara-python`, `pefile`, `capstone`, `python-evtx`), Vol2 (`pycryptodome`, `distorm3`).

### NOT part of the tool AND NOT a dependency (safe to ignore/remove)
- **`LiME/`** — the LiME kernel-module **source** (a separate tool for *capturing* Linux RAM into `.lime` files). CresCentC only *reads* `.lime` images (via magic bytes); no code touches the `LiME/` directory. Independent acquisition tool. Excluded from the tool zip.
- **`_isf_build/{kdbg.deb, x/, mint/, kali_v9.json, build.err, ubuntu_dl.log}`** — **~16 GB of stale build scratch** from old ISF builds. New builds now go to `~/Desktop/CresCentC_work/`. Reclaimable — keep only `dwarf2json`. Excluded from the tool zip.
- `__pycache__/`, `.claude/` — Python bytecode / editor state. Excluded from the zip.

---

## Bundled Vol3 plugin — how `mac.pagecache` survives a reinstall

**Problem:** the `mac.pagecache` plugin lives *inside* the Vol3 install
(`<vol3>/volatility3/framework/plugins/mac/pagecache.py`), NOT in the CresCentC
repo. `installer.install_vol3()` clones **stock** Vol3 from GitHub, which does not
have it — so deleting Vol3 and reinstalling would silently break macOS
file-content recovery.

**Fix (this session):**
- The plugin is bundled in the repo at **`vol_plugins/mac/pagecache.py`**. The
  `vol_plugins/` layout mirrors `volatility3/framework/plugins/` (so
  `vol_plugins/<sub>/x.py` → `<vol3>/volatility3/framework/plugins/<sub>/x.py`).
- `installer.install_bundled_plugins(vol3_root=None)` copies every
  `vol_plugins/**/*.py` into the Vol3 framework. Idempotent.
- It's called automatically inside `install_vol3()` — both on a fresh clone AND
  when Vol3 already exists — so **any install/reinstall re-adds the plugin**.
- Status: `full_status()["mac_pagecache_plugin"]` + the installer menu's status
  screen show `mac.pagecache: OK (installed in Vol3)` vs `NOT in Vol3`.

**Verified:** removed the plugin from Vol3, ran `install_bundled_plugins()` → it
copied the bundled file back byte-identical, Vol3 re-discovered
`mac.pagecache.Pagecache`.

---

## Delete-Vol + reinstall + retest procedure (clean)

1. `rm -rf ~/Desktop/volatility3 ~/Desktop/volatility` (removes Vol3+Vol2, their
   installed/built ISFs, and the in-tree `mac.pagecache`).
2. Run the toolkit → menu `[I]` Installer → `[A]` Install EVERYTHING (or
   `crescent_toolkit.py` and pick Install). This:
   - clones fresh Vol3 + Vol2,
   - installs pip deps + ISF-build tools (dwarf2json→PATH, apt tools),
   - **copies every `vol_plugins/**/*.py` into the fresh Vol3** — `mac.pagecache`
     AND the patched `mac.list_files` (automatic, via `install_bundled_plugins()`),
   - **applies `installer.apply_framework_fixes()`** — idempotent source patches to
     Vol3 *framework* files that can't be shipped as plugins (e.g. the mac
     `netstat`/`files_descriptors_for_process` `UnboundLocalError` fix). No-op if
     upstream already fixed it.
3. Retest. Symbols (ISFs) are re-downloaded/re-built by the resolver on demand, so
   the first Linux/macOS run pays the ISF fetch/build again (expected).

What you get back automatically: Vol3+Vol2, deps, dwarf2json, `mac.pagecache`, the
patched `mac.list_files`, and the framework `netstat` patch.
What is re-created on demand: ISFs (downloaded/built per image), the Vol3 symbol
cache (warmed on first run).

---

## The tool zip

`RAMBreaker_toolkit.zip` (on the Desktop) contains the TOOL only:
`crescent_toolkit.py`, `modules/`, `utils/`, `data/`, `vol_plugins/`,
`_isf_build/dwarf2json`, and `claude context/` (docs). It EXCLUDES: Vol3/Vol2
(installed separately), `LiME/`, the `_isf_build/` scratch (kdbg.deb / x / mint /
logs), `__pycache__/`, and `.claude/`. Everything sits under a top-level
`RAMBreaker_toolkit/` folder. Unzip anywhere and run the installer to provision
Vol3/Vol2 + the bundled plugins (`mac.pagecache`, patched `mac.list_files`) + the
framework `netstat` patch.
