# Changelog

All notable changes to RAMBreaker are recorded here.

## Unreleased

## v6.2 — 2026-07-16

A capability release on top of v6.1's reliability work — three new features and
the test hook switched on. The headline is **symbol self-sufficiency**: for
modern Linux kernels the tool can now build Volatility symbols from the BTF +
kallsyms inside the image itself, so a kernel that is too new, custom-compiled,
or absent from every repo still resolves — offline and exact. Plus fileless-
injection correlation and live memory-region (VAD) dumping.

### Added
- **In-image BTF symbol builder** (`btf2isf`): reconstructs a Volatility3 Linux
  ISF entirely from the BTF type info + kallsyms symbol table embedded **inside**
  the memory image — no matching vmlinux, debug package, or repo lookup. Pure
  Python: parses BTF → user/base/enum types (flattening anonymous members, naming
  typedef'd anonymous structs so Vol3 extensions attach), decodes token-compressed
  kallsyms (heuristic `.rodata` scan **and** deterministic VMCOREINFO-address
  paths), converts runtime→link-time addresses, and types the well-known globals
  Vol3 dereferences — structs, scalars, pointers (e.g. `module_kset`), and linker
  char-arrays (`_text`/`_etext`/…) so lsmod/check_modules/tty_check/capabilities
  all resolve. Handles LiME and flat raw/VMware dumps (auto-detects the
  <4 GB PCI hole) and signed/negative `phys_base`. Wired into
  `linux_resolver.resolve_symbols` as `_try_btf2isf_build()`, placed **before** the
  multi-GB dbgsym download: a kernel with BTF (~5.8+) resolves instantly, offline,
  and exactly — even when it is absent from every repo (too new, custom-compiled,
  or pruned upstream) — and falls through to the dbgsym route when the kernel has
  no BTF (`CONFIG_DEBUG_INFO_BTF` off). Also runs in the >25-banner "banner-cache"
  bail path, where it is ideal (reads VMCOREINFO + BTF directly, ignores banners).
  Still runs standalone (`python3 modules/btf2isf.py <image>`). Validated
  end-to-end through the full resolver on Ubuntu 5.15.0-41, Ubuntu 6.5.0-41
  (VMware `.vmem`), and Kali 6.12.13. Linux-only by nature (macOS/XNU has no BTF).
  Tests: +14 (`166` total) — a hand-crafted BTF blob pins the parser, anonymous-
  member flattening, typedef-anonymous naming, and kallsyms token decode + address
  arithmetic; plus the resolver glue (`_try_btf2isf_build`): version parsed from
  the ISF filename, no-BTF fall-through, and non-Linux short-circuit (no image).
- **Fileless-injection correlator** (`injection_correlator`): correlates the
  injected-memory plugin (malfind) with the module-list plugin (ldrmodules /
  proc.Maps) to flag reflective/manual code injection — HIGH (injected + loader-
  unregistered), MEDIUM (injected alone), LOW (unregistered+unbacked exec region).
  Per-OS parsers (Windows/Linux/macOS) → one engine; MZ/ELF/Mach-O header checks;
  JSON preferred + raw-text fallback (incl. Vol2 malfind regrouping). Standalone
  CLI (`--os`/`--auto`, `--injected`/`--modules`, `--pid`, `--min-confidence`,
  `--export json|csv|both`) and a pipeline stage writing
  `json/injection_correlation.json` (+ a `.txt` in the run root), wired into the
  export pack. New **Injection** tab in all three HTML reports. Tests: +11 (`152` total).
- **VAD memory-region dumper** (`dump-vad`, module `vad_dumper`): dump a process's
  LIVE in-memory regions — heaps, stacks, mapped data, and injected code — instead
  of just its on-disk PE (`vad_dumps/` + `vad_dump_report.txt`). Windows VAD
  (`vadinfo`/`vaddump`), Linux/macOS memory maps (`proc.Maps`/`proc_maps`). Each
  region is hashed; RWX and executable-private regions are flagged as possible
  injection (observations, not verdicts; `PAGE_EXECUTE_WRITECOPY` correctly not
  flagged). Wired into the CLI, menu `[V]`, and DFIR/`dump-all`. Validated across
  the RAMDUMPS image set (Windows Vol2+Vol3, Linux, macOS). Tests: +8 (`141` total).

### Dev
- Enabled the git pre-commit hook in this working tree
  (`git config core.hooksPath .githooks`) and verified it fires: every commit now
  runs Tier-A (`166`) + the canary suite (`21`) and blocks on failure. Still a
  per-clone step — a fresh clone must run the same one-liner to turn it on.

## v6.1 — 2026-07-11

A hardening + reliability release focused on making failures **loud, diagnosable,
and honest** — especially the silent ones that let a broken run masquerade as a
clean one — plus the first real test safety net and a security pass on downloads
and the HTML report.

### Added
- **Run-health guard** (`modules/run_health.py`): assesses a finished extraction
  from its `json/` + local log — process corroboration (pslist vs psscan vs
  pstree), empty-key-tab detection, a failure taxonomy (symbol-missing /
  struct-mismatch / timeout / expected-nonbug / …), and a health banner in
  `SUMMARY.txt` + `run_health.json`. Wired append-only into all three OS extractors.
- **Local crash report** (`modules/crash_report.py`, Step 1): on a real failure,
  writes a scrubbed, whitelisted `crash_report.json` failure-fingerprint (no image
  content; kernel banner reduced to version+distro; addresses/paths redacted) an
  analyst can hand to the tool author.
- **Opt-in crash-report transport** (Step 2): default-OFF telemetry
  (`CRESCENT_TELEMETRY` / `--no-telemetry`), `install_id`, dedup-by-fingerprint,
  bounded best-effort `send()`, `sample_payload()` for consent. Nothing leaves
  without explicit opt-in and an endpoint.
- **Advisory corroboration** (blind spot ③): flags a small high-signal set
  (Windows `svcscan`/`modules`, Linux/macOS `lsof`) that ran but returned nothing
  — WARN, worded as an observation, never a verdict.
- **Tier-B canary** (`tests/run_canary.py` + `tests/fixtures/canary/`): drives the
  REAL pipeline (subprocess → parse → demotion → sidecar → resume → run_health →
  crash_report → HTML report) against a fake Vol3 stub, no memory image needed.
- **Pre-commit hook** (`.githooks/pre-commit`): runs Tier-A + canary before every
  commit; enable with `git config core.hooksPath .githooks`.

### Fixed
- **Silent new-kernel failures** (①): a Linux/macOS plugin that exits 0 with an
  empty result while logging a systemic struct/symbol exception is now demoted to
  a real failure (was counted as a clean-empty success, its diagnostic stderr
  discarded).
- **Resume cache-poisoning** (②): a failed plugin leaves a `<name>.json.error`
  sidecar so a re-run re-executes it instead of trusting stale/partial output.
- **Linux/macOS process corroboration** (H1): `linux.psscan` now runs (was absent,
  so the Bug-#10 pool-scan-vs-linked-list check could never fire on Linux); a
  `psaux` fallback covers macOS; the "psscan ≫ pslist" WARN is gated to Windows
  (normal on Linux).
- **`linux_kernel.json` on the cached-symbol path**: persisted even when symbols
  are already warm, so `crash_report`/`system_info` get the kernel/distro.

### Security
- **HTML report XSS** (H4): the embedded data blob is now encoded via
  `safe_js_json` (`< > &` + U+2028/9 → `\uXXXX`), closing script-context breakout
  from attacker-controlled memory strings; regression-tested end-to-end.
- **Download integrity** (H2/H3): debug-package downloads upgraded to HTTPS where
  supported and verified by archive magic + sha256 before extraction
  (`dbgsym_builder`); Volatility symbol zips verified + optionally pinnable
  (`installer.verify_symbol_zip` / `PINNED_SYMBOL_SHA256`).
- **Transport payload** (L1): the `other` failure category's free-text reason is
  dropped from the sent payload (kept only its category).

### Testing
- Tier-A golden suite (`tests/run_tests.py`): **133 assertions**, zero-dependency,
  no images — pins run-health, crash-report/scrub, telemetry (incl. a real
  localhost round-trip), download integrity, and the report XSS encoding.

### Docs (`claude context/`)
- `TOOL_WEAK_SPOTS.md` (whole-codebase weak-spot analysis, H1–H4 fixed),
  `FUTURE_CRASH_REPORTING.md` (Steps 1–2 built + new-kernel blind-spot analysis),
  `PROJECT_ASSESSMENT.md` (honest strategic assessment: the idea, the new-kernel
  ceiling, Docker, a community ISF commons, struct-mismatch, and the verdict).

### Known limitations (honest)
Bleeding-edge kernels can still fail at the Volatility layer (struct-mismatch is
upstream's to fix); this release makes such failures **diagnosable**, not
impossible. macOS remains the weakest OS. See `PROJECT_ASSESSMENT.md`.

## v6.0

OS-split refactor of v5.0 — every multi-OS module became
`<name>.{windows,linux,mac}.py` behind a thin `importlib` dispatcher; added the
String Hunt module. See `claude context/ARCHITECTURE_V6.md`.
