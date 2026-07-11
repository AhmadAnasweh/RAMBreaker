# Session 2026-07-11 — Local crash report (`crash_report.json`), Step 1

## Context

This continues the "tool-blindness to its own errors" thread. Prior commits in
this repo's short history laid the groundwork:

- `850fa28` — **git init** + defensive `.gitignore` (evidence never enters
  history) + `TOOLCHAIN.lock.md` (separate a *tool-env* regression from a
  *target-image* failure).
- `ae16768` — **`run_health.py`**: turn silently-incomplete extractions loud
  (process corroboration, empty-tab detection, failure taxonomy, health banner).
- `5789457` — Tier-A golden tests pinning that pure logic.

The design in `FUTURE_CRASH_REPORTING.md` called for a two-step feature; **Step 1
(local, zero-network `crash_report.json`) is what this session built.**

## What was built

`modules/crash_report.py` — writes a scrubbed, structured **failure fingerprint**
to `<output>/crash_report.json` whenever an extraction actually fails. It is the
local half of the crash-reporting design: the artifact an analyst can read now
and (once Step-2 transport exists) hand to the tool author manually.

Key properties:

- **Writes only on failure** — `results["fail"] > 0` or `run_health` status ≠
  `healthy`. A clean run leaves nothing behind.
- **Whitelist, never blacklist** — a frozen `_CRASH_KEYS` set (enforced by a
  test) is the only thing that can ever be emitted.
- **Everything scrubbed** — `scrub()` redacts `0x…`→`<addr>` and Windows/POSIX
  user paths→`<path>`; `parse_kernel_banner()` keeps only the parsed kernel
  version + distro label (the raw banner's builder `user@host`/build path is
  never retained).
- **No image content** — no strings, IOCs, hostnames/IPs, paths, usernames,
  hashes, dumped files. No `install_id` (that's a Step-2 consent concern).
- **One source of truth for failures** — `failed_plugins` /
  `process_corroboration` come from the `run_health` taxonomy, not a re-parse.
- **`fingerprint`** — order-independent 16-hex hash of target OS/engine/kernel +
  failure classes, for dedup.

Schema id: `crescent-crash-report/1`.

## Integration

Called from `write_summary()` in `extractor.windows.py`, `extractor.linux.py`,
`extractor.mac.py`, nested inside the existing `run_health` try-block so `health`
is in scope. Append-only, wrapped in try/except — **cannot affect extraction**.

## Git

- `.gitignore` now also ignores `crash_report.json` and
  `tests/fixtures/**/crash_report.json` (mirrors the `run_health.json` rule) —
  the artifact is evidence-adjacent output and must never enter history. The
  *module* is tool code and is tracked.

## Tests

`tests/run_tests.py::test_crash_report` — 19 assertions (scrub redaction, banner
parsing incl. builder-identity drop, fingerprint stability, whitelist-keys guard,
an explicit no-leak sentinel check, `write()` on healthy-vs-broken fixtures).
Full suite: **45 passed, 0 failed** (was 26).

## Design refinement during testing

The first real run (`Windows2.raw`, Vol2/Win7) surfaced a semantic bug in the
trigger: run_health rated the run **healthy** (process list corroborated
37/37/37), yet 2 plugins "failed" — `connections` and `connscan`, both
**expected-nonbug** (XP-era plugins on modern Windows). Writing a file literally
named `crash_report.json` for a run where run_health says nothing broke is
contradictory.

Fixed `_should_write` to agree with run_health's verdict: emit a report only when
status ≠ `healthy`, **or** a failed plugin is a *real* failure (not
expected-nonbug / empty-result), **or** plugins failed but none could be
classified (surface the unknown rather than swallow it). A healthy run whose only
failures are documented non-bugs now leaves **no** artifact.

## Real-image validation

**`Windows2.raw`** (2 GB, Win7 SP1 x64, Vol2, `-m fast`) — full extraction, 14
OK / 2 failed (`connections`, `connscan`). run_health: **healthy** (37/37/37).
Under the refined trigger, `write()` returns `None` — **no** `crash_report.json`,
which is correct (nothing actually broke). This exercised the real
`write_summary → run_health → crash_report` path end-to-end; the report that the
pre-refinement logic wrote was verified leak-clean (no `/home`, `/mnt`, drive
path, hex address, `RAMDUMPS`, or `Windows2` substrings) before being suppressed.

**`kalilinux.lime`** (2 GB, Kali/LiME, Vol3, `-m fast`) — full extraction, 9 OK
/ 1 failed. run_health: **degraded** (empty network tab — `sockstat` returned 0;
`linux.pagecache.Files` hit the 600 s timeout). `crash_report.json` **written**,
leak-clean, with the pagecache failure correctly classified `timeout` (a *real*
failure, not benign) and the empty-network finding carried through. This is the
canonical "real problem" case the artifact exists for.

  *Limitation found here → FIXED:* this run reused **cached** ISF symbols
  ("Symbols already working"), so `linux_resolver.linux.resolve_symbols`
  short-circuited before writing `json/linux_kernel.json` — the file the report
  reads for `target.kernel/distro` — leaving both `""`. Fixed by
  `_persist_kernel_if_missing()`: on the already-working fast path, if the file is
  absent, do the same fast strings-based banner scan + ranking the resolver
  already trusts and persist the top candidate. Guarded (skips when present) and
  wrapped (can't slow/break a working run). Validated on `kalilinux.lime`: writes
  kernel `6.12.13-amd64`, and `crash_report.target` now reads
  `{kernel: 6.12.13-amd64, distro: Kali}` — with the banner's builder identity
  (`devel@kali.org`) correctly **not** retained. The macOS resolver already writes
  the file before its already-working check, so this gap was Linux-only.

**Fixtures + synthetic** (offline, in the test suite): a broken-run report
(`bug10_win`, pslist=0/psscan=5) is written with status `broken`; a synthetic
taxonomy carrying `/home/kali/RAMDUMPS/secret.raw @ 0xdeadbeef` scrubs to
`<path> @ <addr>` with a passing no-leak assertion.

## Follow-up: silent new-kernel failure fixes ①/② (same session)

Analysis of new-kernel handling (documented in `FUTURE_CRASH_REPORTING.md` →
"Known blind spots") surfaced four gaps; ①②④ were fixed, ③ deferred:

- **① `_run_vol3` demotion** (`volatility.py::_vol3_success`, pure/testable): a
  Linux/macOS plugin that exits `0` with an empty result **and** a systemic stderr
  exception (struct drift / stub ISF) is no longer counted as a clean-empty
  success — it's a failure, and its stderr is kept, not discarded. Guarded so
  genuinely clean-empty plugins stay success (verified on real Kali Vol3 output).
- **② resume sidecar** (`_write_error_marker` + resume check in all three
  extractors): a failed plugin leaves a `<name>.json.error` sidecar so a re-run
  re-executes it instead of trusting stale/partial JSON. Inert to every `*.json`
  glob (verified).
- **④** is fixed *by ①* (the demoted failure now reaches the `struct-mismatch →
  "bump Vol3"` classifier); **③** (advisory "usually-not-empty" corroboration) is
  deferred — high false-positive risk, needs calibration.

Tests: `tests/run_tests.py::test_vol3_demotion` (+19) → **69/69** green.

## Next (Step 2, not built)

Opt-in transport: `install_id` + first-run consent (show sample payload),
`--no-telemetry`/`CRESCENT_TELEMETRY=0`, fire-and-forget send deduped by
`fingerprint`, and the privacy-max "send this file? [y/N]" prompt. Builds
directly on `crash_report.build()`. See `FUTURE_CRASH_REPORTING.md`.
