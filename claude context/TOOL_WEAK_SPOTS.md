# Tool-wide weak-spot analysis (2026-07-11)

A whole-codebase pass for weak spots, ranked by severity × likelihood. Scope:
`crescent_toolkit.py`, `modules/`, `utils/` (~29k LOC). Baseline hygiene is
**good** — zero bare `except:`, zero `shell=True`, zero `eval`/`exec`, subprocess
calls are timeout-bounded, JSON is written defensively. The findings below are
the real risks that remain. Items marked ✅ were fixed earlier this same session.

Legend: **[Sev]** High / Med / Low · *(confirmed)* = read in code · *(inferred)*
= reasoned, not exercised.

---

## High

> **Status 2026-07-11: H1, H2, H3, H4 all FIXED** (commits `335a30c`, `21f5068`,
> `8b74871`). Details inline below; 121/121 tests green.

### H1 — Linux/macOS process corroboration is effectively blind *(confirmed → ✅ FIXED)*
**Fix (`335a30c`):** run `linux.psscan.PsScan` in the fast/full/malware Linux
modes (validated live: 904 procs on kalilinux.lime) and make it independent of
`pslist` in DEPENDENCIES; add a `psaux` fallback corroborator for macOS (no
psscan); gate the "psscan ≫ pslist" WARN to Windows so Linux slab retention isn't
noise. Bug-#10 CRITICAL now fires on all OSes.
`run_health.corroborate_processes` is the Bug-#10 guard: it catches "pool scan
(`psscan`) finds processes but the linked list (`pslist`) is empty" — the classic
hidden/failed process-list signature. **But no Linux/macOS plugin list runs
`psscan`** (`extractor.linux.py` / `.mac.py` PLUGINS have `pslist pstree psaux …`,
no `psscan`; only `extractor.windows.py` has `windows.psscan.PsScan`). So on
Linux/macOS `psscan` is always `None` and the strongest corroboration branch can
never fire — a silently-empty or rootkit-hidden Linux process list is **not**
cross-checked.
*Impact:* the headline anti-blindness check is Windows-only.
*Fix:* add a Linux/macOS pool/scan-based process source (Vol3 `linux.pslist` has
scan variants / `linux.psscan` where available; or corroborate `pslist` against
`psaux`/`pstree` counts with a tolerance) and feed it into `corroborate_processes`.

### H2 — Debug-package download over plain HTTP, no integrity check *(confirmed → ✅ FIXED)*
**Fix (`21f5068`):** `DDEBS_POOL`→https; `prefer_https()` upgrades any TLS-capable
host in both download paths; http-only hosts warned. See H3 for the payload check.
`dbgsym_builder.py:72` `DDEBS_POOL = "http://ddebs.ubuntu.com/pool/main/l"` fetches
`.ddeb` kernel debug packages over **HTTP**, and nothing verifies a checksum or
signature before `dwarf2json` parses them into an ISF. A network MITM (very real
for analysts on hostile/field networks) can serve a crafted `.ddeb`.
*Impact:* malformed/hostile DWARF fed to `dwarf2json`; at minimum a poisoned ISF
that yields wrong symbol resolution on evidence.
*Fix:* use the HTTPS ddebs endpoint; verify the `.deb` against the archive
`Packages` SHA256 (already fetched for the index) before building.

### H3 — No integrity verification on any downloaded symbols/ISF *(confirmed → ✅ FIXED for the dbgsym path)*
**Fix (`21f5068`):** `verify_downloaded_package()` checks archive magic
(ar/rpm/xz/gz/bz2/zst/zip) and refuses an HTML error page/garbage before
extraction, verifies an expected sha256 when supplied, and logs the computed
sha256 (fails closed on mismatch). The Volatility symbol-zip download in
`installer.py` is now also verified (`verify_symbol_zip`): zip magic +
`zipfile.testzip()` structural check reject an HTML error page / truncated /
corrupt payload before extraction, and an **optional** `PINNED_SYMBOL_SHA256`
pin is enforced when set (empty by default — these packs update upstream, so a
default pin would reject legitimate refreshes; the installer logs the observed
sha256 so an operator can lock a vetted version).
Beyond H2: `installer.py` pulls Volatility symbol zips
(`downloads.volatilityfoundation.org/.../{windows,linux,mac}.zip`, HTTPS ✓) and
the resolver downloads community ISFs, all **without a pinned checksum**. HTTPS
protects transport, but a compromised mirror or a swapped upstream artifact is
undetected. Contrast the good instinct in `TOOLCHAIN.lock` (dwarf2json binary
committed *because* an upstream change once shipped a broken build).
*Fix:* pin known-good SHA256s for the symbol packs; warn/fail on mismatch.

### H4 — HTML report XSS defense rests on an untested invariant *(confirmed → ✅ FIXED)*
**Fix (`8b74871`):** shared `utils.json_converter.safe_js_json()` escapes `< > &`
+ U+2028/9 to `\uXXXX` (context-breakout-proof regardless of per-field escaping);
all three report generators embed via it. Audited the client side — every
memory-derived render path already uses `esc()`. Regression test feeds a
`</script><img onerror>` payload through `_build_html` and asserts no live
break-out.
The self-contained `report.html` is built from **attacker-controlled memory
strings** (malware process names, command lines, URLs) and opened in the analyst's
browser. Core defenses ARE present: the data blob is `json.dumps(...).replace("</",
"<\\/")` (blocks `</script>` breakout, `html_report.*.py:443`) and values render
through `esc()` (`:483`, escapes `& < > " '`). **But safety requires that *every*
render path routes through `esc()`/`makeTable`'s escaper** — a single `${value}`
on memory-derived data without `esc()` is stored XSS. That invariant is enforced
by nothing but discipline, across a ~900-line JS template **triplicated** in three
OS files. No test asserts it.
*Fix:* add a test that feeds a `<img src=x onerror=alert(1)>`/`</script>` payload
through the report generator and greps the output HTML to confirm it is neutralised
in every tab; de-duplicate the JS template so the invariant lives in one place.

---

## Medium

### M1 — Partial-output struct failures still pass as success *(confirmed, by design)*
The ① fix (`volatility._vol3_success`) demotes rc=0 **empty** + systemic-stderr
runs, but deliberately keeps rc=0 runs that produced *some* rows even when stderr
logged a struct exception (evidence-preserving — it only logs a warning). So a new
kernel that corrupts a *subset* of objects (partial rows + `AttributeError`) is
still counted OK. This was a conscious trade-off (don't discard mostly-good
evidence), but it is a residual blind spot.
*Fix (if wanted):* a `success="suspect"` tri-state surfaced in run_health, so
partial-with-exception is neither a hard fail nor a clean pass.

### M2 — Adaptive RAM guard uses a static per-job estimate *(confirmed)*
`_adaptive_jobs` reads `MemAvailable` once and assumes 1.0–1.5 GB/job. Heavy
plugins on large images (`mftscan`, `malfind`, `vadinfo`, `proc.Maps` on 8 GB+)
can exceed that, and the guard never re-checks mid-run. `fastest` disables it
entirely.
*Impact:* OOM/thrash on big images despite "memory-safe" `normal` mode.
*Fix:* scale per-job estimate with image size; optionally re-poll and throttle new
submissions when `MemAvailable` drops.

### M3 — Triplicated extractor logic invites divergence *(confirmed)*
`class Extractor` is copy-pasted across `extractor.{windows,linux,mac}.py`; the
`run()`/`write_summary()`/resume blocks are near-identical. Every cross-cutting
change this session (run_health wiring, crash_report wiring, the `.json.error`
resume sidecar) had to be applied **three times** — each a chance to miss one.
*Fix:* hoist the shared skeleton into a base class; keep only the PLUGINS tables
and OS-specific hooks in the subclasses.

### M4 — No integration/canary test drives Volatility *(confirmed → ✅ FIXED)*
**Fix (`tests/run_canary.py` + `tests/fixtures/canary/fake_vol3.py`):** a Tier-B
canary drives the REAL pipeline — `Extractor.run` → subprocess → parse →
`_vol3_success` demotion → `.json.error` sidecar → resume → `write_summary` →
`run_health` → `crash_report` → `HTMLReportGenerator.generate` — against a fake
Vol3 stub (no memory image needed; the one un-fakeable step, ISF cache warm-up,
is stubbed). 21 assertions cover success/clean-empty/silent-struct-demotion/
hard-fail, resume skip-vs-re-run, taxonomy classification, and report XSS
encoding of a hostile process name. Run: `python3 tests/run_canary.py`.

### M5 — "Vol3 silent for 180s → abort (stall)" can false-abort on slow storage *(confirmed live)*
Observed this session: with two extractions contending on a `vmhgfs-fuse` shared
folder, detection stalled and `netscan` took 4838 s. Progress-aware probes help,
but a fixed silence budget can still abort a legitimately-slow-but-fine run on
network/USB storage.
*Fix:* base the stall decision on I/O progress (bytes read) rather than wall-clock
silence, or scale the budget with the source's measured throughput.

---

## Low

### L1 — crash_report free-text scrub is whitelist-strong but not total *(confirmed, my code)*
`crash_report.scrub` redacts addresses + common path shapes, and the schema is a
whitelist — but the `classify_failure` `other` category passes 160 chars of
scrubbed-but-free-form error text. A hostname/token embedded in an exception
message that matches none of the path/addr patterns could survive. Low risk (only
reached on unclassified errors, and only sent if the analyst opts into transport),
but the free-text field is the residual leak surface.
*Fix:* for transport, drop `reason` for the `other` category (keep only the
category), or hash it.

### L2 — Passwordless `sudo -n cp/chmod` to install dwarf2json *(confirmed)*
`installer.py:268-270` copies the bundled `dwarf2json` to a system path via
`sudo -n cp` + `sudo -n chmod +x`. The binary is the committed pin (trusted), and
`sudo -n` no-ops without cached creds, so low risk — but it is a privileged write
triggered by the tool worth being explicit about.

### L3 — Static IOC regexes over adversarial input *(inferred)*
IOC patterns are author-defined (`ALL_CATEGORIES`, not user/data-derived — no
untrusted-regex compilation), but they run against tens of millions of
memory-string lines. A pattern with catastrophic backtracking could ReDoS on a
crafted string.
*Fix:* audit the patterns for nested quantifiers; cap per-line length before match.

### L4 — Report data uses `ensure_ascii=False` (U+2028/U+2029) *(inferred)*
`json.dumps(..., ensure_ascii=False)` embeds raw Unicode into the `<script>` blob.
Legal in JSON and, since ES2019, in JS string literals — modern browsers are fine;
only ancient engines could choke. Trivial to harden by also escaping `  `.

---

## What was already fixed this session (context)
- ✅ Silent new-kernel struct demotion (`_vol3_success`) + kept stderr — the ①
  half of H-adjacent blindness.
- ✅ Resume cache-poisoning (`<name>.json.error` sidecar) — ②.
- ✅ `linux_kernel.json` lost on the cached-symbol path (`_persist_kernel_if_missing`).
- ✅ Advisory empty-plugin corroboration (`run_health.advisory_nonempty`) — ③,
  conservative.
- ✅ Local `crash_report.json` + opt-in transport (Steps 1–2).

See `FUTURE_CRASH_REPORTING.md` for the failure-diagnosis subsystem and its own
blind-spot analysis.
