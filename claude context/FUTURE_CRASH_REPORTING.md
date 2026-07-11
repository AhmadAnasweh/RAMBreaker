# Crash / Failure Reporting

Status: **Step 1 (local `crash_report.json`) + Step 2 (opt-in transport) BUILT
2026-07-11.** Author: Ahmad Anasweh.

> Both steps are implemented — see `## Implemented — Step 1` and `## Implemented —
> Step 2` below. Transport is **default OFF** and sends nothing without explicit
> opt-in and an endpoint. What remains is product/UX (an interactive consent
> prompt, a hosted receiver) — noted at the end of the Step 2 section.

## Goal
When a run hits plugin failures, produce a **scrubbed, structured failure
report** that (a) is written locally and (b) can optionally be sent to the tool
author. It operationalises the "failure fingerprint" — turning every failed run
into a self-diagnosing artifact (kernel banner, distro, engine, per-plugin
pass/fail + error class, ISF resolution outcome). See also the log-signature
cheat-sheet at the bottom.

## HARD CONSTRAINT — this is a forensics tool
The data handled is memory dumps of potentially-evidence machines (malware, PII,
credentials, NTLM hashes, case data). Therefore:

1. **Never send the raw `crescent_toolkit.log`.** It contains target process
   names, command lines, IPs, file paths, usernames.
2. **Build the report from the structured results dict, not by scraping the log.**
3. **Whitelist fields — never blacklist.** New sensitive fields must not be able
   to leak by accident.
4. **Opt-in, default OFF.** Honour `--no-telemetry` / `CRESCENT_TELEMETRY=0`
   unconditionally; detect offline/air-gap and skip silently.

## What to send (safe + diagnostically sufficient)
```jsonc
{
  "tool_version": "6.0",
  "install_id": "<random UUID, generated once, opt-in>",
  "host":   { "os": "linux", "arch": "amd64", "python": "3.13" },   // analysis box
  "target": { "os_type": "linux", "engine": "vol3", "profile": null,
              "kernel": "6.19.14+kali-amd64", "distro": "Kali" },   // kernel, parsed
  "vol":    { "vol3_commit": "634774fd", "dwarf2json": "bundled" },
  "isf":    { "resolved": true, "source": "kali-pool", "built": true,
              "stub_structs": [] },
  "plugins": [
    { "name": "linux.lsmod.Lsmod", "status": "fail", "dur": 25.6,
      "error_class": "AttributeError: taint_flag.module" },
    { "name": "linux.lsof.Lsof", "status": "ok", "dur": 54.2 }
  ]
}
```

## NEVER send
Image, image path (send only a salted hash or basename-stripped), strings, IOCs,
browser/comms artifacts, hashes, hostnames/IPs from the image, dumped files, raw log.

## Two non-obvious scrub traps
- **Kernel banners embed the builder `user@host` + build path** (`gcc ... (user@host)`).
  Send only the parsed version+distro, not the full banner.
- **Error messages carry target paths/addresses.** `error_class` = exception type +
  message normalised: `0x...`→`<addr>`, `/home/...`→`<path>`, digits→`<n>`. Scrub
  before it leaves the process.

## Transport / consent
- First-run prompt that **shows a sample payload** before asking to enable.
- Persist choice in settings; easy disable via flag/env.
- **Best-effort send:** 2–3 s timeout, fire-and-forget thread, wrapped so it can
  never crash or slow a run. Dedup + rate-limit by fingerprint hash (once per
  unique fingerprint per install).
- **Privacy-max fallback (recommended default):** write `<output>/crash_report.json`
  and prompt "send this file to the author? [y/N]" — air-gapped analysts still get
  a clean artifact to hand over manually.

## Receiver liability
Collecting this makes the author a data controller — keep the payload minimal.
Cheapest safe sinks: serverless HTTPS fn (Cloudflare Worker / Lambda), a
Sentry/GlitchTip instance (built-in scrubbing), or a pre-filled GitHub issue.
Protect with a shared secret.

## Suggested build order
1. **Local only:** end-of-run failure-fingerprint summary + `crash_report.json`
   (zero privacy risk, most of the diagnostic value). ✅ **DONE** — see below.
2. **Transport:** opt-in send to a chosen endpoint, once scrubbing is proven.
   *(Not built. The scrubbing it depends on is now proven in code + tests, so
   this is the next clean step.)*

## Related: log-signature cheat-sheet (diagnose without the image)
| Log signature | Cause |
|---|---|
| ALL plugins fail `kernel.layer_name`+`kernel.symbol_table_name` + "No matching ISF" | missing/failed ISF |
| basic plugins pass, mount-tree plugins fail `Member not present in template: mnt` | incomplete ISF (stub `struct mount`) — dwarf2json |
| `AttributeError: ...!taint_flag.module` (or similar named struct.field) | Vol3-plugin-vs-kernel struct change |
| first batch (`info/pslist/psscan/pstree`) fails `symbol_table_name`, rest pass | Windows cold-start symbol race |
| `pslist` empty, `psscan` works | bare `.vmem` missing `.vmss/.vmsn` companion |
| `connections/connscan` (Win7), `sockstat` timeout (vmem), `mac.bash` | expected non-bugs |

The **kernel banner in the log is the key**: it lets the maintainer refetch that
kernel's debug package and reproduce the ISF/struct layout **without the image**.

---

## Implemented — Step 1 (local `crash_report.json`)

**Module:** `modules/crash_report.py`. Self-contained (like `run_health.py`):
reads only the output dir + the `run_health` result, writes one file, never
sends anything. Every helper is a pure, unit-testable function; `write()` is the
only side-effecting entry point and is wrapped so it can never disturb an
extraction.

**When it writes:** only when a run actually failed — `results["fail"] > 0` **or**
`run_health` status ≠ `healthy` (`_should_write`). A clean run leaves no artifact.

**Where:** `<output>/crash_report.json`. Gitignored (`crash_report.json` +
`tests/fixtures/**/crash_report.json`) so the artifact never enters history —
same rule as `run_health.json`.

**Schema `crescent-crash-report/1`** (whitelisted top-level keys — enforced by the
`_CRASH_KEYS` frozen-set test):
`schema, generated, note, tool_version, run{status,mode,duration_s,plugins_ok/failed/skipped/dep_skipped}, host{os,arch,python}, target{os_type,engine,profile,kernel,distro}, toolchain{vol3_commit_pinned,dwarf2json,source}, process_corroboration, findings[], failed_plugins[{name,category,reason}], ok_plugins[], fingerprint`.

**Privacy guarantees (the whole point — this is the manual-handover artifact):**
- **Whitelist, never blacklist** — only the keys above are ever emitted; the
  `_CRASH_KEYS` test fails if a new key appears without review.
- **`scrub()`** redacts every free-text field: `0x…`→`<addr>`, Windows paths,
  `/home|Users|root|var|tmp|mnt|media/…` and any remaining absolute POSIX path
  →`<path>`.
- **`parse_kernel_banner()`** keeps only the parsed kernel version + a distro
  label — the raw banner (which embeds the builder `user@host` + build path) is
  **never** retained.
- **No image content** — no strings, IOCs, hostnames/IPs, file paths, usernames,
  hashes, or dumped files. No `install_id` (that's a Step-2 consent concern).

**Failure semantics reuse:** `failed_plugins` and `process_corroboration` come
straight from the `run_health` `failure_taxonomy` / `process_counts`, so there is
one source of truth for "which plugin failed and why."

**`fingerprint`:** 16-hex sha256 over `os_type|engine|kernel|distro` + sorted
`plugin:category` pairs — order-independent, image-free, so the maintainer can
dedup identical failures across runs/machines (the Step-2 rate-limit key).

**Integration:** called from `write_summary()` in `extractor.windows.py`,
`extractor.linux.py`, `extractor.mac.py`, nested inside the existing `run_health`
try-block (so `health` is in scope), append-only and wrapped in try/except.

**Tests:** `tests/run_tests.py::test_crash_report` — 19 assertions covering
scrub redaction, banner parsing (incl. builder-identity drop), fingerprint
stability, the whitelist-keys guard, an explicit *no-leak* check (sentinel path +
address must not survive into the JSON), and `write()` behaviour (nothing on a
healthy run, `crash_report.json` on a broken one).

## Known blind spots — silent new-kernel failures (analysis 2026-07-11)

run_health + crash_report make *loud* failures loud, but a **new kernel** tends to
fail *silently*. The four blind spots below were found by analysis; **①②④ are now
fixed and ③ is deliberately deferred** (see "Status of fixes" after the list).
Ranked by risk:

1. **Linux/macOS false-success on `rc==0` + empty output** — *the main gap.*
   `volatility.py::_run_vol3` (≈L556–575): for Linux/macOS, success is `rc==0`
   **regardless of whether the JSON is `[]`**. A new-kernel struct change has two
   failure modes: (a) the exception propagates → `rc!=0` → correctly caught; but
   (b) Vol3 logs a per-object error to **stderr**, still exits `0`, and writes an
   empty/partial array → **counted as a successful, empty plugin.** Worse, the
   `err_msg` (which `_meaningful_stderr` already distils to the one useful
   `AttributeError: …!taint_flag.module` line) is only logged/returned when
   `not ok` (L576–581) — so on false-success the single most diagnostic line is
   **discarded**. That same struct drift is then invisible to `_classify_log_failures`
   (it greps `X FAILED:` lines that never get written) — so it never reaches the
   `struct-mismatch → "bump Vol3"` classifier either.

2. **Resume cache poisons on `[]`** — `extractor.*::run` `_BAD_MARKERS` (≈L110–138)
   decides a plugin can be skipped if its existing JSON contains none of the
   failure markers. A false-success struct-mismatch wrote `"[]"`, which contains
   no marker **and** the traceback went to stderr (never into the JSON) — so a
   re-run skips it forever, caching the silent failure as good.

3. **Corroboration only covers 3 tabs** — `run_health.KEY_PLUGINS` (L46–56) only
   flags emptiness for process / network / files. A new kernel that silently
   empties `lsmod`, `check_modules`, `check_syscall`, `malfind`, `mountinfo`,
   `elfs`, … trips nothing. No "expected non-empty" heuristic exists for them.

4. **Pinned Vol3 can't self-diagnose the silent case** — the `TOOLCHAIN.lock`
   pin (Vol3 `634774fd`) is correct for reproducibility, and `classify_failure`
   *does* say "bump Vol3" for struct-mismatch — but only when the failure is seen
   (rc!=0, logged `FAILED`). The highest-risk new-kernel drifts are the silent
   rc=0 ones from (1), which never reach that message.

**Status of fixes:**

- **① FIXED** — `volatility.py::_vol3_success()` (pure/testable) now demotes the
  silent case: on Linux/macOS, `rc==0` + empty result + a *systemic* stderr
  exception (`_is_plugin_exception`: `AttributeError`/`not present in template`/
  `Unhandled exception`/traceback) is a **failure**, not a clean-empty success.
  The distilled stderr is kept (returned as the plugin's `error`) and, even when
  the result is *non-empty* (partial), the exception is now logged instead of
  discarded. Guarded so a genuinely clean-empty plugin (`check_modules`/`tty_check`
  on a quiet host, no stderr exception) stays a success — verified on real Kali
  Vol3 output (pslist/check_modules not demoted).
- **② FIXED** — a failed plugin now leaves a `<name>.json.error` sidecar
  (`_write_error_marker`, written at every failure return of `_run_vol3`/`_run_vol2`,
  cleared on success). The resume logic in all three extractors re-runs any plugin
  with a sidecar instead of trusting stale/partial JSON. The sidecar is inert to
  every `*.json` glob and the `suffix == ".json"` / OS-heuristic scans (verified).
- **④ FIXED-by-①** — no separate code. ④ was a *consequence* of ①'s blindness:
  once the silent failure is demoted to a real `FAILED` with its stderr, it flows
  through `run_health._classify_log_failures → classify_failure → struct-mismatch`,
  which already prints "bump Vol3". We deliberately do **not** auto-bump the pin
  (reproducibility is the point of `TOOLCHAIN.lock`).
- **③ BUILT — conservatively** — `run_health.advisory_nonempty()` +
  `ADVISORY_NONEMPTY` flag a *small, high-signal* set that is almost never empty
  on a real host (Windows `svcscan`/`modules`, Linux/macOS `lsof`) when they RAN
  but returned 0 rows. Deliberately NOT the risky wide list (`malfind`/
  `check_syscall`/`tty_check` are legitimately empty on clean hosts, so they are
  excluded). Every finding is a **WARN worded as an observation** ("verify",
  "not a verdict") — status can reach `degraded`, never `broken` — matching the
  existing empty-tab checks and the tool's "evidence, not verdicts" rule. A
  plugin that did not run (no JSON) is never flagged. Tested
  (`test_advisory_nonempty`).

The kernel banner needed to *act* on any of these was itself being lost on the
cached-symbol path — also fixed (`_persist_kernel_if_missing`), so a crash_report
from a new-kernel box now carries `target.kernel/distro`.

## Implemented — Step 2 (opt-in transport)

Built in `crash_report.py`; **default OFF**, nothing sent without explicit opt-in
AND an endpoint. The report is already scrubbed/whitelisted, so transport adds
only an opt-in `install_id`.

- **Consent / gating** (`telemetry_enabled`, pure): OFF by default. Env wins over
  config — `CRESCENT_TELEMETRY=0` (or `--no-telemetry`, which `main()` maps to that
  env) forces OFF; `=1` forces ON; otherwise the saved config `enabled` flag (set
  via `enable(endpoint)` / cleared via `disable()`). Endpoint from
  `CRESCENT_TELEMETRY_ENDPOINT` or config; **no endpoint ⇒ no-op**.
- **`install_id`** — random UUID generated + persisted only on an opted-in send
  (`get_install_id(create=True)`); a disabled install has none. Config lives at
  `~/.config/rambreaker/telemetry.json` (override: `CRESCENT_TELEMETRY_CONFIG`).
- **`send()`** — stdlib `urllib` POST, 3 s timeout, fully wrapped (never raises /
  never blocks a run beyond the timeout). **`maybe_send()`** (called from
  `write()`) sends the scrubbed report exactly once per unique `fingerprint`
  (dedup via `sent_fingerprints`), only when enabled + endpoint.
- **`sample_payload()`** — a placeholder, image-free payload to SHOW before opt-in
  ("show a sample before asking").
- **Tests** — `test_telemetry` (17 assertions) covers gating precedence, dedup,
  payload scrubbing, and a **real localhost POST** (spins up an `http.server`,
  asserts the endpoint received the scrubbed body and that a duplicate fingerprint
  is not re-sent). No external service is contacted.

**Still open (product/UX, not plumbing):** an interactive first-run consent prompt
in the menu (the env/`enable()` path is the current opt-in); a real hosted
receiver endpoint (deliberately not invented here); optionally moving `send` to a
fire-and-forget daemon thread if the 3 s bound is ever felt.
