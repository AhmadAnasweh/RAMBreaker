# RAMBreaker (CresCentC v6.0)

A modular memory-forensics framework over **Volatility 2 / 3**: feed it a RAM
image (`.raw`, `.mem`, `.lime`, `.dmp`, VMware `.vmem`) and it auto-detects the
OS, drives the right Volatility engine, and produces one self-contained,
interactive `report.html` — **Windows, Linux, and macOS**.

Full documentation lives in [`claude context/`](<claude context>) — start with
[`README.md`](<claude context/README.md>) and
[`TOOL_OVERVIEW.md`](<claude context/TOOL_OVERVIEW.md>). Release notes are in
[`CHANGELOG.md`](CHANGELOG.md).

## Scope & honest limitations

RAMBreaker is a **workflow layer over Volatility**, not a replacement for it — it
drives Volatility, survives and diagnoses its failures, and correlates the output
into one report. It works well on the common cases (Windows 10/11, common Linux
distros with available kernel symbols). It does **not** magically support a
brand-new kernel: if the community has no ISF and no debug package exists yet, or
if Volatility's own plugins don't yet handle that kernel's structs, the run will
fail — but it now fails **loudly and precisely** (symbol-missing vs
struct-mismatch vs timeout) instead of silently producing an empty report. macOS
is the weakest OS (Apple symbol availability). See
[`claude context/PROJECT_ASSESSMENT.md`](<claude context/PROJECT_ASSESSMENT.md>)
for the candid, full picture.

## Run

```bash
python3 crescent_toolkit.py                          # interactive menu
python3 crescent_toolkit.py full -i image.raw -o ./results/
```

`-i` is the image (not `-f`). See the docs for modes, flags, and the CLI surface.

## Development

After cloning, **enable the git pre-commit hook** — git does not clone hooks, so
this is a one-time per-clone step. It runs the two zero-dependency test suites
before every commit and blocks the commit if either fails:

```bash
git config core.hooksPath .githooks
```

Run the suites manually any time (both are ~2 s and need no memory image):

```bash
python3 tests/run_tests.py     # Tier-A: pure logic — run_health, crash_report, IOC, XSS, download integrity
python3 tests/run_canary.py    # Tier-B: drives the real extraction pipeline against a fake Vol3 stub
```

Bypass the hook in a genuine emergency with `git commit --no-verify`.

Toolchain version pins (Volatility, dwarf2json, Python) are recorded in
[`TOOLCHAIN.lock.md`](TOOLCHAIN.lock.md).
