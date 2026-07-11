# RAMBreaker (CresCentC v6.0)

A modular memory-forensics framework over **Volatility 2 / 3**: feed it a RAM
image (`.raw`, `.mem`, `.lime`, `.dmp`, VMware `.vmem`) and it auto-detects the
OS, drives the right Volatility engine, and produces one self-contained,
interactive `report.html` — **Windows, Linux, and macOS**.

Full documentation lives in [`claude context/`](<claude context>) — start with
[`README.md`](<claude context/README.md>) and
[`TOOL_OVERVIEW.md`](<claude context/TOOL_OVERVIEW.md>).

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
