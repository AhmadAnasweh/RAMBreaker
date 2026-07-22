# RAMBreaker (v6.2)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A modular memory-forensics framework over **Volatility 2 / 3**: feed it a RAM
image (`.raw`, `.mem`, `.lime`, `.dmp`, VMware `.vmem`) and it auto-detects the
OS, drives the right Volatility engine, and produces one self-contained,
interactive `report.html` — **Windows, Linux, and macOS**.

Full documentation lives in [`docs/`](docs/) — start with
[`RAMBreaker_Guide.html`](docs/RAMBreaker_Guide.html). Release notes are in
[`CHANGELOG.md`](CHANGELOG.md).

## Scope & honest limitations

RAMBreaker is a **workflow layer over Volatility**, not a replacement for it — it
drives Volatility, survives and diagnoses its failures, and correlates the output
into one report. It works well on the common cases (Windows 10/11, common Linux
distros with available kernel symbols). For modern Linux kernels (~5.8+) it can
often build the symbols **from the image itself**: the `btf2isf` module
reconstructs a Volatility3 ISF from the BTF + kallsyms embedded in the dump, so a
kernel that is too new, custom-compiled, or missing from every repo still
resolves — offline and exactly, before any debug-package download. Where that is
not possible — a pre-BTF kernel (built without `CONFIG_DEBUG_INFO_BTF`) with no
community ISF and no debug package, or a kernel whose structs Volatility's own
plugins don't yet handle — the run will fail, but now **loudly and precisely**
(symbol-missing vs struct-mismatch vs timeout) instead of silently producing an
empty report. macOS is the weakest OS (Apple symbol availability, and no BTF).

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

## License

[MIT](LICENSE) — use it, fork it, build on it. It drives Volatility 2/3 and
bundles dwarf2json as external tools, which keep their own licenses.
