# Toolchain Pin — known-good versions

The tool sits at the bottom of a stack that moves independently (kernels,
Volatility, symbol builders). This file records the **known-good** versions so
that when a run breaks you can tell a *tool-environment* regression (fixable,
your fault — pin drift) apart from a *target-image* failure (the kernel's, not
fixable). Update this file deliberately, only after re-running the test suite
and canary matrix.

Captured: 2026-07-11 on Kali (Python 3.13.2).

| Component | Pinned version | Location | Notes |
|---|---|---|---|
| Volatility 3 | **2.28.1** @ commit `634774fd` | `~/Desktop/volatility3` | lives outside repo; verify commit before important runs |
| Volatility 2 | legacy | `~/Desktop/volatility` | frozen upstream; profile-based |
| dwarf2json | **0.9.0** (output schema 6.2.0) | `_isf_build/dwarf2json` | **binary committed in-repo = the pin** |
| Python | 3.13.2 | system | |

## How to verify the pin before a real case
```bash
git -C ~/Desktop/volatility3 rev-parse --short HEAD    # expect 634774fd
./_isf_build/dwarf2json --version                       # expect dwarf2json 0.9.0
```
If the Vol3 commit differs, either re-pin here (after testing) or check out the
recorded commit. A Vol3 bump can silently invalidate `installer.apply_framework_fixes`.

## Why the dwarf2json binary is committed
An old dwarf2json once produced an incomplete `struct mount`, silently yielding
a broken ISF (mount-tree plugins failed 8 plugins deep). Freezing the binary in
git history means that class of failure can't recur without showing up as a
binary change in a diff.
