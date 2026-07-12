# Session 2026-07-12 — VAD memory-region dumper (`dump-vad`)

## Why

The existing `process_dumper` only wrote a process's **on-disk executable**
(`windows.pslist.PsList --dump` / Vol2 `procdump`). That is the PE image, not what
the process was *doing in memory* — heaps, stacks, mapped data files, and, most
importantly, **injected code**. To see "what was actually going on" inside, say,
`notepad.exe`, you need its **VAD** (Virtual Address Descriptor) regions.

## What was built

A new, deliberately distinct module — **`vad_dumper`** (class `VADDumper`,
output `vad_dumps/`, report `vad_dump_report.txt`) — OS-split like the rest:

| OS | Vol3 | Vol2 |
|---|---|---|
| Windows | `windows.vadinfo.VadInfo --pid P --dump` | `vaddump -p P -D dir` |
| Linux | `linux.proc.Maps --pid P --dump` | — |
| macOS | `mac.proc_maps.Maps --pid P --dump` (best-effort) | — |

Each dumped region is hashed, and regions that look like **code injection** are
flagged as *observations* (the tool's principle — never a verdict):

- **RWX** — protection contains `EXECUTE` + `READWRITE` → classic injection.
- **executable private** — executable, no backing file, not `WRITECOPY` → shellcode.
- `PAGE_EXECUTE_WRITECOPY` (normal copy-on-write image code) is **not** flagged —
  this was a real false-positive bug caught by the unit test and fixed.

## Wiring

- **CLI** `dump-vad` — `-i image -o out --vad-name notepad` (or `--vad-pid`, or the
  names `all` / `suspicious` / `first`). `first` skips kernel/System processes so
  it lands on a real user process with regions.
- **Menu** `[V]` VAD Dumper.
- **DFIR / `dump-all`** — a VAD phase runs after the PE/file dumps, dumping every
  process's regions to `dumped_all/vad_dumps/`.

Files: `modules/vad_dumper.{py,windows,linux,mac}.py`; CLI/menu/DFIR wiring in
`crescent_toolkit.py`. Tests: `tests/run_tests.py::test_vad_injection` (+8) →
**141/141** green (plus the canary).

## Real-image validation — whole check over /home/kali/Desktop/RAMDUMPS

Ran `dump-vad --vad-name first` across every image. **7 of 8 produced real region
dumps, across both engines and all three OSes:**

| Image | OS / Engine | Region files |
|---|---|---|
| Windows2.raw | Windows / Vol2 (Win7) | 101 |
| dump.mem | Vol3 | 101 |
| Challenge.raw | Windows / Vol3 | 108 |
| ubuntu.20211208.mem | Linux / Vol3 | 145 |
| kalilinux.lime | Linux / Vol3 | 139 |
| MAC | macOS / Vol3 | 252 |
| MAC2.raw | macOS / Vol3 | 151 |
| linux.vmem | Linux / Vol3 (4 GB) | 152 (after extraction reused) |

**8/8 validated.** All `inj=0` (benign test images; **no false positives** — the
WRITECOPY fix holding on real data). `linux.vmem` is the documented slow 4 GB
VMware image: its full `fast` extraction exceeds ~45 min, so the initial timed-out
runs never reached the dump step — an operational limit, not a VAD-module fault.
Once the extraction JSON existed, the VAD dump itself ran in 3m 48s (152 VMA
regions from systemd et al., `pid.1.vma.0x…-0x….dmp`). Note for later: `dump-vad`
only needs the process list, so a future refinement could run a minimal
process-only extraction instead of full `fast` mode.

Example (`smss.exe`): 14 regions dumped as
`smss.exe.<off>.0x…-0x….dmp` files (512 K/1 M heaps, 128 K mapped, 4–8 K
stacks/PEB/TEB) — the live memory, not the PE.
