# Session 2026-07-12 — Fileless-injection correlator (malfind × module-list)

## Why

Two plugins each hold half the story of code injection: the **injected-memory**
plugin (malfind) flags private, executable, header-bearing regions; the
**module-list** plugin says whether a region is registered in the OS loader. Neither
alone is conclusive. Correlating them — same PID + address, region present but
*unregistered* — is a strong reflective/manual-injection signal. This module
automates that, cross-OS.

## What was built — `modules/injection_correlator.py`

Runs **standalone** (full CLI) and as a **pipeline stage**.

| OS | injected-memory | module-list | header magic |
|---|---|---|---|
| Windows | `windows.malfind` | `windows.ldrmodules` | MZ (`4d 5a`) |
| Linux | `linux.malfind` | `linux.proc.Maps` / `linux.elfs` | ELF (`7f 45 4c 46`) |
| macOS | `mac.malfind` | `mac.proc_maps` / `mac.lsmod` | Mach-O (`fe ed fa …`) |

- **Per-OS parsers** (`parse_windows/linux/macos`) normalize the differently-named
  fields into ONE schema `{pid, process_name, base_address, end_address,
  protection, private_or_unbacked, header_signature_found, registered_in_module_list,
  mapped_path}` and feed a single `correlate()` engine — a 4th OS is just a parser.
- **Confidence:** **HIGH** = malfind hit + a matching module-list entry that is
  unregistered/unbacked (same PID + address; a `<<12` page-shift retry survives the
  Windows "Start VPN" quirk where that column actually holds a full address).
  **MEDIUM** = malfind hit alone. **LOW** = an executable region that is
  unregistered AND unbacked, with no malfind hit. Observations, never verdicts.
- **Inputs:** JSON preferred; a per-OS **raw-text fallback**, including regrouping
  Vol2 malfind's fragmented `Process/Pid/Address` + `Protection` + hexdump lines
  into whole regions.
- **CLI:** `--os` / `--auto`, `--injected` / `--modules`, `--pid`,
  `--min-confidence`, `--export json|csv|both`, `--overlap-tolerance`; colorama
  colour (rich not required). Ships a "how to generate the plugin outputs" note.

## Wiring

- **Pipeline:** `_cmd_core` runs `injection_correlator.run_from_output_dir()` after
  correlation → writes `injection_correlation.json` (+ `.txt`); best-effort, can't
  break the run.
- **HTML report:** an **Injection** tab added to all three OS reports
  (`html_report.{windows,linux,mac}.py`), rendered XSS-safe through the existing
  `safe_js_json` + `esc()`.

## How to generate the inputs (Vol3)

```
Windows: vol -r json -f mem windows.malfind.Malfind      > malfind.json
         vol -r json -f mem windows.ldrmodules.LdrModules > modules.json
Linux:   vol -r json -f mem linux.malfind.Malfind        > malfind.json
         vol -r json -f mem linux.proc.Maps               > modules.json
macOS:   vol -r json -f mem mac.malfind.Malfind           > malfind.json
         vol -r json -f mem mac.proc_maps.Maps             > modules.json
python3 modules/injection_correlator.py --os windows --injected malfind.json --modules modules.json --export both
```

## Validation

- Unit: `tests/run_tests.py::test_injection_correlator` (+11) — header detection
  per OS, HIGH/MEDIUM/LOW classification, registered+backed → not flagged, Linux
  path, auto-OS. **152/152** green (+ canary).
- Real image (`Windows2.raw`, Vol2): the fragmented Vol2 malfind regrouped into
  **5 RWX regions** (explorer/svchost), all correctly **MEDIUM** (benign RWX, no
  reflective-DLL correlation), **no false HIGH/LOW** after tightening the LOW
  anomaly to unregistered-AND-unbacked. Standalone CLI, `--auto`, filters, and
  JSON/CSV export all verified.
- **Full-pipeline** run (`full -m full` on `Windows2.raw`): confirmed end-to-end —
  the pipeline extracted `malfind` + `ldrmodules`, ran the correlation step
  automatically (no manual input), wrote `injection_correlation.json`/`.txt`, and
  the generated `report.html` shows the populated **Injection** tab (5 MEDIUM).
