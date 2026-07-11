# Future Feature — Opt-in Crash / Failure Reporting

Status: **planned, not built** (design agreed 2026-07-11). Author: Ahmad Anasweh.

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
   (zero privacy risk, most of the diagnostic value).
2. **Transport:** opt-in send to a chosen endpoint, once scrubbing is proven.

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
