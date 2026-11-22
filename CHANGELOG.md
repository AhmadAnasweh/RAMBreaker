# Changelog

RAMBreaker v2 is the Windows edition: a port and upgrade of the original
Linux RAMBreaker/CresCent toolkit (v6.2, git tag `v6.2`; its own history is in
`src/CHANGELOG.md`). Details of each change are in `README.md`.

## Unreleased

- GUI: the mouse wheel over a drop-down, number box or slider (Case setup panel,
  Settings, Threat Intel, Retry, Extraction) now scrolls the panel behind it and
  never changes the value; hovering no longer picks Preset, Engine, Parallel jobs
  etc. Values change by clicking, typing, the arrow buttons or the keyboard; an
  open drop-down list still scrolls with the wheel.

## v2.5.0 (2026-11-18): protected output

- Every extracted file (Extraction workspace: files, process executables, DLLs
  and memory, memory regions; the threat-intel dump) is written straight into
  its own AES-256 password ZIP, password `infected` (changeable). Volatility 3
  writes the encrypted ZIP itself, so the plain file never touches the disk and
  the virus scanner cannot quarantine the evidence.
- Manifests and the results table still show size, type and SHA-256/SHA-1/MD5
  of the file inside; the threat-intel YARA scan decrypts in memory only.
- Switch "Protect extracted files" in the Extraction workspace and the Threat
  Intel dialog; CLI `--no-protect` and `--zip-password`.

## v2.4.1 (2026-11-18): plugin dependencies

- A plugin that reads another plugin's structures waits for it, and is skipped
  with a Retry button only when that plugin really failed. A timeout, a process
  Windows could not start, or symbol tables still being built skip nothing.
- `psscan`, `psxview` and `modscan` never wait; `netscan` -> `netstat` is one-way.

## v2.4.0 (2026-11-16, re-released 2026-11-17)

- Faster: Volatility 2 extras in parallel lanes (Full DFIR on a 2 GB Win7 image
  34 min 47 s -> 19 min 45 s), text scanners in parallel with the IOC scan
  (96 s -> 47 s), one-pass ASCII + UTF-16 strings, Linux `library_list`
  807 s -> 39 s.
- Threat intel: files lost to the 260-character path limit are recovered
  (989 -> 1,441 files on the test image); a batch continues after a failing
  object; databases quarantined by antivirus are reported; memory-capture tools
  flagged by VirusTotal get a context note.
- Optional local hash databases: MalwareBazaar, VirusShare MD5 lists, NIST NSRL
  known files.
- Dump queue in the GUI: add several dumps, start the queue, get a summary.
- VMware `.vmem` without its `.vmss`/`.vmsn`: the guest memory map is rebuilt
  from the guest's own page tables and applied to Volatility 3 and 2.
- No Volatility 2 probe for Windows builds newer than its profiles.

## v2.3.0 (2026-11-15): per-plugin retry

- A plugin that failed, timed out, was skipped or never ran gets a Retry button
  in the run monitor, with its own time limit (or none). Works on old cases too;
  a retry pressed during an analysis is queued. CLI `retry`.

## v2.2.0 (2026-11-15): DFIR + Threat Intel

- New preset: Full DFIR, then every file and process executable is dumped,
  SHA-256 hashed and checked with YARA (YARA Forge rules), bundled offline feeds
  and optional downloaded feeds, and VirusTotal if you enter a key. Only hashes,
  public IPs and domains are looked up; files are never uploaded.

## v2.1.0 (2026-11-13): every CLI feature in the GUI

- Extraction workspace: search and extract files, process executables/DLLs/
  memory, memory regions (whole process or selected regions), string hunt,
  export pack.
- Presets, plugin category and fast mode; animated help guides for each.
- Native-crash log and a run-health view that shows each plugin's latest outcome.

## v2.0.0 (2026-11-08): Windows port

- Runs natively on Windows 10/11, no WSL or Docker; one folder, start
  `RAMBreaker.exe`. Volatility 3 2.28.2 and Volatility 2 2.6.1 bundled.
- Desktop GUI (PySide6) with a case navigator, live log, help on every control,
  a tour, and dark and light themes.
- Linux symbol ladder: community ISF, distro debug packages via dwarf2json,
  BTF-to-ISF from inside the dump, Volatility 2 profile fallback.
- Dynamic per-dump plugin timeouts, a built-in Sigma engine, 24 new IOC types,
  an IOC checker for the raw dump, and e-mail artefact extraction.
