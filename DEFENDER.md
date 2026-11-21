# RAMBreaker and Microsoft Defender

RAMBreaker is a memory-forensics tool. Two things about it commonly make antivirus
products react, even though nothing in it is malicious:

1. **The program itself** is a PyInstaller bundle (`RAMBreaker.exe` + `_internal\`).
   It is built **without UPX** and without any packing, obfuscation or signing tricks,
   which keeps false positives rare - but Defender's machine-learning heuristics can
   still flag new, unsigned PyInstaller executables.
2. **What it reads and writes is malware.** Memory dumps contain malware, Volatility
   carves injected code, dumped processes, EVTX files and YARA/Sigma rule text; the
   `sigma_rules\` folder contains detection signatures (strings like `mimikatz`).
   Defender may quarantine files under `output\`, `cache\` or `sigma_rules\`, or slow
   every file write while it scans multi-GB strings files.

RAMBreaker never disables or bypasses any security product. If Defender interferes,
add exclusions **yourself**, scoped as narrowly as possible:

## Recommended exclusions (Windows Security GUI)

Windows Security > Virus & threat protection > Manage settings >
Exclusions > Add or remove exclusions > Add an exclusion > **Folder**:

| Folder | Why |
|---|---|
| `<RAMBreaker folder>\output` | case results: carved malware, dumped processes, strings |
| `<RAMBreaker folder>\cache` | symbol cache, Vol2 profiles |
| `<RAMBreaker folder>\sigma_rules` | detection rule text that looks like malware strings |
| `<RAMBreaker folder>\threat_intel_db` | downloaded threat-intel lists (malware URLs, hashes, C2 addresses). Seen live on 2026-11-16: Defender removed `threatfox.csv` and two Maltrail lists minutes after the download. The report then says "Missing after download" and that database is not checked |
| `<RAMBreaker folder>\yara_rules` | YARA rule text (malware signatures) |
| the folder holding your memory dumps (read-only evidence) | optional: speeds up large reads |

If the program itself is blocked ("Windows protected your PC" or a Defender
detection on `RAMBreaker.exe`), add a **File** exclusion for
`<RAMBreaker folder>\RAMBreaker.exe` and a **Process** exclusion for
`RAMBreaker.exe`, `<RAMBreaker folder>\runtime\py3\pythonw.exe` and
`<RAMBreaker folder>\runtime\py27\python.exe`.

## Same thing in an elevated PowerShell

```powershell
$rb = "C:\Tools\RAMBreaker"          # <- your RAMBreaker folder
Add-MpPreference -ExclusionPath "$rb\output", "$rb\cache", "$rb\sigma_rules", "$rb\threat_intel_db", "$rb\yara_rules"
# only if the program itself is flagged:
Add-MpPreference -ExclusionPath "$rb\RAMBreaker.exe"
Add-MpPreference -ExclusionProcess "$rb\RAMBreaker.exe", "$rb\runtime\py3\pythonw.exe", "$rb\runtime\py27\python.exe"
# review / undo:
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
Remove-MpPreference -ExclusionPath "$rb\output"
```

## Good practice

- Use a dedicated analysis machine or VM for malware-bearing evidence.
- Keep exclusions limited to the RAMBreaker folder; do not exclude whole drives.
- If a file was quarantined, restore it from Protection history *after* adding the
  exclusion, or simply re-run the analysis.
- Report a false positive on the program to Microsoft:
  https://www.microsoft.com/wdsi/filesubmission
