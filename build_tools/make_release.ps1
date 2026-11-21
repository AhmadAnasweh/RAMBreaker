# Package dist\RAMBreaker as release\RAMBreaker_v<Version> + a dated zip.
# Leaves out case data and per-machine state: output, work, logs, CresCentC_RESULTS
# (kept as empty folders), *.bak symbol backups, *.pyc, config\gui_settings.json, and (v2.2) the
# threat-intel feeds downloaded on this PC (not redistributable), saved API keys and the VT cache.
# Never overwrites an existing release folder or zip.
param([string]$Version = "2.1")
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$src = Join-Path $root "dist\RAMBreaker"
$rel = Join-Path $root "release"
$name = "RAMBreaker_v$Version"
$dst = Join-Path $rel $name
$zip = Join-Path $rel ("{0}_{1}.zip" -f $name, (Get-Date -Format "yyyy-MM-dd"))
if (Test-Path $dst) { throw "Release folder already exists: $dst" }
if (Test-Path $zip) { throw "Zip already exists: $zip" }

$skipDirs = "output", "work", "logs", "CresCentC_RESULTS", "threat_intel_db\downloaded", "yara_rules\yara-forge\_downloaded", "cache\vt", "cache\yara" | ForEach-Object { Join-Path $src $_ }
robocopy $src $dst /E /XD $skipDirs /XD __pycache__ /XF *.bak *.pyc gui_settings.json secrets.dat /NFL /NDL /NJH /NP | Out-Null
if ($LASTEXITCODE -ge 8) { throw "robocopy failed ($LASTEXITCODE)" }
"output", "work", "logs", "CresCentC_RESULTS" | ForEach-Object { New-Item -ItemType Directory -Force (Join-Path $dst $_) | Out-Null }

$left = @(Get-ChildItem $dst -Recurse -File -Include *.bak, *.pyc, gui_settings.json, secrets.dat)
if (Test-Path (Join-Path $dst "threat_intel_db\downloaded")) { throw "downloaded threat-intel feeds must not be released" }
if ($left.Count) { throw "Excluded files still present: $($left[0].FullName)" }

Push-Location $rel
# full path: from Git Bash, "tar.exe" resolves to GNU tar, which has no -a zip mode (v2.2: exit 128)
try { & (Join-Path $env:SystemRoot "System32\tar.exe") -a -c -f $zip $name } finally { Pop-Location }
if ($LASTEXITCODE -ne 0) { throw "tar failed ($LASTEXITCODE)" }

$files = (Get-ChildItem $dst -Recurse -File | Measure-Object Length -Sum)
"==> $dst  ({0} files, {1:N2} GB)" -f $files.Count, ($files.Sum / 1GB)
"==> $zip  ({0:N2} GB)" -f ((Get-Item $zip).Length / 1GB)
