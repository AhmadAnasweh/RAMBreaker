# RAMBreaker v2 build: PyInstaller GUI exe + portable runtimes + data.
# Usage:  powershell -ExecutionPolicy Bypass -File build_tools\build.ps1 [-Out D:\...\dist] [-SkipRuntime]
param(
    [string]$Out = "",
    [switch]$SkipRuntime
)
$ErrorActionPreference = "Stop"
$P = Split-Path -Parent $PSScriptRoot
if (-not $Out) { $Out = Join-Path $P "dist" }
$PY = Join-Path $P "runtime\py3\Scripts\python.exe"
$D = Join-Path $Out "RAMBreaker"
function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Rc($src, $dst, [string[]]$xd = @(), [string[]]$xf = @()) {
    $a = @($src, $dst, "/E", "/NFL", "/NDL", "/NJH", "/NJS", "/NP", "/R:1", "/W:1")
    if ($xd.Count) { $a += "/XD"; $a += $xd }
    if ($xf.Count) { $a += "/XF"; $a += $xf }
    & robocopy @a | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "robocopy failed ($LASTEXITCODE): $src" }
}

Step "PyInstaller (one-dir, windowed, no UPX)"
& $PY -m PyInstaller --noconfirm --clean --windowed --onedir --noupx `
    --name RAMBreaker --icon (Join-Path $P "src\gui\app.ico") `
    --add-data "$P\src\gui\icons;gui\icons" --add-data "$P\src\gui\app.ico;gui" `
    --add-data "$P\src\gui\help_media;gui\help_media" `
    --exclude-module modules --exclude-module utils --exclude-module crescent_toolkit `
    --exclude-module tkinter --exclude-module matplotlib --exclude-module numpy `
    --hidden-import statistics --hidden-import shlex --hidden-import sqlite3 --hidden-import ast `
    --hidden-import ctypes.wintypes `
    --distpath (Join-Path $P "build\pyidist") --workpath (Join-Path $P "build\pyi") `
    --specpath (Join-Path $P "build") (Join-Path $P "src\rambreaker_gui.py")
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed" }
# app\modules are excluded from the exe, so stdlib modules only they import must be hidden imports
& $PY (Join-Path $P "build_tools\check_frozen_imports.py") (Join-Path $P "src") (Join-Path $P "build\pyi\RAMBreaker\PYZ-00.toc")
if ($LASTEXITCODE -ne 0) { throw "frozen exe is missing stdlib modules the GUI needs (see above; add --hidden-import)" }
# PyInstaller wipes its dist folder on every run, so build in staging and merge
New-Item -ItemType Directory -Force $D | Out-Null
if (Test-Path (Join-Path $D "_internal")) { Remove-Item -Recurse -Force (Join-Path $D "_internal") }
Rc (Join-Path $P "build\pyidist\RAMBreaker") $D

if (-not $SkipRuntime) {
    Step "Portable CPython 3 runtime (runtime\py3)"
    $BASE = & $PY -c "import sys; print(sys.base_prefix)"
    Rc $BASE (Join-Path $D "runtime\py3") @("__pycache__", "test", "tests", "idlelib", "tkinter", "turtledemo", "Doc", "Scripts") @("*.pyc")
    $RPY = Join-Path $D "runtime\py3\python.exe"
    & $RPY -m ensurepip --upgrade | Out-Null
    Step "Python 3 dependencies (Volatility 3 [full] + toolkit)"
    & $RPY -m pip install --disable-pip-version-check --no-warn-script-location -q `
        "$P\runtime\volatility3[full]" pyyaml==6.0.3 pyahocorasick==2.3.1 zstandard==0.25.0 `
        python-evtx==0.8.1 yara-python==4.5.4 numpy==2.5.4
    if ($LASTEXITCODE -ne 0) { throw "pip install failed" }
    Step "Volatility 3 source, Volatility 2 + Python 2.7, symbols, tools"
    Rc "$P\runtime\volatility3" (Join-Path $D "runtime\volatility3") @(".git", "__pycache__", "build", "*.egg-info", "doc", "test") @("*.bak")
    Rc "$P\runtime\volatility2" (Join-Path $D "runtime\volatility2") @(".git")
    Rc "$P\runtime\py27" (Join-Path $D "runtime\py27") @() @("*.msi")
    Rc "$P\runtime\symbols" (Join-Path $D "runtime\symbols")
    Rc "$P\runtime\bin" (Join-Path $D "runtime\bin")
}

Step "Vol3: bundled plugins + framework fixes (idempotent)"
& $PY (Join-Path $P "build_tools\prepare_vol3.py") (Join-Path $D "runtime\volatility3")
if ($LASTEXITCODE -ne 0) { throw "prepare_vol3 failed" }

Step "Toolkit source (app\), Sigma rules, config, docs"
Rc "$P\src" (Join-Path $D "app") @("__pycache__", "gui") @("*.pyc")
Rc "$P\sigma_rules" (Join-Path $D "sigma_rules")
# Threat intel (v2.2): YARA rules + bundled feeds ship; feeds the user downloaded on this PC are
# copied into this machine's dist too (make_release.ps1 leaves them out of a release)
Rc "$P\yara_rules" (Join-Path $D "yara_rules") @("_downloaded")
Rc "$P\threat_intel_db\bundled" (Join-Path $D "threat_intel_db\bundled")
if (Test-Path "$P\threat_intel_db\downloaded") { Rc "$P\threat_intel_db\downloaded" (Join-Path $D "threat_intel_db\downloaded") }
New-Item -ItemType Directory -Force (Join-Path $D "config"), (Join-Path $D "output"), (Join-Path $D "logs"), (Join-Path $D "cache\vol3") | Out-Null
# Timing calibration: merge what the shipped exe learned (and its run logs) back
# into the project copy, re-fit, then ship - never overwrite learned runtimes.
& $PY (Join-Path $P "build_tools\backfill_timings.py") (Join-Path $D "output") "$P\config\timing_samples.jsonl" --merge (Join-Path $D "config\timing_samples.jsonl") --fit
if ($LASTEXITCODE -ne 0) { throw "timing calibration merge failed" }
Copy-Item "$P\config\timeouts.json", "$P\config\timing_samples.jsonl" (Join-Path $D "config") -Force
if (Test-Path "$P\cache\vol3\identifier.cache") {
    Step "Pre-built Vol3 symbol index (relocated on first run)"
    Copy-Item "$P\cache\vol3\identifier.cache" (Join-Path $D "cache\vol3") -Force
    [IO.File]::WriteAllText((Join-Path $D "cache\vol3\root.txt"), $P)
}
Copy-Item "$P\VERSIONS.md" $D -Force
if (Test-Path "$P\README.md") { Copy-Item "$P\README.md" $D -Force }
if (Test-Path "$P\DEFENDER.md") { Copy-Item "$P\DEFENDER.md" $D -Force }
New-Item -ItemType Directory -Force (Join-Path $D "licenses") | Out-Null
Copy-Item "$P\src\LICENSE" (Join-Path $D "licenses\RAMBreaker-LICENSE.txt") -Force
Copy-Item "$P\src\gui\icons\LICENSE-lucide.txt" (Join-Path $D "licenses") -Force
Copy-Item "$P\sigma_rules\sigmahq\LICENSE_DRL.txt" (Join-Path $D "licenses\SigmaHQ-DRL-1.1.txt") -Force
[IO.File]::WriteAllText((Join-Path $D "licenses\ThreatIntel-sources.txt"), "Threat-intel sources (RAMBreaker 2.2)`r`n`r`nBundled:`r`n- YARA Forge rule packages (https://github.com/YARAHQ/yara-forge), release 20261108. Each source repository's licence is kept in the header of its rule section inside yara_rules\yara-forge\*.yar (DRL 1.1, MIT, Apache-2.0, BSD, GPL-3.0, ...).`r`n- IPsum (https://github.com/stamparm/ipsum): Unlicense.`r`n- abuse.ch Feodo Tracker: CC0.`r`n`r`nNot bundled (downloaded to your PC only when you choose Update, for your own use under their terms):`r`n- Maltrail trails (https://github.com/stamparm/trails): Maltrail Trails Community Data License 1.0.`r`n- Spamhaus DROP, Emerging Threats compromised IPs, CINS Army, OpenPhish community feed.`r`n- abuse.ch ThreatFox / URLhaus / MalwareBazaar: abuse.ch terms of use, needs your own Auth-Key.`r`n")
if (Test-Path "$P\runtime\volatility3\LICENSE.txt") { Copy-Item "$P\runtime\volatility3\LICENSE.txt" (Join-Path $D "licenses\Volatility3-LICENSE.txt") -Force }
if (Test-Path "$P\runtime\volatility2\LICENSE.txt") { Copy-Item "$P\runtime\volatility2\LICENSE.txt" (Join-Path $D "licenses\Volatility2-LICENSE.txt") -Force }
[IO.File]::WriteAllText((Join-Path $D "rambreaker-cli.cmd"), "@echo off`r`n""%~dp0runtime\py3\python.exe"" -X utf8 ""%~dp0app\crescent_toolkit.py"" %*`r`n")

$size = (Get-ChildItem -Recurse $D -File | Measure-Object Length -Sum).Sum / 1GB
Step ("Done: {0}  ({1:N2} GB)" -f $D, $size)
