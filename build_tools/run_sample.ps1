# Run ONE sample through the packaged exe (real GUI workflow) + report checks.
# Usage: run_sample.ps1 -Dump <path> [-Preset 0] [-IocList <file>]
param([Parameter(Mandatory)][string]$Dump, [int]$Preset = 0, [string]$IocList = "",
      [string]$KnownOs = "", [string]$Vol2Zip = "", [string]$ProfileName = "", [switch]$Extract)
if ($Extract) { $env:RB_E2E_EXTRACT = "1" } else { Remove-Item Env:RB_E2E_EXTRACT -ErrorAction SilentlyContinue }
if ($KnownOs) { $env:RB_E2E_OS = $KnownOs; $env:RB_E2E_V2ZIP = $Vol2Zip; $env:RB_E2E_PROFILE = $ProfileName }
$ErrorActionPreference = "Stop"
$P = Split-Path -Parent $PSScriptRoot
$D = Join-Path $P "dist\RAMBreaker"
$name = [IO.Path]::GetFileNameWithoutExtension($Dump) + "_" + ([IO.Path]::GetExtension($Dump).TrimStart("."))
$name = $name.TrimEnd("_")
$shots = Join-Path $P "screenshots\samples\$name"
$size = (Get-Item $Dump).Length
$free = (Get-PSDrive ([IO.Path]::GetPathRoot($D).Substring(0,1))).Free
if ($free -lt [Math]::Max(20GB, 3 * $size)) { throw "Not enough free disk: $([int]($free/1GB)) GB" }
New-Item -ItemType Directory -Force $shots | Out-Null
$exeArgs = @("--e2e", "`"$Dump`"", "`"$shots`"", "$Preset")
if ($IocList) { $exeArgs += "`"$IocList`"" }
$t = Measure-Command { $script:proc = Start-Process -FilePath (Join-Path $D "RAMBreaker.exe") -ArgumentList $exeArgs -PassThru -Wait }
$proc = $script:proc
"exe exit=$($proc.ExitCode) wall=$([int]$t.TotalSeconds)s"
$od = Join-Path $D "output\$name"
if (Test-Path (Join-Path $od "report.html")) {
    & (Join-Path $P "runtime\py3\Scripts\python.exe") (Join-Path $P "build_tools\report_check.py") (Join-Path $od "report.html") (Join-Path $shots "report") 2>&1 | Select-Object -First 30
} else { "NO report.html in $od" }
