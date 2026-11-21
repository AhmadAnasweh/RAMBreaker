# Start one CLI run in its own hidden console, detached from the calling shell, and return at once.
# usage: run_detached.ps1 -Log <file> -CliArgs "core -i ... -o ..."
# The log ends with a line "exit=<code>" when the run is over.
param([Parameter(Mandatory)][string]$Log, [Parameter(Mandatory)][string]$CliArgs)
$root = Split-Path -Parent $PSScriptRoot
$py = Join-Path $root "runtime\py3\Scripts\python.exe"
$bat = [IO.Path]::ChangeExtension($Log, ".cmd")
$lines = @("@echo off", "cd /d `"$(Join-Path $root 'src')`"",
           "`"$py`" crescent_toolkit.py $CliArgs > `"$Log`" 2>&1",
           "echo exit=%ERRORLEVEL%>> `"$Log`"")
[IO.File]::WriteAllLines($bat, $lines, (New-Object Text.UTF8Encoding($false)))
$p = Start-Process -FilePath $env:ComSpec -ArgumentList "/c `"$bat`"" -WindowStyle Hidden -PassThru
"started pid $($p.Id)"
