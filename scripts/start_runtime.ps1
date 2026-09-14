param([string]$Python = "python")

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$RuntimeRoot = Join-Path $RepoRoot "AgentMeter-Gov"
$env:AGENTMETER_GOV_HOME = $RuntimeRoot
Set-Location $RuntimeRoot
& $Python server.py
