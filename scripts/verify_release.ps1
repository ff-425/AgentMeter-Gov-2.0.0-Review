param(
    [string]$Python = "python",
    [string]$Node = "node",
    [string]$Npm = "npm",
    [switch]$CheckOpenClaw
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$RuntimeRoot = Join-Path $RepoRoot "AgentMeter-Gov"
$PluginRoot = Join-Path $RepoRoot "agentmeter-gov-openclaw-plugin"

function Invoke-Step {
    param([string]$Name, [scriptblock]$Command)
    Write-Host "`n==> $Name" -ForegroundColor Cyan
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Name failed with exit code $LASTEXITCODE"
    }
}

$previousLocation = Get-Location
$previousPython = $env:AGENTMETER_PYTHON
try {
    Set-Location $RepoRoot
    $pythonInfoText = & $Python -c 'import json, sys; print(json.dumps(dict(executable=sys.executable, version=list(sys.version_info[:3]))))'
    if ($LASTEXITCODE -ne 0) { throw "Cannot inspect Python interpreter: $Python" }
    $pythonInfo = ($pythonInfoText | Out-String) | ConvertFrom-Json
    if (-not $pythonInfo.executable -or $pythonInfo.version.Count -ne 3) {
        throw "Python interpreter returned invalid version information"
    }
    if ([version]($pythonInfo.version -join '.') -lt [version]'3.11') {
        throw "Python 3.11+ is required; selected $($pythonInfo.version -join '.')"
    }
    $Python = $pythonInfo.executable
    $env:AGENTMETER_PYTHON = $Python
    Write-Host "Python: $Python ($($pythonInfo.version -join '.'))"
    $version = (Get-Content (Join-Path $RepoRoot "VERSION") -Raw).Trim()
    $pluginVersion = (Get-Content (Join-Path $PluginRoot "package.json") -Raw | ConvertFrom-Json).version
    $manifestVersion = (Get-Content (Join-Path $PluginRoot "openclaw.plugin.json") -Raw | ConvertFrom-Json).version
    if ($version -ne "2.0.0" -or $pluginVersion -ne $version -or $manifestVersion -ne $version) {
        throw "Version mismatch: root=$version package=$pluginVersion manifest=$manifestVersion"
    }

    Invoke-Step "Python compile" { & $Python -m compileall -q (Join-Path $RuntimeRoot "agentmeter_gov") (Join-Path $RuntimeRoot "server.py") }

    foreach ($test in @(
        "test_server_controls.py",
        "test_production_controls.py",
        "test_live_evaluation_accounting.py",
        "run_security_defense_tests.py",
        "run_gov_scenario_regression.py",
        "test_evaluation_metrics.py",
        "test_evaluation_log_rotation.py",
        "test_batch_meter.py",
        "test_holdout_regressions.py",
        "test_security_config_tamper.py",
        "test_586_live_findings.py",
        "test_scope_over_vocabulary.py",
        "test_live_eval_contract.py",
        "test_external_full_eval_contract.py",
        "test_external_eval_analysis.py",
        "test_v6_full_eval_findings.py",
        "test_p0_trust_boundary_and_blast_radius.py",
        "test_shadowed_definitions.py"
    )) {
        Invoke-Step $test { & $Python (Join-Path $RuntimeRoot "scripts\$test") }
    }

    foreach ($test in @('test_review_monitoring.py', 'test_invalid_monitor_events.py', 'test_boot_monitoring.py', 'test_risk_display_context.py', 'test_monitor_performance.py', 'test_gate_performance.py', 'test_semantic_performance.py', 'test_network_commands.py')) {
        Invoke-Step $test { & $Python (Join-Path $RuntimeRoot "tests\$test") }
    }

    Invoke-Step "OpenClaw plugin tests" { & $Npm --prefix $PluginRoot test }
    Invoke-Step "Execution outcome regressions" { & $Npm --prefix $PluginRoot run test:execution }
    Invoke-Step "Plugin-backend integration replay" { & $Npm --prefix $PluginRoot run test:integration }
    Invoke-Step "Monitoring frontend model tests" { & $Node (Join-Path $RuntimeRoot "frontend\monitor-model.test.cjs") }
    Invoke-Step "Monitoring compact transport tests" { & $Node (Join-Path $RuntimeRoot "frontend\monitor-transport.test.cjs") }
    Invoke-Step "Task risk aggregation tests" { & $Node (Join-Path $RuntimeRoot "frontend\task-risk.test.cjs") }
    Invoke-Step "Fixed demo cases" { & $Python (Join-Path $RuntimeRoot "scripts\run_demo.py") }
    Invoke-Step "Output redaction demo" { & $Node (Join-Path $PluginRoot "demo-output-redaction.mjs") }

    if ($CheckOpenClaw) {
        Invoke-Step "OpenClaw configuration" { & openclaw config validate }
        Write-Host "`n==> OpenClaw health" -ForegroundColor Cyan
        $healthText = (& openclaw health --json | Out-String)
        if ($LASTEXITCODE -ne 0) { throw "OpenClaw health command failed" }
        $health = $healthText | ConvertFrom-Json
        if (-not $health.ok) { throw "OpenClaw health is not ok" }
        $serialized = $health | ConvertTo-Json -Depth 20
        if ($serialized -notmatch "agentmeter-gov-guard") {
            throw "agentmeter-gov-guard was not found in OpenClaw health output"
        }
        Write-Host "`n==> Installed plugin version" -ForegroundColor Cyan
        $pluginsText = (& openclaw plugins list --json | Out-String)
        if ($LASTEXITCODE -ne 0) { throw "OpenClaw plugin listing failed" }
        $plugins = $pluginsText | ConvertFrom-Json
        $guard = $plugins.plugins | Where-Object id -eq "agentmeter-gov-guard"
        if (-not $guard -or $guard.status -ne "loaded" -or $guard.version -ne $version) {
            throw "Expected loaded agentmeter-gov-guard $version, observed $($guard.version) / $($guard.status)"
        }
        Write-Host "`n==> Auto-started AgentMeter-Gov backend" -ForegroundColor Cyan
        $backendHealth = Invoke-RestMethod -Uri "http://127.0.0.1:8765/health" -TimeoutSec 5
        if ($backendHealth.status -ne "ok" -or $backendHealth.version -ne $version) {
            throw "Expected auto-started AgentMeter-Gov $version, observed $($backendHealth.version) / $($backendHealth.status)"
        }
        Invoke-Step "Actual local OpenClaw acceptance" {
            & (Join-Path $PSScriptRoot "test_openclaw_live_acceptance.ps1") -OpenClaw "openclaw"
        }
    }

    Write-Host "`nAgentMeter-Gov $version release verification passed." -ForegroundColor Green
} finally {
    $env:AGENTMETER_PYTHON = $previousPython
    Set-Location $previousLocation
}
