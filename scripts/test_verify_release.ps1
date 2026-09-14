$ErrorActionPreference = 'Stop'
$originalPython = $env:AGENTMETER_PYTHON
$originalLocation = Get-Location

function Test-PythonAlias {
    $global:ReleaseTest.probes++
    $global:LASTEXITCODE = 0
    @{ executable = 'Test-SelectedPython'; version = $global:ReleaseTest.version } | ConvertTo-Json -Compress
}

function Test-SelectedPython {
    if ($env:AGENTMETER_PYTHON -ne 'Test-SelectedPython') { throw 'Python child did not receive selected executable' }
    $global:ReleaseTest.python++
    $global:LASTEXITCODE = 0
}

function Test-Node {
    if ($env:AGENTMETER_PYTHON -ne 'Test-SelectedPython') { throw 'Node did not inherit selected executable' }
    $global:ReleaseTest.node++
    $global:LASTEXITCODE = 0
}

function Test-Npm {
    if ($env:AGENTMETER_PYTHON -ne 'Test-SelectedPython') { throw 'npm did not inherit selected executable' }
    $global:ReleaseTest.npm++
    $global:LASTEXITCODE = $(if ($global:ReleaseTest.failNpm) { 9 } else { 0 })
}

try {
    foreach ($prior in @($null, 'prior-interpreter')) {
        foreach ($mode in @('success', 'unsupported', 'child-failure')) {
            $env:AGENTMETER_PYTHON = $prior
            $global:ReleaseTest = @{ probes = 0; python = 0; node = 0; npm = 0; version = @(3, 12, 14); failNpm = $mode -eq 'child-failure' }
            if ($mode -eq 'unsupported') { $global:ReleaseTest.version = @(3, 8, 0) }
            $failure = $null
            try {
                & (Join-Path $PSScriptRoot 'verify_release.ps1') -Python Test-PythonAlias -Node Test-Node -Npm Test-Npm
            } catch { $failure = $_.Exception.Message }
            if ($env:AGENTMETER_PYTHON -ne $prior) { throw "Environment not restored: $mode" }
            if ((Get-Location).Path -ne $originalLocation.Path) { throw "Location not restored: $mode" }
            if ($global:ReleaseTest.probes -ne 1) { throw 'Interpreter alias must be resolved exactly once' }
            if ($mode -eq 'success') {
                if ($failure) { throw $failure }
                if ($global:ReleaseTest.python -lt 10 -or $global:ReleaseTest.npm -ne 2 -or $global:ReleaseTest.node -ne 3) { throw 'Expected Python, npm and Node steps were not exercised' }
            } elseif ($mode -eq 'unsupported') {
                if ($failure -notlike '*Python 3.11+ is required*' -or $global:ReleaseTest.python -ne 0 -or $global:ReleaseTest.npm -ne 0) { throw 'Unsupported Python did not fail before tests' }
            } elseif ($failure -notlike '*failed with exit code 9*') { throw 'Child failure was not propagated' }
            Write-Host "PASS: $mode; prior interpreter='$prior'"
        }
    }
} finally {
    $env:AGENTMETER_PYTHON = $originalPython
    Set-Location $originalLocation
    Remove-Variable ReleaseTest -Scope Global -ErrorAction SilentlyContinue
}
