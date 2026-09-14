param()

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$sourceRuntimeRoot = Join-Path $repoRoot "AgentMeter-Gov"
$packagedRuntimeRoot = Join-Path $repoRoot "backend\_internal"
$packagedBackend = Join-Path $repoRoot "backend\AgentMeterGovBackend.exe"
$isPackagedInstall = Test-Path -LiteralPath $packagedBackend -PathType Leaf
$runtimeRoot = if ($isPackagedInstall) { $packagedRuntimeRoot } else { $sourceRuntimeRoot }
$serviceBaseUrl = "http://127.0.0.1:8765"
$serviceUrlFile = Join-Path $PSScriptRoot "service-base-url.txt"
if (Test-Path -LiteralPath $serviceUrlFile -PathType Leaf) {
    $configuredServiceUrl = (Get-Content -LiteralPath $serviceUrlFile -Raw).Trim().TrimEnd("/")
    if ($configuredServiceUrl -match '^http://(127\.0\.0\.1|localhost|\[::1\]):\d+$') {
        $serviceBaseUrl = $configuredServiceUrl
    }
}
$pageUrl = "$serviceBaseUrl/security-layer.html"
$healthUrl = "$serviceBaseUrl/health"
$petLauncher = Join-Path $PSScriptRoot "launch_desktop_pet.vbs"

# 安全层启动时同时唤起桌面宠物；宠物自身带单实例保护，不会重复显示。
if (Test-Path -LiteralPath $petLauncher) {
    Start-Process -FilePath "$env:SystemRoot\System32\wscript.exe" `
        -ArgumentList @("`"$petLauncher`"") -WindowStyle Hidden
}

# The backend answers /health in roughly 0.6s even when idle, and slower while
# it is recording audit events. A single one-second probe therefore reports a
# healthy-but-busy service as an outage, which used to restart the gateway and
# then show a startup-failure dialog. Probe with a realistic timeout and retry
# before concluding the service is actually down.
function Test-AgentMeterService {
    param([int]$Attempts = 3, [int]$TimeoutSeconds = 5)
    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri $healthUrl -TimeoutSec $TimeoutSeconds
            if ($response.StatusCode -eq 200) { return $true }
        }
        catch { }
        if ($attempt -lt $Attempts) { Start-Sleep -Milliseconds 400 }
    }
    return $false
}

function Get-CompatiblePython {
    $candidates = @()

    # Prefer the Windows Python launcher because `python.exe` on PATH can point
    # to an older installation or to the Microsoft Store placeholder.
    $pyLauncher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($pyLauncher) {
        try {
            $launcherPython = & $pyLauncher.Source -3 -c "import sys; print(sys.executable)" 2>$null
            if ($LASTEXITCODE -eq 0 -and $launcherPython) {
                $candidates += ($launcherPython | Select-Object -Last 1).Trim()
            }
        }
        catch { }
    }

    $candidates += Get-Command python.exe -All -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty Source

    foreach ($candidate in $candidates | Select-Object -Unique) {
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
        try {
            & $candidate -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)" 2>$null
            if ($LASTEXITCODE -eq 0) { return $candidate }
        }
        catch { }
    }

    return $null
}

if (-not (Test-AgentMeterService)) {
    if ($isPackagedInstall) {
        $openClaw = Get-Command openclaw -ErrorAction SilentlyContinue
        if ($openClaw) {
            & $openClaw.Source gateway restart | Out-Null
        }
    } else {
        $pythonExe = Get-CompatiblePython
        if (-not $pythonExe) {
            Add-Type -AssemblyName PresentationFramework
            [System.Windows.MessageBox]::Show(
                "Python 3.9 or newer was not found. Please install a current Python 3 release and try again.",
                "AgentMeter-Gov startup failed",
                "OK",
                "Error"
            ) | Out-Null
            exit 1
        }

        $env:AGENTMETER_GOV_HOME = $runtimeRoot
        Start-Process -FilePath $pythonExe -ArgumentList @("server.py") -WorkingDirectory $runtimeRoot -WindowStyle Hidden
    }

    # Poll with a single probe per iteration; the retry budget above already
    # covers a busy backend, and nesting retries here would stretch one poll to
    # tens of seconds.
    $ready = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        Start-Sleep -Milliseconds 500
        if (Test-AgentMeterService -Attempts 1 -TimeoutSeconds 3) {
            $ready = $true
            break
        }
    }

    if (-not $ready) {
        Add-Type -AssemblyName PresentationFramework
        [System.Windows.MessageBox]::Show(
            "The local service did not start. Please check the AgentMeter-Gov installation diagnostics.",
            "AgentMeter-Gov startup failed",
            "OK",
            "Error"
        ) | Out-Null
        exit 1
    }
}

Start-Process $pageUrl
