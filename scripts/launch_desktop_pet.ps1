param([switch]$HiddenChild)

$ErrorActionPreference = "Stop"
$petScript = Join-Path $PSScriptRoot "start_desktop_pet.ps1"
$logRoot = Join-Path $env:LOCALAPPDATA "AgentMeter-Gov"
$logPath = Join-Path $logRoot "desktop-pet-startup.log"

# A user may launch this script from Explorer, a shortcut, or a visible terminal.
# Detach immediately into a hidden PowerShell process so closing the original
# console cannot terminate the WPF desktop pet.
if (-not $HiddenChild) {
    $powerShell = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
    Start-Process -FilePath $powerShell `
        -ArgumentList @("-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", "`"$PSCommandPath`"", "-HiddenChild") `
        -WorkingDirectory $PSScriptRoot -WindowStyle Hidden | Out-Null
    exit 0
}

function Write-StartupFailure([System.Exception]$Exception, [int]$Attempt) {
    try {
        New-Item -ItemType Directory -Path $logRoot -Force | Out-Null
        $message = "{0:o} attempt={1} error={2}" -f (Get-Date), $Attempt, $Exception.Message
        Add-Content -LiteralPath $logPath -Value $message -Encoding UTF8
    } catch { }
}

# The Run key can be processed while Explorer is still initializing on slower
# computers. Wait briefly for the interactive desktop before creating the WPF
# window, otherwise the pet can start without becoming visible.
for ($waitAttempt = 0; $waitAttempt -lt 20; $waitAttempt += 1) {
    if (Get-Process explorer -ErrorAction SilentlyContinue) { break }
    Start-Sleep -Seconds 1
}
Start-Sleep -Seconds 3

if (-not (Test-Path -LiteralPath $petScript -PathType Leaf)) {
    Write-StartupFailure ([System.IO.FileNotFoundException]::new("Desktop pet script not found: $petScript")) 1
    exit 1
}

for ($attempt = 1; $attempt -le 3; $attempt += 1) {
    try {
        & $petScript
        exit 0
    } catch {
        Write-StartupFailure $_.Exception $attempt
        if ($attempt -lt 3) { Start-Sleep -Seconds 5 }
    }
}

exit 1
