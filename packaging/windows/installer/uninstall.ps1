[CmdletBinding()]
param(
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA "AgentMeter-Gov\current"),
    [string]$ArchiveParent = (Join-Path $env:LOCALAPPDATA "AgentMeter-Gov-Archive"),
    [switch]$PurgeData
)

$ErrorActionPreference = "Stop"
$ProductVersion = "2.0.0"
$PluginId = "agentmeter-gov-guard"
$ProductRoot = [System.IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA "AgentMeter-Gov"))
$InstallRoot = [System.IO.Path]::GetFullPath($InstallRoot)
$AllowedInstallRoot = Join-Path $ProductRoot "current"
$StatePath = Join-Path $ProductRoot "install-state.json"
$BackendExecutable = Join-Path $InstallRoot "backend\AgentMeterGovBackend.exe"
$DesktopPetScript = Join-Path $InstallRoot "desktop\start_desktop_pet.ps1"
$DesktopPetLauncher = Join-Path $InstallRoot "desktop\launch_desktop_pet.ps1"
$DesktopPetVbsLauncher = Join-Path $InstallRoot "desktop\launch_desktop_pet.vbs"
$DefaultAutoStartRegistryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$DefaultAutoStartValueName = "AgentMeterGovDesktopPet"
$script:OpenClawCommand = $null

function Write-Step([string]$Message) {
    Write-Host "[AgentMeter-Gov] $Message" -ForegroundColor Cyan
}

function Invoke-OpenClaw([string[]]$ArgumentList, [switch]$AllowFailure) {
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        & $script:OpenClawCommand @ArgumentList 2>&1 | Out-Host
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    if ($exitCode -ne 0 -and -not $AllowFailure) {
        throw "OpenClaw command failed (exit $exitCode): openclaw $($ArgumentList -join ' ')"
    }
    return $exitCode
}

function Remove-DesktopPetShortcut([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($Path)
    $identity = "$($shortcut.TargetPath) $($shortcut.Arguments)"
    if ($identity.IndexOf($InstallRoot, [System.StringComparison]::OrdinalIgnoreCase) -lt 0 -or
        ($identity.IndexOf($DesktopPetScript, [System.StringComparison]::OrdinalIgnoreCase) -lt 0 -and
         $identity.IndexOf($DesktopPetLauncher, [System.StringComparison]::OrdinalIgnoreCase) -lt 0 -and
         $identity.IndexOf($DesktopPetVbsLauncher, [System.StringComparison]::OrdinalIgnoreCase) -lt 0)) {
        Write-Warning "Shortcut was not removed because it does not belong to this AgentMeter-Gov installation: $Path"
        return
    }
    Remove-Item -LiteralPath $Path -Force
    $parent = Split-Path $Path -Parent
    if ($parent -and (Split-Path $parent -Leaf) -eq "AgentMeter-Gov") {
        $remaining = Get-ChildItem -LiteralPath $parent -Force -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $remaining) { Remove-Item -LiteralPath $parent -Force }
    }
}

function Remove-DesktopPetAutoStart([string]$RegistryPath, [string]$ValueName) {
    if ([string]::IsNullOrWhiteSpace($RegistryPath) -or [string]::IsNullOrWhiteSpace($ValueName)) { return }
    if (-not (Test-Path -LiteralPath $RegistryPath)) { return }
    $command = Get-ItemPropertyValue -LiteralPath $RegistryPath -Name $ValueName -ErrorAction SilentlyContinue
    if (-not $command) { return }
    if ($command.IndexOf($InstallRoot, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        Write-Warning "The auto-start entry was not removed because it no longer belongs to this installation."
        return
    }
    Remove-ItemProperty -LiteralPath $RegistryPath -Name $ValueName -Force
    if ($RegistryPath -eq $DefaultAutoStartRegistryPath -and $ValueName -eq $DefaultAutoStartValueName) {
        $startupApprovalPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
        Remove-ItemProperty -LiteralPath $startupApprovalPath -Name $ValueName -ErrorAction SilentlyContinue
    }
}

function Copy-AuditTree([string]$Source, [string]$Destination) {
    $sourceRoot = [System.IO.Path]::GetFullPath($Source).TrimEnd('\')
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    foreach ($directory in Get-ChildItem -LiteralPath $sourceRoot -Directory -Recurse -Force) {
        $relativePath = $directory.FullName.Substring($sourceRoot.Length).TrimStart('\')
        New-Item -ItemType Directory -Path (Join-Path $Destination $relativePath) -Force | Out-Null
    }
    foreach ($file in Get-ChildItem -LiteralPath $sourceRoot -File -Recurse -Force) {
        $relativePath = $file.FullName.Substring($sourceRoot.Length).TrimStart('\')
        $destinationFile = Join-Path $Destination $relativePath
        $destinationParent = Split-Path $destinationFile -Parent
        if (-not (Test-Path -LiteralPath $destinationParent)) {
            New-Item -ItemType Directory -Path $destinationParent -Force | Out-Null
        }
        # Stream the plaintext content instead of asking Copy-Item to preserve
        # the source EFS attribute. This also works when the install directory
        # is encrypted but the chosen archive directory is not.
        $sourceStream = [System.IO.File]::Open($file.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            $destinationStream = [System.IO.File]::Open($destinationFile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            try {
                $sourceStream.CopyTo($destinationStream)
            } finally {
                $destinationStream.Dispose()
            }
        } finally {
            $sourceStream.Dispose()
        }
    }
}

try {
    if (-not $InstallRoot.Equals($AllowedInstallRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Uninstall refused: the target is not the fixed AgentMeter-Gov current directory."
    }
    if (-not (Test-Path -LiteralPath $StatePath -PathType Leaf)) {
        throw "A valid AgentMeter-Gov install marker was not found. No files were deleted."
    }
    $state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
    if ($state.product -ne "AgentMeter-Gov" -or $state.version -ne $ProductVersion -or
        -not ([string]$state.install_root).Equals($InstallRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "The AgentMeter-Gov $ProductVersion install marker does not match. No files were deleted."
    }

    $shortcutPaths = @()
    if ($state.shortcuts) {
        if ($state.shortcuts.desktop) { $shortcutPaths += [string]$state.shortcuts.desktop }
        if ($state.shortcuts.start_menu) { $shortcutPaths += [string]$state.shortcuts.start_menu }
    }
    $desktop = [Environment]::GetFolderPath([Environment+SpecialFolder]::Desktop)
    if ($desktop) {
        $shortcutPaths += (Join-Path $desktop "AgentMeter-Gov 桌面巡检宠物.lnk")
        $shortcutPaths += (Join-Path $desktop "AgentMeter-Gov 监控中心.url")
    }

    $autoStartRegistryPath = $DefaultAutoStartRegistryPath
    $autoStartValueName = $DefaultAutoStartValueName
    if ($state.desktop_pet_autostart) {
        if ($state.desktop_pet_autostart.registry_path) { $autoStartRegistryPath = [string]$state.desktop_pet_autostart.registry_path }
        if ($state.desktop_pet_autostart.value_name) { $autoStartValueName = [string]$state.desktop_pet_autostart.value_name }
    }

    Write-Step "Removing the desktop pet auto-start entry..."
    Remove-DesktopPetAutoStart $autoStartRegistryPath $autoStartValueName

    $openClaw = Get-Command openclaw -ErrorAction SilentlyContinue
    if ($openClaw) {
        $script:OpenClawCommand = $openClaw.Source
        Write-Step "Stopping the Gateway and removing only the AgentMeter-Gov plugin..."
        Invoke-OpenClaw @("gateway", "stop") -AllowFailure | Out-Null
        Start-Sleep -Milliseconds 800
        Invoke-OpenClaw @("plugins", "uninstall", $PluginId, "--force") -AllowFailure | Out-Null
    } else {
        Write-Warning "OpenClaw was not found. Only AgentMeter-Gov files and shortcuts will be removed."
    }

    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        ($_.ExecutablePath -and $_.ExecutablePath.Equals($BackendExecutable, [System.StringComparison]::OrdinalIgnoreCase)) -or
        ($_.CommandLine -and $_.CommandLine.IndexOf($DesktopPetVbsLauncher, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) -or
        ($_.CommandLine -and $_.CommandLine.IndexOf($DesktopPetLauncher, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) -or
        ($_.CommandLine -and $_.CommandLine.IndexOf($DesktopPetScript, [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
    } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

    $archiveRoot = $null
    if (-not $PurgeData) {
        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $archiveRoot = Join-Path ([System.IO.Path]::GetFullPath($ArchiveParent)) $timestamp
        $dataSource = Join-Path $InstallRoot "backend\_internal\data"
        $reportSource = Join-Path $InstallRoot "backend\_internal\audit_reports"
        if ((Test-Path -LiteralPath $dataSource) -or (Test-Path -LiteralPath $reportSource)) {
            Write-Step "Preserving audit data at $archiveRoot"
            New-Item -ItemType Directory -Path $archiveRoot -Force | Out-Null
            if (Test-Path -LiteralPath $dataSource) { Copy-AuditTree $dataSource (Join-Path $archiveRoot "data") }
            if (Test-Path -LiteralPath $reportSource) { Copy-AuditTree $reportSource (Join-Path $archiveRoot "audit_reports") }
        }
    }

    Write-Step "Removing obsolete AgentMeter-Gov desktop pet shortcuts..."
    foreach ($shortcutPath in $shortcutPaths) { Remove-DesktopPetShortcut $shortcutPath }

    Write-Step "Removing AgentMeter-Gov program files..."
    Start-Sleep -Milliseconds 300
    Remove-Item -LiteralPath $InstallRoot -Recurse -Force
    Remove-Item -LiteralPath $StatePath -Force

    if ($openClaw) { Invoke-OpenClaw @("gateway", "start") -AllowFailure | Out-Null }

    Write-Host ""
    Write-Host "AgentMeter-Gov $ProductVersion was uninstalled." -ForegroundColor Green
    if ($archiveRoot) { Write-Host "Audit data was preserved at: $archiveRoot" }
    elseif ($PurgeData) { Write-Host "Audit data was purged because -PurgeData was explicitly supplied." }
    exit 0
} catch {
    Write-Host ""
    Write-Host "Uninstall failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
