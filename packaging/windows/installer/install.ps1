[CmdletBinding()]
param(
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA "AgentMeter-Gov\current"),
    [switch]$SkipGatewayRestart,
    [string]$DesktopShortcutPath,
    [string]$StartMenuShortcutPath,
    # Historic name: this switch has only ever gated launching the desktop pet,
    # never opening a page. Kept so existing callers keep working.
    [switch]$SkipOpenMonitoringPage,
    [switch]$SkipDesktopPetLaunch,
    [int]$GatewayReadyTimeoutSeconds = 30,
    [int]$BackendReadyTimeoutSeconds = 60,
    [string]$ServiceBaseUrl = "http://127.0.0.1:8765",
    [int]$InitialGatewayWaitSeconds = 8,
    [string]$AutoStartRegistryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    [string]$AutoStartValueName = "AgentMeterGovDesktopPet"
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$ProductVersion = "2.0.0"
$MinimumOpenClawVersion = [version]"2026.6.5"
$PluginId = "agentmeter-gov-guard"
$PackageRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$PayloadRoot = Join-Path $PackageRoot "payload"
$BackendSource = Join-Path $PayloadRoot "backend"
$BackendSourceExecutable = Join-Path $BackendSource "AgentMeterGovBackend.exe"
$PluginSource = Join-Path $PayloadRoot "plugin"
$DesktopSource = Join-Path $PayloadRoot "desktop"
$ManifestPath = Join-Path $PackageRoot "package-manifest.json"
$ProductRoot = [System.IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA "AgentMeter-Gov"))
$InstallRoot = [System.IO.Path]::GetFullPath($InstallRoot)
$AllowedInstallRoot = Join-Path $ProductRoot "current"
$BackendTarget = Join-Path $InstallRoot "backend"
$PluginTarget = Join-Path $InstallRoot "plugin"
$DesktopTarget = Join-Path $InstallRoot "desktop"
$DesktopPetVbsLauncher = Join-Path $DesktopTarget "launch_desktop_pet.vbs"
$RuntimeDir = Join-Path $BackendTarget "_internal"
$StatePath = Join-Path $ProductRoot "install-state.json"
$ServiceBaseUrl = $ServiceBaseUrl.TrimEnd("/")
$RequestedServiceBaseUrl = $ServiceBaseUrl
$MonitoringUrl = "$ServiceBaseUrl/security-layer.html"
$HealthUrl = "$ServiceBaseUrl/health"
$LegacyMonitoringUrl = "http://127.0.0.1:8765"
$LegacyDesktopShortcutPath = ""
$LegacyStartMenuShortcutPath = ""
$LegacyDesktopPetShortcutPath = ""
$OpenClawConfigPath = Join-Path $env:USERPROFILE ".openclaw\openclaw.json"
$OpenClawPluginPath = Join-Path $env:USERPROFILE ".openclaw\extensions\$PluginId"
$TransactionId = (Get-Date -Format "yyyyMMdd-HHmmss") + "-" + [guid]::NewGuid().ToString("N").Substring(0, 8)
$StageRoot = Join-Path $ProductRoot ".staging-$TransactionId"
$RollbackRoot = Join-Path $ProductRoot ".rollback-$TransactionId"
$BackupRoot = Join-Path $ProductRoot "backups\$TransactionId"
$ConfigBackupPath = Join-Path $BackupRoot "openclaw.json.before"
$PluginBackupPath = Join-Path $BackupRoot "plugin-before"
$StateBackupPath = Join-Path $BackupRoot "install-state.json.before"
$PreflightPath = Join-Path $BackupRoot "plugin-preflight.json"
$script:OpenClawCommand = $null
$script:PreviousCurrentMoved = $false
$script:GatewayWasReady = $false
$script:TransactionStarted = $false
$script:PetWasRunning = $false

if (-not $InstallRoot.Equals($AllowedInstallRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "AgentMeter-Gov 2.0.0 uses the fixed upgrade directory: $AllowedInstallRoot"
}

if ([string]::IsNullOrWhiteSpace($DesktopShortcutPath)) {
    $desktop = [Environment]::GetFolderPath([Environment+SpecialFolder]::Desktop)
    if ($desktop) {
        $DesktopShortcutPath = Join-Path $desktop "AgentMeter-Gov 桌宠.lnk"
        $LegacyDesktopShortcutPath = Join-Path $desktop "AgentMeter-Gov 监控中心.url"
        $LegacyDesktopPetShortcutPath = Join-Path $desktop "AgentMeter-Gov 桌面巡检宠物.lnk"
    }
}
if ([string]::IsNullOrWhiteSpace($StartMenuShortcutPath)) {
    $programs = [Environment]::GetFolderPath([Environment+SpecialFolder]::Programs)
    if ($programs) {
        $StartMenuShortcutPath = Join-Path $programs "AgentMeter-Gov\AgentMeter-Gov 桌宠.lnk"
        $LegacyStartMenuShortcutPath = Join-Path $programs "AgentMeter-Gov\AgentMeter-Gov 监控中心.url"
    }
}
if ($DesktopShortcutPath -and -not $LegacyDesktopShortcutPath) {
    $desktopParent = Split-Path $DesktopShortcutPath -Parent
    $LegacyDesktopShortcutPath = Join-Path $desktopParent "AgentMeter-Gov 监控中心.url"
    $LegacyDesktopPetShortcutPath = Join-Path $desktopParent "AgentMeter-Gov 桌面巡检宠物.lnk"
}
if ($StartMenuShortcutPath -and -not $LegacyStartMenuShortcutPath) {
    $LegacyStartMenuShortcutPath = Join-Path (Split-Path $StartMenuShortcutPath -Parent) "AgentMeter-Gov 监控中心.url"
}
$startupFolder = [Environment]::GetFolderPath([Environment+SpecialFolder]::Startup)
$legacyEntryPaths = @(
    $DesktopShortcutPath,
    $StartMenuShortcutPath,
    $LegacyDesktopShortcutPath,
    $LegacyStartMenuShortcutPath,
    $LegacyDesktopPetShortcutPath
)
if ($desktop) {
    $legacyEntryPaths += Join-Path $desktop "AgentMeter-Gov 安全审计平台.lnk"
}
if ($startupFolder) {
    $legacyEntryPaths += Join-Path $startupFolder "AgentMeter-Gov 桌面巡检宠物.lnk"
    $legacyEntryPaths += Join-Path $startupFolder "AgentMeter-Gov 桌宠.lnk"
}

function Write-Step([string]$Message) {
    Write-Host "[AgentMeter-Gov] $Message" -ForegroundColor Cyan
}

function Assert-ProductPath([string]$Path) {
    $resolved = [System.IO.Path]::GetFullPath($Path)
    if (-not $resolved.StartsWith($ProductRoot + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to modify a path outside the AgentMeter-Gov product directory: $resolved"
    }
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

function Invoke-OpenClawCapture([string[]]$ArgumentList, [switch]$AllowFailure) {
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $text = (& $script:OpenClawCommand @ArgumentList 2>&1 | Out-String)
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    if ($exitCode -ne 0 -and -not $AllowFailure) {
        throw "OpenClaw command failed (exit $exitCode): openclaw $($ArgumentList -join ' ')`n$text"
    }
    return [pscustomobject]@{ ExitCode = $exitCode; Text = $text.Trim() }
}

function Set-OpenClawString([string]$Path, [string]$Value) {
    Invoke-OpenClaw @("config", "set", $Path, $Value) | Out-Null
}

function Set-OpenClawJson([string]$Path, [string]$JsonValue) {
    Invoke-OpenClaw @("config", "set", $Path, $JsonValue, "--strict-json") | Out-Null
}

function Ensure-AgentMeterPluginPolicy {
    if (Test-Path -LiteralPath $OpenClawConfigPath -PathType Leaf) {
        try {
            $config = Get-Content -LiteralPath $OpenClawConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
            $allowProperty = $null
            if ($null -ne $config -and $null -ne $config.plugins) {
                $allowProperty = $config.plugins.PSObject.Properties["allow"]
            }
            if ($allowProperty) {
                $allow = @($allowProperty.Value | Where-Object { $_ -is [string] -and -not [string]::IsNullOrWhiteSpace($_) })
                if ($allow -notcontains $PluginId) {
                    $allow += $PluginId
                    $uniqueAllow = @($allow | Select-Object -Unique)
                    Set-OpenClawJson "plugins.allow" (ConvertTo-Json -InputObject $uniqueAllow -Compress)
                }
            }
        } catch {
            throw "Could not safely preserve the OpenClaw plugin allowlist: $($_.Exception.Message)"
        }
    }
    # OpenClaw denies prompt mutation for non-bundled plugins unless the user
    # explicitly grants it. AgentMeter uses one short-lived, review-ID-bound
    # heartbeat prompt contribution only after a verified human approval. This
    # lets mobile approvals resume the exact paused action without asking the
    # user to send the original request again.
    Set-OpenClawJson "plugins.entries.$PluginId.hooks.allowPromptInjection" "true"
    Set-OpenClawJson "plugins.entries.$PluginId.hooks.allowConversationAccess" "true"
    Set-OpenClawJson "plugins.entries.$PluginId.hooks.timeoutMs" "60000"
}

function Get-OpenClawVersion {
    $result = Invoke-OpenClawCapture @("--version")
    $match = [regex]::Match($result.Text, "(?<version>\d{4}\.\d+\.\d+)")
    if (-not $match.Success) { throw "Could not determine the installed OpenClaw version: $($result.Text)" }
    return [version]$match.Groups["version"].Value
}

function Assert-PreflightConfiguration {
    $validation = Invoke-OpenClawCapture @("config", "validate") -AllowFailure
    if ($validation.ExitCode -eq 0) { return }

    # A partially installed older AgentMeter-Gov release can fail validation solely
    # because its plugin API floor is newer than the current OpenClaw kernel.  The
    # transaction replaces that plugin immediately, so this one known condition is
    # safe to repair.  Every unrelated configuration error remains a hard stop.
    $mentionsAgentMeter = $validation.Text -match "(?i)agentmeter-gov-(guard|openclaw-plugin)"
    $isCompatibilityFailure = $validation.Text -match "(?i)(pluginapi|min(?:imum)?\s*gateway|compatib|version\s*(?:require|mismatch|unsupported))"
    if ($mentionsAgentMeter -and $isCompatibilityFailure) {
        Write-Warning "The previous AgentMeter-Gov plugin is incompatible with this OpenClaw version; setup will replace it transactionally."
        return
    }
    throw "OpenClaw configuration is invalid before installation. Repair it first; AgentMeter-Gov will not alter unrelated configuration.`n$($validation.Text)"
}

function Get-PluginSnapshot {
    $result = Invoke-OpenClawCapture @("plugins", "list", "--json")
    try { $snapshot = $result.Text | ConvertFrom-Json } catch {
        throw "OpenClaw returned an invalid plugin inventory. Existing plugins may already be broken: $($_.Exception.Message)"
    }
    return $snapshot
}

function Get-UnhealthyUnrelatedPlugins($Snapshot) {
    return @($Snapshot.plugins | Where-Object {
        $_.id -ne $PluginId -and $_.enabled -eq $true -and $_.status -ne "loaded"
    })
}

function Assert-UnrelatedPluginsUnchanged($Before, $After) {
    $afterById = @{}
    foreach ($plugin in @($After.plugins)) { $afterById[[string]$plugin.id] = $plugin }
    $changes = @()
    foreach ($plugin in @($Before.plugins)) {
        if ($plugin.id -eq $PluginId) { continue }
        $current = $afterById[[string]$plugin.id]
        if (-not $current) {
            $changes += "$($plugin.id): missing after install"
        } elseif ([bool]$current.enabled -ne [bool]$plugin.enabled) {
            $changes += "$($plugin.id): enabled $($plugin.enabled) -> $($current.enabled)"
        } elseif ($plugin.status -eq "loaded" -and $current.status -ne "loaded") {
            $changes += "$($plugin.id): status loaded -> $($current.status)"
        }
    }
    if ($changes.Count -gt 0) {
        throw "Unrelated plugin state changed; rolling back: $($changes -join '; ')"
    }
}

function Test-GatewayReady {
    $status = Invoke-OpenClawCapture @("gateway", "status") -AllowFailure
    return $status.Text -match "(?im)(connectivity|rpc)\s+probe\s*:\s*ok"
}

function Wait-GatewayReady([int]$TimeoutSeconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds([Math]::Max(5, $TimeoutSeconds))
    while ([DateTime]::UtcNow -lt $deadline) {
        if (Test-GatewayReady) { return $true }
        Start-Sleep -Milliseconds 750
    }
    return $false
}

function Ensure-GatewayReady {
    if (Test-GatewayReady) { return }
    Invoke-OpenClaw @("gateway", "restart") -AllowFailure | Out-Null
    if (Wait-GatewayReady $InitialGatewayWaitSeconds) { return }

    Write-Step "Gateway service is missing or unreachable; registering it for this user..."
    Invoke-OpenClaw @("gateway", "install", "--force") | Out-Null
    Invoke-OpenClaw @("gateway", "start") -AllowFailure | Out-Null
    if (-not (Wait-GatewayReady $GatewayReadyTimeoutSeconds)) {
        $status = Invoke-OpenClawCapture @("gateway", "status") -AllowFailure
        throw "OpenClaw Gateway did not become reachable after automatic repair.`n$($status.Text)"
    }
}

function Disable-DuplicateOpenClawGatewayStartup {
    # Some OpenClaw upgrades leave both the supported Scheduled Task and an
    # older Startup-folder CMD launcher behind. At sign-in they race: the
    # second gateway kills the first one as "stale", and closing the visible
    # CMD window then stops the only remaining gateway. Retire only the exact
    # legacy launcher when the scheduled service exists and the file points to
    # this user's OpenClaw gateway.cmd. Unknown startup files are never touched.
    if ([string]::IsNullOrWhiteSpace($startupFolder)) { return }
    $legacyLauncher = Join-Path $startupFolder "OpenClaw Gateway.cmd"
    if (-not (Test-Path -LiteralPath $legacyLauncher -PathType Leaf)) { return }

    $gatewayTask = Get-ScheduledTask -TaskName "OpenClaw Gateway" -ErrorAction SilentlyContinue
    if (-not $gatewayTask) {
        Write-Warning "A legacy OpenClaw Gateway startup launcher exists, but no scheduled Gateway service was found; it was preserved."
        return
    }

    $gatewayCommand = [System.IO.Path]::GetFullPath((Join-Path $env:USERPROFILE ".openclaw\gateway.cmd"))
    $launcherText = Get-Content -LiteralPath $legacyLauncher -Raw -ErrorAction SilentlyContinue
    if ([string]::IsNullOrWhiteSpace($launcherText) -or
        $launcherText.IndexOf($gatewayCommand, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        Write-Warning "The OpenClaw Gateway startup launcher has unexpected content; it was preserved for manual review."
        return
    }

    $startupBackupRoot = Join-Path $BackupRoot "retired-startup-launchers"
    New-Item -ItemType Directory -Path $startupBackupRoot -Force | Out-Null
    $backupPath = Join-Path $startupBackupRoot "OpenClaw Gateway.cmd"
    if (Test-Path -LiteralPath $backupPath) {
        $backupPath = Join-Path $startupBackupRoot ("OpenClaw Gateway-{0}.cmd" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
    }
    Move-Item -LiteralPath $legacyLauncher -Destination $backupPath
    Write-Step "Retired a duplicate OpenClaw Gateway Startup-folder launcher; the scheduled Gateway service remains active."
}

function Get-LocalServiceEndpointState([string]$BaseUrl) {
    try { $uri = [Uri]$BaseUrl } catch { throw "Invalid AgentMeter-Gov service URL: $BaseUrl" }
    $hostName = $uri.Host.Trim('[', ']')
    if ($uri.Scheme -ne "http" -or $hostName -notin @("127.0.0.1", "localhost", "::1") -or $uri.Port -le 0) {
        throw "The packaged backend requires a local HTTP URL with an explicit port: $BaseUrl"
    }
    try {
        $health = Invoke-RestMethod -Uri "$($BaseUrl.TrimEnd('/'))/health" -TimeoutSec 3
        if (($health.status -eq "ok" -or $health.ok -eq $true) -and $health.PSObject.Properties.Name -contains "audit_chain") {
            return "agentmeter"
        }
        return "occupied"
    } catch { }

    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $pending = $client.BeginConnect($hostName, $uri.Port, $null, $null)
        if ($pending.AsyncWaitHandle.WaitOne(350)) {
            try { $client.EndConnect($pending); return "occupied" } catch { }
        }
    } finally {
        $client.Dispose()
    }
    return "available"
}

function Resolve-AgentMeterServiceBaseUrl([string]$RequestedUrl) {
    $requested = $RequestedUrl.TrimEnd('/')
    $state = Get-LocalServiceEndpointState $requested
    if ($state -in @("available", "agentmeter")) { return $requested }

    foreach ($port in 18765..18775) {
        $candidate = "http://127.0.0.1:$port"
        if ((Get-LocalServiceEndpointState $candidate) -eq "available") {
            Write-Warning "$requested is occupied by another application. AgentMeter-Gov will use $candidate without stopping that application."
            return $candidate
        }
    }
    throw "$requested is occupied by another application and no AgentMeter-Gov fallback port is available (18765-18775)."
}

function Test-DesktopPetRunning([string]$Root) {
    if ([string]::IsNullOrWhiteSpace($Root)) { return $false }
    $petLauncher = Join-Path $Root "desktop\launch_desktop_pet.ps1"
    $petScript = Join-Path $Root "desktop\start_desktop_pet.ps1"
    $match = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        $_.CommandLine -and (
            $_.CommandLine.IndexOf($petLauncher, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or
            $_.CommandLine.IndexOf($petScript, [System.StringComparison]::OrdinalIgnoreCase) -ge 0
        )
    } | Select-Object -First 1
    return [bool]$match
}

function Stop-OwnedProcesses([string]$Root) {
    if ([string]::IsNullOrWhiteSpace($Root)) { return }
    # Remember that we are about to terminate a pet the user had running, so the
    # upgrade can put it back. An unattended upgrade must not silently leave the
    # user without the pet they had before.
    if (Test-DesktopPetRunning $Root) { $script:PetWasRunning = $true }
    $backend = Join-Path $Root "backend\AgentMeterGovBackend.exe"
    $petLauncher = Join-Path $Root "desktop\launch_desktop_pet.ps1"
    $petScript = Join-Path $Root "desktop\start_desktop_pet.ps1"
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        ($_.ExecutablePath -and $_.ExecutablePath.Equals($backend, [System.StringComparison]::OrdinalIgnoreCase)) -or
        ($_.CommandLine -and $_.CommandLine.IndexOf($petLauncher, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) -or
        ($_.CommandLine -and $_.CommandLine.IndexOf($petScript, [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
    } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}

function Copy-PersistentRuntimeContent([string]$SourceRuntime, [string]$DestinationRoot, [switch]$SkipExisting) {
    if ([string]::IsNullOrWhiteSpace($SourceRuntime) -or -not (Test-Path -LiteralPath $SourceRuntime -PathType Container)) { return }
    $sourceData = Join-Path $SourceRuntime "data"
    $destinationRuntime = Join-Path $DestinationRoot "backend\_internal"
    $destinationData = Join-Path $destinationRuntime "data"
    if (Test-Path -LiteralPath $sourceData -PathType Container) {
        New-Item -ItemType Directory -Path $destinationData -Force | Out-Null
        $persistentNames = @(
            "openclaw_guard_approvals.json", "openclaw_guard_switch.json", "user_profiles.json",
            "review_memory.json", "batch_behavior_profile.json", "memory_governance_state.json"
        )
        Get-ChildItem -LiteralPath $sourceData -File -Recurse -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -match "\.(db|db-wal|db-shm)$" -or $_.Name -match "\.jsonl(\.|$)" -or
            $_.Name -in $persistentNames -or $_.Name -match "_(state|profile)\.json$"
        } | ForEach-Object {
            $relative = $_.FullName.Substring($sourceData.Length).TrimStart("\")
            $target = Join-Path $destinationData $relative
            if ($SkipExisting -and (Test-Path -LiteralPath $target -PathType Leaf)) { return }
            New-Item -ItemType Directory -Path (Split-Path $target -Parent) -Force | Out-Null
            Copy-Item -LiteralPath $_.FullName -Destination $target -Force
        }
        foreach ($folder in @("quarantine", "memory_quarantine")) {
            $sourceFolder = Join-Path $sourceData $folder
            $targetFolder = Join-Path $destinationData $folder
            if ((Test-Path -LiteralPath $sourceFolder -PathType Container) -and -not ($SkipExisting -and (Test-Path -LiteralPath $targetFolder -PathType Container))) {
                Copy-Item -LiteralPath $sourceFolder -Destination $destinationData -Recurse -Force
            }
        }
    }
    $sourceReports = Join-Path $SourceRuntime "audit_reports"
    $targetReports = Join-Path $destinationRuntime "audit_reports"
    if ((Test-Path -LiteralPath $sourceReports -PathType Container) -and -not ($SkipExisting -and (Test-Path -LiteralPath $targetReports -PathType Container))) {
        Copy-Item -LiteralPath $sourceReports -Destination $destinationRuntime -Recurse -Force
    }
}

function Copy-PersistentRuntimeState([string]$SourceRoot, [string]$DestinationRoot) {
    if (-not (Test-Path -LiteralPath $SourceRoot -PathType Container)) { return }
    Copy-PersistentRuntimeContent (Join-Path $SourceRoot "backend\_internal") $DestinationRoot
}

function Resolve-ConfiguredRuntimeDirectory([string]$RuntimePath) {
    if ([string]::IsNullOrWhiteSpace($RuntimePath)) { return $null }
    try {
        $resolved = [System.IO.Path]::GetFullPath($RuntimePath)
        if (Test-Path -LiteralPath $resolved -PathType Container) { return $resolved }

        # Older Windows installers could persist a Chinese path after UTF-8 bytes
        # had been decoded with the active ANSI code page. Recover that path only
        # when it resolves to a real directory; never guess a write target.
        foreach ($encoding in @([System.Text.Encoding]::Default, [System.Text.Encoding]::GetEncoding(936))) {
            $candidate = [System.Text.Encoding]::UTF8.GetString($encoding.GetBytes($RuntimePath))
            if ($candidate -eq $RuntimePath) { continue }
            $candidate = [System.IO.Path]::GetFullPath($candidate)
            if (Test-Path -LiteralPath $candidate -PathType Container) {
                Write-Warning "Recovered a legacy OpenClaw runtime path whose Chinese characters were encoded incorrectly."
                return $candidate
            }
        }
    } catch {}
    return $null
}

function Get-ConfiguredRuntimeDirectories {
    $configPaths = @($OpenClawConfigPath)
    $historicalConfigs = Get-ChildItem -LiteralPath (Join-Path $ProductRoot "backups") -Filter "openclaw.json.before" -File -Recurse -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 20
    $configPaths += @($historicalConfigs | ForEach-Object { $_.FullName })
    $results = @()
    foreach ($configPath in @($configPaths | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) { continue }
        try {
            $config = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 | ConvertFrom-Json
            $entry = $config.plugins.entries.PSObject.Properties[$PluginId].Value
            if ($entry -and $entry.config.runtimeDir) {
                $resolved = Resolve-ConfiguredRuntimeDirectory ([string]$entry.config.runtimeDir)
                if ($resolved) { $results += $resolved }
            }
        } catch {
            Write-Warning "A previous AgentMeter-Gov runtime path could not be read; known packaged directories will still be migrated."
        }
    }
    return @($results | Select-Object -Unique)
}

function Get-DesktopPetLaunchDefinition {
    if (Test-Path -LiteralPath $DesktopPetVbsLauncher -PathType Leaf) {
        $wscript = Join-Path $env:SystemRoot "System32\wscript.exe"
        $arguments = '"{0}"' -f $DesktopPetVbsLauncher
        return [pscustomobject]@{
            Target = $wscript
            Arguments = $arguments
            Command = ('"{0}" {1}' -f $wscript, $arguments)
        }
    }
    $petScript = Join-Path $DesktopTarget "launch_desktop_pet.ps1"
    $powerShell = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
    $arguments = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}"' -f $petScript
    return [pscustomobject]@{
        Target = $powerShell
        Arguments = $arguments
        Command = ('"{0}" {1}' -f $powerShell, $arguments)
    }
}

function Set-DesktopPetAutoStart {
    $launcher = Get-DesktopPetLaunchDefinition

    if (-not (Test-Path -LiteralPath $AutoStartRegistryPath)) {
        New-Item -Path $AutoStartRegistryPath -Force | Out-Null
    }
    New-ItemProperty -LiteralPath $AutoStartRegistryPath -Name $AutoStartValueName -Value $launcher.Command -PropertyType String -Force | Out-Null

    # If a user disabled an older entry in Task Manager, reset only this
    # product's approval record so a reinstall reliably enables it again.
    if ($AutoStartRegistryPath -eq "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -and $AutoStartValueName -eq "AgentMeterGovDesktopPet") {
        $startupApprovalPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
        Remove-ItemProperty -LiteralPath $startupApprovalPath -Name $AutoStartValueName -ErrorAction SilentlyContinue
    }
    return $launcher.Command
}

function Set-DesktopPetStartMenuShortcut {
    if ([string]::IsNullOrWhiteSpace($StartMenuShortcutPath)) { return $null }
    $launcher = Get-DesktopPetLaunchDefinition
    $shortcutParent = Split-Path $StartMenuShortcutPath -Parent
    New-Item -ItemType Directory -Path $shortcutParent -Force | Out-Null
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($StartMenuShortcutPath)
    $shortcut.TargetPath = $launcher.Target
    $shortcut.Arguments = $launcher.Arguments
    $shortcut.WorkingDirectory = $InstallRoot
    $icon = Join-Path $RuntimeDir "frontend\assets\desktop-pet-audit-fox.ico"
    if (Test-Path -LiteralPath $icon -PathType Leaf) { $shortcut.IconLocation = $icon }
    $shortcut.Description = "Open AgentMeter-Gov desktop pet and security audit workspace"
    $shortcut.Save()
    return $StartMenuShortcutPath
}

function Remove-LegacyAgentMeterEntry([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    $extension = [System.IO.Path]::GetExtension($Path)
    if ($extension -ieq ".url") {
        $content = Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue
        if ($content -notmatch [regex]::Escape("URL=$LegacyMonitoringUrl")) { return }
    } elseif ($extension -ieq ".lnk") {
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($Path)
        $identity = "$($shortcut.TargetPath) $($shortcut.Arguments)"
        if ($identity -notmatch "AgentMeter-Gov|AgentMeterGov") { return }
    } else {
        return
    }
    try {
        Remove-Item -LiteralPath $Path -Force
    } catch {
        Write-Warning "The obsolete AgentMeter-Gov shortcut could not be removed: $Path"
    }
}

function Restore-Transaction {
    Write-Step "Rolling back the interrupted installation..."
    if ($script:OpenClawCommand) { Invoke-OpenClaw @("gateway", "stop") -AllowFailure | Out-Null }
    Stop-OwnedProcesses $InstallRoot
    if (Test-Path -LiteralPath $InstallRoot) {
        Assert-ProductPath $InstallRoot
        Remove-Item -LiteralPath $InstallRoot -Recurse -Force
    }
    if ($script:PreviousCurrentMoved -and (Test-Path -LiteralPath $RollbackRoot)) {
        Move-Item -LiteralPath $RollbackRoot -Destination $InstallRoot
    }
    if ($script:OpenClawCommand) {
        Invoke-OpenClaw @("plugins", "uninstall", $PluginId, "--force") -AllowFailure | Out-Null
        if (Test-Path -LiteralPath $PluginBackupPath -PathType Container) {
            Invoke-OpenClaw @("plugins", "install", $PluginBackupPath, "--force") -AllowFailure | Out-Null
        }
    }
    if (Test-Path -LiteralPath $ConfigBackupPath -PathType Leaf) {
        New-Item -ItemType Directory -Path (Split-Path $OpenClawConfigPath -Parent) -Force | Out-Null
        Copy-Item -LiteralPath $ConfigBackupPath -Destination $OpenClawConfigPath -Force
    }
    if (Test-Path -LiteralPath $StateBackupPath -PathType Leaf) {
        Copy-Item -LiteralPath $StateBackupPath -Destination $StatePath -Force
    } elseif (Test-Path -LiteralPath $StatePath -PathType Leaf) {
        Remove-Item -LiteralPath $StatePath -Force
    }
    if ($script:OpenClawCommand -and $script:GatewayWasReady) {
        Invoke-OpenClaw @("gateway", "start") -AllowFailure | Out-Null
    }
}

try {
    Write-Step "Checking the v$ProductVersion package and OpenClaw..."
    foreach ($required in @($ManifestPath, $BackendSourceExecutable, (Join-Path $PluginSource "openclaw.plugin.json"), (Join-Path $DesktopSource "launch_desktop_pet.ps1"), (Join-Path $DesktopSource "launch_desktop_pet.vbs"), (Join-Path $DesktopSource "start_desktop_pet.ps1"), (Join-Path $DesktopSource "open_security_audit.ps1"))) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "The package is incomplete: $required" }
    }
    $openClaw = Get-Command openclaw -ErrorAction SilentlyContinue
    if (-not $openClaw) { throw "OpenClaw was not found. Install OpenClaw 2026.6.5 or newer first." }
    $script:OpenClawCommand = $openClaw.Source
    $openClawVersion = Get-OpenClawVersion
    if ($openClawVersion -lt $MinimumOpenClawVersion) {
        throw "OpenClaw $openClawVersion is unsupported. AgentMeter-Gov requires 2026.6.5 or newer."
    }
    Assert-PreflightConfiguration
    $beforePlugins = Get-PluginSnapshot
    $previousConfiguredRuntimes = @(Get-ConfiguredRuntimeDirectories)
    $preExistingUnhealthy = Get-UnhealthyUnrelatedPlugins $beforePlugins
    if ($preExistingUnhealthy.Count -gt 0) {
        $details = ($preExistingUnhealthy | ForEach-Object { "$($_.id)=$($_.status)" }) -join ", "
        Write-Warning "Existing plugin warnings will not block AgentMeter-Gov setup: $details"
        Write-Warning "Setup will preserve their enabled state. If one prevents the Gateway from starting, the upgrade will roll back safely."
    }

    New-Item -ItemType Directory -Path $ProductRoot, $BackupRoot -Force | Out-Null
    if (Test-Path -LiteralPath $OpenClawConfigPath -PathType Leaf) { Copy-Item -LiteralPath $OpenClawConfigPath -Destination $ConfigBackupPath -Force }
    if (Test-Path -LiteralPath $OpenClawPluginPath -PathType Container) { Copy-Item -LiteralPath $OpenClawPluginPath -Destination $PluginBackupPath -Recurse -Force }
    if (Test-Path -LiteralPath $StatePath -PathType Leaf) { Copy-Item -LiteralPath $StatePath -Destination $StateBackupPath -Force }
    $script:GatewayWasReady = Test-GatewayReady
    $script:TransactionStarted = $true

    Write-Step "Stopping OpenClaw before the transactional upgrade..."
    Invoke-OpenClaw @("gateway", "stop") -AllowFailure | Out-Null
    $installedRoots = @($InstallRoot, (Join-Path $ProductRoot "1.0.0"), (Join-Path $ProductRoot "1.1.0"))
    if (Test-Path -LiteralPath $StatePath -PathType Leaf) {
        try {
            $recordedRoot = (Get-Content -LiteralPath $StatePath -Raw -Encoding UTF8 | ConvertFrom-Json).install_root
            if ($recordedRoot) { $installedRoots += [string]$recordedRoot }
        } catch { Write-Warning "The previous install-state file could not be read; known version folders will still be migrated." }
    }
    foreach ($installedRoot in @($installedRoots | Select-Object -Unique)) {
        Stop-OwnedProcesses $installedRoot
    }
    Start-Sleep -Milliseconds 800

    # Resolve the port only after the previous AgentMeter-Gov runtime has been
    # stopped. During an in-place upgrade its own backend can be temporarily
    # busy and fail the health probe even though it legitimately owns the
    # requested port. Resolving earlier would misclassify that process as an
    # unrelated application and unnecessarily move the new runtime to 18765.
    $ServiceBaseUrl = Resolve-AgentMeterServiceBaseUrl $RequestedServiceBaseUrl
    $MonitoringUrl = "$ServiceBaseUrl/security-layer.html"
    $HealthUrl = "$ServiceBaseUrl/health"
    [ordered]@{
        checked_at = (Get-Date).ToUniversalTime().ToString("o")
        product_version = $ProductVersion
        openclaw_version = $openClawVersion.ToString()
        requested_service_url = $RequestedServiceBaseUrl
        selected_service_url = $ServiceBaseUrl
        existing_plugins = @($beforePlugins.plugins | ForEach-Object {
            [ordered]@{ id = $_.id; enabled = [bool]$_.enabled; status = $_.status; version = $_.version }
        })
        pre_existing_unhealthy_plugins = @($preExistingUnhealthy | ForEach-Object { $_.id })
    } | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $PreflightPath -Encoding UTF8

    Assert-ProductPath $StageRoot
    New-Item -ItemType Directory -Path $StageRoot -Force | Out-Null
    Copy-Item -LiteralPath $BackendSource -Destination $StageRoot -Recurse -Force
    Copy-Item -LiteralPath $PluginSource -Destination $StageRoot -Recurse -Force
    Copy-Item -LiteralPath $DesktopSource -Destination $StageRoot -Recurse -Force

    Write-Step "Migrating audit and approval state from earlier versions..."
    foreach ($source in @((Join-Path $ProductRoot "1.0.0"), (Join-Path $ProductRoot "1.1.0"), $InstallRoot)) {
        if (-not $source.Equals($StageRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            Copy-PersistentRuntimeState $source $StageRoot
        }
    }
    foreach ($previousConfiguredRuntime in $previousConfiguredRuntimes) {
        if (-not $previousConfiguredRuntime.Equals((Join-Path $InstallRoot "backend\_internal"), [System.StringComparison]::OrdinalIgnoreCase)) {
            Write-Step "Migrating state from a previously configured development or portable runtime..."
            # Never overwrite data already migrated from the current install; the
            # configured runtime can be a stale source checkout with older audit data.
            Copy-PersistentRuntimeContent $previousConfiguredRuntime $StageRoot -SkipExisting
        }
    }

    if (Test-Path -LiteralPath $InstallRoot) {
        Assert-ProductPath $RollbackRoot
        Move-Item -LiteralPath $InstallRoot -Destination $RollbackRoot
        $script:PreviousCurrentMoved = $true
    }
    Move-Item -LiteralPath $StageRoot -Destination $InstallRoot
    Set-Content -LiteralPath (Join-Path $DesktopTarget "service-base-url.txt") -Value $ServiceBaseUrl -Encoding ASCII

    Write-Step "Installing AgentMeter-Gov without changing unrelated plugins..."
    Invoke-OpenClaw @("plugins", "install", $PluginTarget, "--force") | Out-Null
    Invoke-OpenClaw @("plugins", "enable", $PluginId) | Out-Null
    Ensure-AgentMeterPluginPolicy
    Set-OpenClawString "plugins.entries.$PluginId.config.runtimeDir" $RuntimeDir
    Set-OpenClawString "plugins.entries.$PluginId.config.backendRoot" $RuntimeDir
    Set-OpenClawString "plugins.entries.$PluginId.config.backendExecutable" "../AgentMeterGovBackend.exe"
    Set-OpenClawString "plugins.entries.$PluginId.config.gateUrl" "$ServiceBaseUrl/api/v1/evaluate"
    Set-OpenClawString "plugins.entries.$PluginId.config.supplyChainScanUrl" "$ServiceBaseUrl/api/supply-chain/scan"
    Set-OpenClawString "plugins.entries.$PluginId.config.eventUrl" "$ServiceBaseUrl/api/events"
    Set-OpenClawJson "plugins.entries.$PluginId.config.autoStartBackend" "true"
    Set-OpenClawJson "plugins.entries.$PluginId.config.stopBackendOnGatewayExit" "true"
    Set-OpenClawJson "plugins.entries.$PluginId.config.backendStartupTimeoutMs" "60000"
    Invoke-OpenClaw @("config", "validate") | Out-Null

    if (-not $SkipGatewayRestart) {
        Write-Step "Starting and verifying the OpenClaw Gateway..."
        Ensure-GatewayReady
        Disable-DuplicateOpenClawGatewayStartup
        Write-Step "Waiting for the AgentMeter-Gov backend..."
        $ready = $false
        $deadline = [DateTime]::UtcNow.AddSeconds([Math]::Max(15, $BackendReadyTimeoutSeconds))
        while ([DateTime]::UtcNow -lt $deadline) {
            try {
                $health = Invoke-RestMethod -Uri $HealthUrl -TimeoutSec 2
                if (($health.status -eq "ok" -or $health.ok -eq $true) -and $health.version -eq $ProductVersion) { $ready = $true; break }
            } catch { }
            Start-Sleep -Milliseconds 750
        }
        if (-not $ready) { throw "The Gateway is running, but AgentMeter-Gov $ProductVersion was not healthy within $BackendReadyTimeoutSeconds seconds." }
    }

    $afterPlugins = Get-PluginSnapshot
    Assert-UnrelatedPluginsUnchanged $beforePlugins $afterPlugins
    $guard = @($afterPlugins.plugins | Where-Object { $_.id -eq $PluginId }) | Select-Object -First 1
    if (-not $guard -or $guard.status -ne "loaded" -or $guard.version -ne $ProductVersion) {
        throw "AgentMeter-Gov plugin runtime verification failed: version=$($guard.version), status=$($guard.status)"
    }

    Write-Step "Registering the desktop pet to start automatically at Windows sign-in..."
    foreach ($legacyEntryPath in $legacyEntryPaths | Select-Object -Unique) {
        Remove-LegacyAgentMeterEntry $legacyEntryPath
    }
    $autoStartCommand = Set-DesktopPetAutoStart
    $startMenuEntry = Set-DesktopPetStartMenuShortcut

    $state = [ordered]@{
        product = "AgentMeter-Gov"
        version = $ProductVersion
        plugin_id = $PluginId
        install_root = $InstallRoot
        installed_at = (Get-Date).ToUniversalTime().ToString("o")
        openclaw_version = $openClawVersion.ToString()
        monitoring_url = $MonitoringUrl
        upgrade_mode = "transactional-in-place"
        desktop_pet_autostart = [ordered]@{
            registry_path = $AutoStartRegistryPath
            value_name = $AutoStartValueName
            command = $autoStartCommand
        }
        shortcuts = [ordered]@{
            start_menu = $startMenuEntry
        }
        package_manifest = (Get-Content -LiteralPath $ManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json)
    }
    $state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $StatePath -Encoding UTF8

    foreach ($obsolete in @($RollbackRoot, (Join-Path $ProductRoot "1.0.0"), (Join-Path $ProductRoot "1.1.0"))) {
        if (Test-Path -LiteralPath $obsolete) {
            Assert-ProductPath $obsolete
            Remove-Item -LiteralPath $obsolete -Recurse -Force
        }
    }

    # Launch the pet unless the caller opted out, but always restore one that was
    # running before this upgrade: Stop-OwnedProcesses terminated it, so skipping
    # the relaunch would leave the user without a pet they already had. A silent
    # or scripted upgrade therefore no longer needs a Windows sign-in to get it
    # back.
    $skipPetLaunch = $SkipDesktopPetLaunch -or $SkipOpenMonitoringPage
    if ((-not $skipPetLaunch) -or $script:PetWasRunning) {
        try {
            Start-Process -FilePath (Join-Path $env:SystemRoot "System32\wscript.exe") `
                -ArgumentList @("`"$DesktopPetVbsLauncher`"") -WorkingDirectory $InstallRoot -WindowStyle Hidden | Out-Null
            if ($skipPetLaunch) { Write-Step "Restored the desktop pet that was running before the upgrade." }
        } catch {
            Write-Warning "The desktop pet could not be started now. It remains registered to retry automatically at the next Windows sign-in."
        }
    }

    Write-Host ""
    Write-Host "AgentMeter-Gov $ProductVersion installed or upgraded successfully." -ForegroundColor Green
    Write-Host "OpenClaw compatibility: $openClawVersion"
    Write-Host "Protection continues when the desktop pet is closed."
    Write-Host "Monitoring page: $MonitoringUrl"
    Write-Host "Desktop pet: starts automatically after Windows sign-in and can be reopened from the Start menu."
    Write-Host "Double-click the floating pet to open the monitoring page."
    Write-Host "Install location: $InstallRoot"
    exit 0
} catch {
    $failure = $_.Exception.Message
    if ($script:TransactionStarted) {
        try { Restore-Transaction } catch { Write-Warning "Automatic rollback encountered an error: $($_.Exception.Message)" }
    }
    if (Test-Path -LiteralPath $StageRoot) {
        Assert-ProductPath $StageRoot
        Remove-Item -LiteralPath $StageRoot -Recurse -Force
    }
    Write-Host ""
    Write-Host "Installation failed: $failure" -ForegroundColor Red
    Write-Host "Unrelated plugins were not disabled. Existing audit data was preserved."
    Write-Host "Diagnostics backup: $BackupRoot"
    exit 1
}
