[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PackageZip,
    [string]$SetupExe
)

$ErrorActionPreference = "Stop"
$PackageZip = [System.IO.Path]::GetFullPath($PackageZip)
$TestId = [guid]::NewGuid().ToString("N").Substring(0, 8)
$TestRoot = Join-Path $env:TEMP "amg-$TestId"
$ExtractRoot = Join-Path $TestRoot "extract"
$FakeBin = Join-Path $TestRoot "fake-bin"
$FakeState = Join-Path $TestRoot "fake-state"
$FakeLog = Join-Path $TestRoot "openclaw-commands.log"
$TestLocalAppData = Join-Path $TestRoot "localappdata"
$TestUserProfile = Join-Path $TestRoot "user"
$InstallRoot = Join-Path $TestLocalAppData "AgentMeter-Gov\current"
$StatePath = Join-Path $TestLocalAppData "AgentMeter-Gov\install-state.json"
$ArchiveParent = Join-Path $TestRoot "archive"
$DesktopShortcutPath = Join-Path $TestRoot "desktop\AgentMeter-Gov-pet.lnk"
$StartMenuShortcutPath = Join-Path $TestRoot "programs\AgentMeter-Gov\AgentMeter-Gov-pet.lnk"
$AutoStartRegistryPath = "HKCU:\Software\AgentMeterGovInstallerTests\$TestId"
$AutoStartValueName = "DesktopPet"
$TestPort = 20000 + (Get-Random -Minimum 1000 -Maximum 20000)
$ServiceBaseUrl = "http://127.0.0.1:$TestPort"
$oldPath = $env:PATH
$oldLocalAppData = $env:LOCALAPPDATA
$oldUserProfile = $env:USERPROFILE
$oldModuleAnalysisCachePath = $env:PSModuleAnalysisCachePath
$listenerJob = $null
$conflictListenerJob = $null

function Assert-Under([string]$Path, [string]$Parent) {
    $resolvedPath = [System.IO.Path]::GetFullPath($Path)
    $resolvedParent = [System.IO.Path]::GetFullPath($Parent)
    if (-not $resolvedPath.StartsWith($resolvedParent + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Unsafe test cleanup target: $resolvedPath"
    }
}

try {
    New-Item -ItemType Directory -Path $ExtractRoot, $FakeBin, $FakeState, $TestLocalAppData, (Join-Path $TestUserProfile ".openclaw") -Force | Out-Null
    $chinesePathSegment = (-join @([char]0x63ED, [char]0x699C, [char]0x8FC1, [char]0x79FB)) + "-runtime"
    $portableRuntime = Join-Path $TestRoot $chinesePathSegment
    New-Item -ItemType Directory -Path (Join-Path $portableRuntime "data") -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $portableRuntime "data\portable-audit.jsonl") -Value '{"source":"portable"}' -Encoding UTF8
    $portableConfig = [ordered]@{
        plugins = [ordered]@{
            entries = [ordered]@{
                "agentmeter-gov-guard" = [ordered]@{
                    enabled = $true
                    config = [ordered]@{
                        # Reproduce the legacy UTF-8/ANSI path corruption seen on
                        # Chinese Windows systems. The installer must recover it.
                        runtimeDir = [System.Text.Encoding]::GetEncoding(936).GetString(
                            [System.Text.Encoding]::UTF8.GetBytes($portableRuntime)
                        )
                    }
                }
            }
        }
    }
    $portableConfig | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $TestUserProfile ".openclaw\openclaw.json") -Encoding UTF8
    Expand-Archive -LiteralPath $PackageZip -DestinationPath $ExtractRoot -Force
    $PackageRoot = Get-ChildItem -LiteralPath $ExtractRoot -Directory | Select-Object -First 1
    if (-not $PackageRoot) { throw "The ZIP has no package root directory." }
    $installerSource = Get-Content -LiteralPath (Join-Path $PackageRoot.FullName "installer\install.ps1") -Raw
    $stopOwnedIndex = $installerSource.IndexOf('Stop-OwnedProcesses $installedRoot', [System.StringComparison]::Ordinal)
    $resolvePortIndex = $installerSource.LastIndexOf('$ServiceBaseUrl = Resolve-AgentMeterServiceBaseUrl $RequestedServiceBaseUrl', [System.StringComparison]::Ordinal)
    if ($stopOwnedIndex -lt 0 -or $resolvePortIndex -lt 0 -or $resolvePortIndex -lt $stopOwnedIndex) {
        throw "Installer regression: the service port must be resolved after the previous AgentMeter-Gov runtime is stopped."
    }

    # The backend answers /health in roughly 0.6s idle and slower under audit
    # load. A one-second single-shot probe reported a live service as down,
    # restarted the gateway and showed a startup-failure dialog on double-click.
    foreach ($desktopScript in @("start_desktop_pet.ps1", "open_security_audit.ps1")) {
        $desktopPath = Join-Path $PackageRoot.FullName "payload\desktop\$desktopScript"
        if (-not (Test-Path -LiteralPath $desktopPath -PathType Leaf)) {
            throw "Desktop payload regression: $desktopScript is missing from the package."
        }
        $desktopSource = Get-Content -LiteralPath $desktopPath -Raw
        if ($desktopSource -match '/health"\s+-TimeoutSec\s+1\b' -or $desktopSource -match '\$healthUrl\s+-TimeoutSec\s+1\b') {
            throw "Desktop regression: $desktopScript probes /health with a one-second timeout, which reports a busy backend as an outage."
        }
    }

    # The pet used to dock to the screen-edge peek 5.8s after appearing, so at
    # sign-in it vanished before the user saw it and looked like it never started.
    $petSource = Get-Content -LiteralPath (Join-Path $PackageRoot.FullName "payload\desktop\start_desktop_pet.ps1") -Raw
    if ($petSource -notmatch '\$startupDockTicks\s*=\s*(\d+)') {
        throw "Desktop regression: the pet no longer defines a startup dock dwell time."
    }
    $startupTicks = [int]$Matches[1]
    if ($startupTicks -lt 1875) {
        throw "Desktop regression: the pet docks after $([math]::Round($startupTicks * 16 / 1000, 1))s at startup; it must stay visible for at least 30s."
    }

    # Closing the pet only docks it, so the process keeps holding the
    # single-instance mutex. A second launch must wake the docked pet instead of
    # returning silently, which used to make the Start menu entry do nothing.
    if ($petSource -notmatch 'AgentMeterGovDesktopPetShow') {
        throw "Desktop regression: the pet no longer exposes a show-request event for second launches."
    }
    if ($petSource -match 'if\s*\(-not\s+\$createdNew\)\s*\{\s*return\s*\}') {
        throw "Desktop regression: a second launch exits silently instead of signaling the running pet to show."
    }

    # An unattended upgrade terminates a running pet via Stop-OwnedProcesses. It
    # must put it back even when the caller asked not to launch one, otherwise
    # the user is left without the pet they had until the next Windows sign-in.
    if ($installerSource -notmatch '\$script:PetWasRunning') {
        throw "Installer regression: the upgrade no longer tracks whether the desktop pet was running."
    }
    if ($installerSource -notmatch '\(-not\s+\$skipPetLaunch\)\s*-or\s+\$script:PetWasRunning') {
        throw "Installer regression: a silent upgrade no longer restores a desktop pet that was running before it."
    }

    # OpenClaw can leave a legacy Startup-folder CMD launcher alongside its
    # scheduled Gateway service. The two launchers race at sign-in and the
    # visible CMD becomes an accidental kill switch for the gateway. Setup must
    # retire only that verified duplicate and preserve unknown startup files.
    if ($installerSource -notmatch 'function\s+Disable-DuplicateOpenClawGatewayStartup') {
        throw "Installer regression: duplicate OpenClaw Gateway startup launchers are no longer handled."
    }
    if ($installerSource -notmatch 'Get-ScheduledTask\s+-TaskName\s+"OpenClaw Gateway"') {
        throw "Installer regression: Startup-folder cleanup is not gated on the scheduled Gateway service."
    }
    if ($installerSource -notmatch 'IndexOf\(\$gatewayCommand,\s*\[System\.StringComparison\]::OrdinalIgnoreCase\)') {
        throw "Installer regression: an unverified Startup-folder command could be modified."
    }
    $ensureGatewayIndex = $installerSource.LastIndexOf('Ensure-GatewayReady', [System.StringComparison]::Ordinal)
    $retireDuplicateIndex = $installerSource.LastIndexOf('Disable-DuplicateOpenClawGatewayStartup', [System.StringComparison]::Ordinal)
    if ($ensureGatewayIndex -lt 0 -or $retireDuplicateIndex -lt $ensureGatewayIndex) {
        throw "Installer regression: duplicate startup cleanup must run only after the scheduled Gateway is ready."
    }

    $fakeScript = @'
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$CliArgs)
$ErrorActionPreference = "Stop"
$stateRoot = $env:AGENTMETER_FAKE_OPENCLAW_STATE
$logPath = $env:AGENTMETER_FAKE_OPENCLAW_LOG
New-Item -ItemType Directory -Path $stateRoot -Force | Out-Null
$command = ($CliArgs -join " ").Trim()
Add-Content -LiteralPath $logPath -Value $command -Encoding UTF8
$serviceFlag = Join-Path $stateRoot "gateway-service"
$runningFlag = Join-Path $stateRoot "gateway-running"
$pluginFlag = Join-Path $stateRoot "plugin-installed"
$driftFlag = Join-Path $stateRoot "unrelated-plugin-drift"
$configPath = Join-Path $env:USERPROFILE ".openclaw\openclaw.json"
$extensionPath = Join-Path $env:USERPROFILE ".openclaw\extensions\agentmeter-gov-guard"

if ($command -eq "--version") { Write-Output "OpenClaw 2026.6.5 (installer-test)"; exit 0 }
if ($command -eq "config validate") { Write-Output "Config valid"; exit 0 }
if ($CliArgs.Count -ge 2 -and $CliArgs[0] -eq "config" -and $CliArgs[1] -eq "set") {
    Set-Content -LiteralPath $configPath -Value '{"sentinel":"mutated-by-installer"}' -Encoding UTF8
    exit 0
}
if ($command -eq "plugins list --json") {
    $existingEnabled = -not (Test-Path -LiteralPath $driftFlag)
    $existingStatus = if ($env:AGENTMETER_FAKE_EXISTING_UNHEALTHY -eq "1") { "error" } elseif ($existingEnabled) { "loaded" } else { "disabled" }
    $plugins = @([ordered]@{ id = "existing-channel"; enabled = $existingEnabled; status = $existingStatus; version = "9.9.9" })
    if (Test-Path -LiteralPath $pluginFlag) {
        $plugins += [ordered]@{ id = "agentmeter-gov-guard"; enabled = $true; status = "loaded"; version = "2.0.0" }
    }
    [ordered]@{ registry = [ordered]@{ source = "test"; diagnostics = @() }; plugins = $plugins; diagnostics = @() } |
        ConvertTo-Json -Depth 8
    exit 0
}
if ($CliArgs.Count -ge 2 -and $CliArgs[0] -eq "plugins" -and $CliArgs[1] -eq "install") {
    $sourcePath = [System.IO.Path]::GetFullPath($CliArgs[2])
    if (Test-Path -LiteralPath $extensionPath) { Remove-Item -LiteralPath $extensionPath -Recurse -Force }
    New-Item -ItemType Directory -Path (Split-Path $extensionPath -Parent) -Force | Out-Null
    Copy-Item -LiteralPath $sourcePath -Destination $extensionPath -Recurse -Force
    Set-Content -LiteralPath $pluginFlag -Value "installed" -Encoding ASCII
    if ($env:AGENTMETER_FAKE_PLUGIN_DRIFT -eq "1") { Set-Content -LiteralPath $driftFlag -Value "drift" -Encoding ASCII }
    exit 0
}
if ($CliArgs.Count -ge 2 -and $CliArgs[0] -eq "plugins" -and $CliArgs[1] -eq "enable") { exit 0 }
if ($CliArgs.Count -ge 2 -and $CliArgs[0] -eq "plugins" -and $CliArgs[1] -eq "uninstall") {
    Remove-Item -LiteralPath $pluginFlag -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $extensionPath -Recurse -Force -ErrorAction SilentlyContinue
    exit 0
}
if ($command -eq "gateway status") {
    if ((Test-Path -LiteralPath $serviceFlag) -and (Test-Path -LiteralPath $runningFlag)) {
        Write-Output "Runtime: running"
        Write-Output "Connectivity probe: ok"
    } else {
        Write-Error "Connectivity probe: failed"
        exit 1
    }
    exit 0
}
if ($command -eq "gateway install --force") {
    Set-Content -LiteralPath $serviceFlag -Value "installed" -Encoding ASCII
    exit 0
}
if ($command -eq "gateway start") {
    if (-not (Test-Path -LiteralPath $serviceFlag)) { Write-Error "Gateway service missing"; exit 1 }
    Set-Content -LiteralPath $runningFlag -Value "running" -Encoding ASCII
    exit 0
}
if ($command -eq "gateway restart") {
    if (Test-Path -LiteralPath $serviceFlag) { Set-Content -LiteralPath $runningFlag -Value "running" -Encoding ASCII }
    Write-Output "Gateway service missing or restarted"
    exit 0
}
if ($command -eq "gateway stop") {
    Remove-Item -LiteralPath $runningFlag -Force -ErrorAction SilentlyContinue
    exit 0
}
exit 0
'@
    Set-Content -LiteralPath (Join-Path $FakeBin "fake-openclaw.ps1") -Value $fakeScript -Encoding UTF8
    $fakeCommand = @'
@echo off
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0fake-openclaw.ps1" %*
exit /b %ERRORLEVEL%
'@
    Set-Content -LiteralPath (Join-Path $FakeBin "openclaw.cmd") -Value $fakeCommand -Encoding ASCII

    $listenerJob = Start-Job -ArgumentList $TestPort -ScriptBlock {
        param($Port)
        $listener = [System.Net.HttpListener]::new()
        $listener.Prefixes.Add("http://127.0.0.1:$Port/")
        $listener.Start()
        try {
            while ($listener.IsListening) {
                $context = $listener.GetContext()
                $path = $context.Request.Url.AbsolutePath
                $payload = if ($path -eq "/health") {
                    '{"status":"ok","version":"2.0.0","audit_chain":{"verification":"deferred","latest_sequence":0}}'
                } else { '<html><body>AgentMeter-Gov installer test</body></html>' }
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
                $context.Response.StatusCode = 200
                $context.Response.ContentType = if ($path -eq "/health") { "application/json" } else { "text/html" }
                $context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
                $context.Response.Close()
                if ($path -eq "/shutdown") { break }
            }
        } finally { $listener.Stop(); $listener.Close() }
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    do {
        try { $ready = (Invoke-RestMethod -Uri "$ServiceBaseUrl/health" -TimeoutSec 1).status -eq "ok" } catch { $ready = $false }
        if (-not $ready) { Start-Sleep -Milliseconds 200 }
    } while (-not $ready -and [DateTime]::UtcNow -lt $deadline)
    if (-not $ready) { throw "The installer test health endpoint did not start." }

    $ConflictPort = $TestPort + 1
    $ConflictServiceBaseUrl = "http://127.0.0.1:$ConflictPort"
    $conflictListenerJob = Start-Job -ArgumentList $ConflictPort -ScriptBlock {
        param($Port)
        $listener = [System.Net.HttpListener]::new()
        $listener.Prefixes.Add("http://127.0.0.1:$Port/")
        $listener.Start()
        try {
            while ($listener.IsListening) {
                $context = $listener.GetContext()
                $payload = '{"status":"foreign-service"}'
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
                $context.Response.StatusCode = 200
                $context.Response.ContentType = "application/json"
                $context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
                $context.Response.Close()
                if ($context.Request.Url.AbsolutePath -eq "/shutdown") { break }
            }
        } finally { $listener.Stop(); $listener.Close() }
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    do {
        try { $conflictReady = (Invoke-RestMethod -Uri "$ConflictServiceBaseUrl/health" -TimeoutSec 1).status -eq "foreign-service" } catch { $conflictReady = $false }
        if (-not $conflictReady) { Start-Sleep -Milliseconds 200 }
    } while (-not $conflictReady -and [DateTime]::UtcNow -lt $deadline)
    if (-not $conflictReady) { throw "The installer conflict endpoint did not start." }

    $env:PATH = "$FakeBin;$oldPath"
    $env:LOCALAPPDATA = $TestLocalAppData
    $env:USERPROFILE = $TestUserProfile
    $env:AGENTMETER_FAKE_OPENCLAW_STATE = $FakeState
    $env:AGENTMETER_FAKE_OPENCLAW_LOG = $FakeLog
    $env:PSModuleAnalysisCachePath = Join-Path $TestRoot "powershell\ModuleAnalysisCache"

    $legacyPetName = "AgentMeter-Gov " + (-join @([char]0x684C, [char]0x9762, [char]0x5DE1, [char]0x68C0, [char]0x5BA0, [char]0x7269)) + ".lnk"
    $legacyPetShortcut = Join-Path (Split-Path $DesktopShortcutPath -Parent) $legacyPetName
    New-Item -ItemType Directory -Path (Split-Path $legacyPetShortcut -Parent) -Force | Out-Null
    $legacyShell = New-Object -ComObject WScript.Shell
    $legacyShortcut = $legacyShell.CreateShortcut($legacyPetShortcut)
    $legacyShortcut.TargetPath = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
    $legacyShortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$InstallRoot\desktop\start_desktop_pet.ps1`""
    $legacyShortcut.Save()

    $installArgs = @(
        "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", (Join-Path $PackageRoot.FullName "installer\install.ps1"),
        "-DesktopShortcutPath", $DesktopShortcutPath, "-StartMenuShortcutPath", $StartMenuShortcutPath,
        "-AutoStartRegistryPath", $AutoStartRegistryPath, "-AutoStartValueName", $AutoStartValueName,
        "-SkipOpenMonitoringPage", "-GatewayReadyTimeoutSeconds", "5", "-BackendReadyTimeoutSeconds", "5",
        "-InitialGatewayWaitSeconds", "1", "-ServiceBaseUrl", $ServiceBaseUrl
    )

    # A pre-existing unhealthy third-party plugin is reported, but does not block
    # AgentMeter-Gov while the Gateway itself can still run. Its state is preserved.
    $env:AGENTMETER_FAKE_EXISTING_UNHEALTHY = "1"
    & powershell.exe @installArgs
    $preflightExit = $LASTEXITCODE
    Remove-Item Env:AGENTMETER_FAKE_EXISTING_UNHEALTHY -ErrorAction SilentlyContinue
    if ($preflightExit -ne 0) { throw "A pre-existing plugin warning incorrectly blocked installation." }
    if (-not (Test-Path -LiteralPath $InstallRoot)) { throw "Compatibility-mode installation did not create the install directory." }
    if (-not (Test-Path -LiteralPath (Join-Path $InstallRoot "backend\_internal\data\portable-audit.jsonl") -PathType Leaf)) {
        throw "State from the previously configured portable/development runtime was not migrated."
    }
    if (Test-Path -LiteralPath $legacyPetShortcut -PathType Leaf) {
        throw "The obsolete duplicate desktop-pet shortcut was not retired."
    }
    $preflightCommands = Get-Content -LiteralPath $FakeLog
    if ($preflightCommands -match "plugins disable existing-channel|plugins uninstall existing-channel") {
        throw "Installer changed an unrelated unhealthy plugin instead of preserving it."
    }

    # Exercise migration from both legacy version directories during an in-place 2.0.0 upgrade.
    foreach ($legacyVersion in @("1.0.0", "1.1.0")) {
        $legacyData = Join-Path $TestLocalAppData "AgentMeter-Gov\$legacyVersion\backend\_internal\data"
        New-Item -ItemType Directory -Path $legacyData -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $legacyData "legacy-$legacyVersion.jsonl") -Value "{`"version`":`"$legacyVersion`"}" -Encoding UTF8
    }
    $retiredDashboard = Join-Path $InstallRoot "backend\_internal\frontend\security-layer-legacy.html"
    Set-Content -LiteralPath $retiredDashboard -Value "retired dashboard" -Encoding UTF8
    & powershell.exe @installArgs
    if ($LASTEXITCODE -ne 0) { throw "The isolated installer returned $LASTEXITCODE." }
    if (Test-Path -LiteralPath $retiredDashboard -PathType Leaf) { throw "The retired monitoring dashboard survived the in-place upgrade." }

    foreach ($required in @(
        $StatePath,
        (Join-Path $InstallRoot "backend\AgentMeterGovBackend.exe"),
        (Join-Path $InstallRoot "plugin\openclaw.plugin.json"),
        (Join-Path $InstallRoot "desktop\launch_desktop_pet.ps1"),
        (Join-Path $InstallRoot "desktop\launch_desktop_pet.vbs"),
        (Join-Path $InstallRoot "desktop\start_desktop_pet.ps1")
    )) {
        if (-not (Test-Path -LiteralPath $required)) { throw "Expected installed file is missing: $required" }
    }
    if (Test-Path -LiteralPath $DesktopShortcutPath) { throw "A desktop shortcut should not be created: $DesktopShortcutPath" }
    if (-not (Test-Path -LiteralPath $StartMenuShortcutPath -PathType Leaf)) { throw "The Start menu recovery shortcut was not created." }
    $startMenuShortcut = (New-Object -ComObject WScript.Shell).CreateShortcut($StartMenuShortcutPath)
    if ($startMenuShortcut.Arguments -notlike "*launch_desktop_pet.vbs*") { throw "The Start menu shortcut does not use the windowless launcher." }
    $autoStartCommand = Get-ItemPropertyValue -LiteralPath $AutoStartRegistryPath -Name $AutoStartValueName -ErrorAction Stop
    if ($autoStartCommand -notlike "*launch_desktop_pet.vbs*") { throw "Desktop pet auto-start entry has the wrong command." }
    $state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
    if ($state.version -ne "2.0.0" -or $state.openclaw_version -ne "2026.6.5") { throw "Install state version mismatch." }
    if ($state.shortcuts.start_menu -ne $StartMenuShortcutPath) { throw "Install state did not record the Start menu recovery shortcut." }
    foreach ($legacyVersion in @("1.0.0", "1.1.0")) {
        $migrated = Join-Path $InstallRoot "backend\_internal\data\legacy-$legacyVersion.jsonl"
        if (-not (Test-Path -LiteralPath $migrated -PathType Leaf)) { throw "Legacy $legacyVersion audit state was not migrated." }
        if (Test-Path -LiteralPath (Join-Path $TestLocalAppData "AgentMeter-Gov\$legacyVersion")) { throw "Legacy $legacyVersion program directory was not retired." }
    }
    $commands = Get-Content -LiteralPath $FakeLog
    if (-not ($commands -contains "gateway install --force")) {
        throw "Gateway repair regression: service-missing output with exit 0 did not trigger gateway install."
    }

    $runtimeMarker = Join-Path $InstallRoot "backend\_internal\data\installer-test-audit.jsonl"
    Set-Content -LiteralPath $runtimeMarker -Value '{"event":"installer-test"}' -Encoding UTF8
    & powershell.exe @installArgs
    if ($LASTEXITCODE -ne 0) { throw "The in-place upgrade returned $LASTEXITCODE." }
    if (-not (Test-Path -LiteralPath $runtimeMarker)) { throw "Audit state was not preserved across the in-place upgrade." }
    $upgradeState = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
    if ($upgradeState.monitoring_url -ne "$ServiceBaseUrl/security-layer.html") {
        throw "In-place upgrade unexpectedly changed the AgentMeter-Gov service port: $($upgradeState.monitoring_url)"
    }

    # A non-AgentMeter process on the requested port must be preserved. Setup
    # selects a free fallback and records it for the plugin and desktop pet.
    $conflictInstallArgs = @($installArgs)
    $serviceArgumentIndex = [Array]::IndexOf($conflictInstallArgs, "-ServiceBaseUrl")
    $conflictInstallArgs[$serviceArgumentIndex + 1] = $ConflictServiceBaseUrl
    $conflictInstallArgs += "-SkipGatewayRestart"
    & powershell.exe @conflictInstallArgs
    if ($LASTEXITCODE -ne 0) { throw "Installation with an occupied requested port failed instead of selecting a fallback." }
    $conflictState = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
    if ($conflictState.monitoring_url -like "$ConflictServiceBaseUrl*") { throw "Installer retained the occupied service port." }
    if ($conflictState.monitoring_url -notmatch '^http://127\.0\.0\.1:187(6[5-9]|7[0-5])/security-layer\.html$') { throw "Installer selected an unexpected fallback URL: $($conflictState.monitoring_url)" }
    $desktopServiceUrl = (Get-Content -LiteralPath (Join-Path $InstallRoot "desktop\service-base-url.txt") -Raw).Trim()
    if (-not $conflictState.monitoring_url.StartsWith($desktopServiceUrl)) { throw "Desktop pet did not receive the selected fallback service URL." }

    # Restore the normal test endpoint before exercising the rollback path.
    & powershell.exe @installArgs
    if ($LASTEXITCODE -ne 0) { throw "Installer did not return to the requested healthy AgentMeter-Gov endpoint." }

    $rollbackMarker = Join-Path $InstallRoot "rollback-sentinel.txt"
    Set-Content -LiteralPath $rollbackMarker -Value "previous-version" -Encoding ASCII
    $rollbackConfig = '{"sentinel":"before-rollback"}'
    Set-Content -LiteralPath (Join-Path $TestUserProfile ".openclaw\openclaw.json") -Value $rollbackConfig -Encoding UTF8
    $previousPluginMarker = Join-Path $TestUserProfile ".openclaw\extensions\agentmeter-gov-guard\previous-plugin.txt"
    Set-Content -LiteralPath $previousPluginMarker -Value "previous-plugin" -Encoding ASCII
    $env:AGENTMETER_FAKE_PLUGIN_DRIFT = "1"
    & powershell.exe @installArgs
    $rollbackExit = $LASTEXITCODE
    Remove-Item Env:AGENTMETER_FAKE_PLUGIN_DRIFT -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath (Join-Path $FakeState "unrelated-plugin-drift") -Force -ErrorAction SilentlyContinue
    if ($rollbackExit -eq 0) { throw "Plugin coexistence drift should have failed and rolled back." }
    if (-not (Test-Path -LiteralPath $rollbackMarker -PathType Leaf)) { throw "Failed upgrade did not restore the previous current directory." }
    $restoredConfig = (Get-Content -LiteralPath (Join-Path $TestUserProfile ".openclaw\openclaw.json") -Raw).Trim()
    if ($restoredConfig -ne $rollbackConfig) { throw "Failed upgrade did not restore the previous OpenClaw configuration." }
    if (-not (Test-Path -LiteralPath $previousPluginMarker -PathType Leaf)) { throw "Failed upgrade did not restore the previous AgentMeter-Gov plugin." }
    $commands = Get-Content -LiteralPath $FakeLog
    if ($commands -match "plugins disable existing-channel|plugins uninstall existing-channel") {
        throw "Installer attempted to disable or uninstall an unrelated plugin."
    }

    & powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PackageRoot.FullName "installer\uninstall.ps1") -ArchiveParent $ArchiveParent
    if ($LASTEXITCODE -ne 0) { throw "The isolated uninstaller returned $LASTEXITCODE." }
    if (Test-Path -LiteralPath $InstallRoot) { throw "Install root still exists after uninstall." }
    foreach ($shortcutPath in @($DesktopShortcutPath, $StartMenuShortcutPath)) {
        if (Test-Path -LiteralPath $shortcutPath) { throw "Desktop pet shortcut still exists: $shortcutPath" }
    }
    $remainingAutoStart = $null
    if (Test-Path -LiteralPath $AutoStartRegistryPath) {
        $remainingAutoStart = (Get-Item -LiteralPath $AutoStartRegistryPath).GetValue($AutoStartValueName, $null)
    }
    if ($remainingAutoStart) { throw "Desktop pet auto-start entry still exists after uninstall." }
    $archivedMarker = Get-ChildItem -LiteralPath $ArchiveParent -Filter "installer-test-audit.jsonl" -File -Recurse | Select-Object -First 1
    if (-not $archivedMarker) { throw "Audit data was not preserved during uninstall." }

    if (-not [string]::IsNullOrWhiteSpace($SetupExe)) {
        $SetupExe = [System.IO.Path]::GetFullPath($SetupExe)
        if (-not (Test-Path -LiteralPath $SetupExe -PathType Leaf)) { throw "Setup.exe was not found: $SetupExe" }
        Remove-Item -LiteralPath (Join-Path $FakeState "gateway-service"), (Join-Path $FakeState "gateway-running"), (Join-Path $FakeState "plugin-installed") -Force -ErrorAction SilentlyContinue
        $env:AGENTMETER_FAKE_PLUGIN_DRIFT = "1"
        $failedSetupRoot = Join-Path $TestRoot "failed-setup-program"
        $failedSetupProcess = Start-Process -FilePath $SetupExe -ArgumentList @(
            "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/DIR=$failedSetupRoot",
            "/SERVICEBASEURL=$ServiceBaseUrl"
        ) -Wait -PassThru
        Remove-Item Env:AGENTMETER_FAKE_PLUGIN_DRIFT -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath (Join-Path $FakeState "unrelated-plugin-drift") -Force -ErrorAction SilentlyContinue
        if ($failedSetupProcess.ExitCode -eq 0) { throw "Setup.exe returned success after its installation core failed." }
        if (Test-Path -LiteralPath $StatePath) { throw "Failed Setup.exe left an install-state marker." }

        $setupProgramRoot = Join-Path $TestRoot "setup-program"
        $setupLog = Join-Path $TestRoot "setup.log"
        $setupProcess = Start-Process -FilePath $SetupExe -ArgumentList @(
            "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/DIR=$setupProgramRoot",
            "/SERVICEBASEURL=$ServiceBaseUrl", "/LOG=$setupLog"
        ) -Wait -PassThru
        if ($setupProcess.ExitCode -ne 0) { throw "Setup.exe returned $($setupProcess.ExitCode). See $setupLog" }
        if (-not (Test-Path -LiteralPath $StatePath -PathType Leaf)) {
            $setupLogText = if (Test-Path -LiteralPath $setupLog) { Get-Content -LiteralPath $setupLog -Raw } else { "(setup log missing)" }
            throw "Setup.exe did not create install state.`n$setupLogText"
        }
        if (-not (Test-Path -LiteralPath (Join-Path $InstallRoot "backend\AgentMeterGovBackend.exe") -PathType Leaf)) { throw "Setup.exe did not install the backend." }
        $setupMarker = Join-Path $InstallRoot "backend\_internal\data\setup-test-audit.jsonl"
        Set-Content -LiteralPath $setupMarker -Value '{"event":"setup-test"}' -Encoding UTF8
        $uninstaller = Join-Path $setupProgramRoot "unins000.exe"
        if (-not (Test-Path -LiteralPath $uninstaller -PathType Leaf)) { throw "Windows uninstaller entry was not created." }
        $uninstallProcess = Start-Process -FilePath $uninstaller -ArgumentList @("/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART") -Wait -PassThru
        if ($uninstallProcess.ExitCode -ne 0) { throw "Setup.exe uninstaller returned $($uninstallProcess.ExitCode)." }
        if (Test-Path -LiteralPath $InstallRoot) { throw "Setup.exe uninstall left the program directory behind." }
        $setupArchive = Join-Path $TestLocalAppData "AgentMeter-Gov-Archive"
        if (-not (Get-ChildItem -LiteralPath $setupArchive -Filter "setup-test-audit.jsonl" -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1)) {
            throw "Setup.exe uninstall did not preserve audit data."
        }
    }

    Write-Host "Windows installer and Setup.exe compatibility, repair, upgrade and uninstall tests passed." -ForegroundColor Green
} finally {
    $env:PATH = $oldPath
    $env:LOCALAPPDATA = $oldLocalAppData
    $env:USERPROFILE = $oldUserProfile
    $env:PSModuleAnalysisCachePath = $oldModuleAnalysisCachePath
    Remove-Item Env:AGENTMETER_FAKE_OPENCLAW_STATE -ErrorAction SilentlyContinue
    Remove-Item Env:AGENTMETER_FAKE_OPENCLAW_LOG -ErrorAction SilentlyContinue
    Remove-Item Env:AGENTMETER_FAKE_EXISTING_UNHEALTHY -ErrorAction SilentlyContinue
    Remove-Item Env:AGENTMETER_FAKE_PLUGIN_DRIFT -ErrorAction SilentlyContinue
    if ($listenerJob) {
        try { Invoke-WebRequest -UseBasicParsing -Uri "$ServiceBaseUrl/shutdown" -TimeoutSec 2 | Out-Null } catch { }
        Wait-Job $listenerJob -Timeout 5 -ErrorAction SilentlyContinue | Out-Null
        Stop-Job $listenerJob -ErrorAction SilentlyContinue
        Remove-Job $listenerJob -Force -ErrorAction SilentlyContinue
    }
    if ($conflictListenerJob) {
        try { Invoke-WebRequest -UseBasicParsing -Uri "$ConflictServiceBaseUrl/shutdown" -TimeoutSec 2 | Out-Null } catch { }
        Wait-Job $conflictListenerJob -Timeout 5 -ErrorAction SilentlyContinue | Out-Null
        Stop-Job $conflictListenerJob -ErrorAction SilentlyContinue
        Remove-Job $conflictListenerJob -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $AutoStartRegistryPath) {
        Remove-Item -LiteralPath $AutoStartRegistryPath -Recurse -Force
    }
    if (Test-Path -LiteralPath $TestRoot) {
        Assert-Under $TestRoot $env:TEMP
        Remove-Item -LiteralPath $TestRoot -Recurse -Force
    }
}
