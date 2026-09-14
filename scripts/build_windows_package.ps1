[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Python,
    [string]$OutputDir,
    [string]$InnoCompiler
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$RepoRoot = [System.IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$DistRoot = [System.IO.Path]::GetFullPath((Join-Path $RepoRoot "dist"))
if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $DistRoot "packages"
}
$OutputDir = [System.IO.Path]::GetFullPath($OutputDir)
$Version = (Get-Content -LiteralPath (Join-Path $RepoRoot "VERSION") -Raw).Trim()
$PackageName = "AgentMeter-Gov-$Version-Windows-x64"
$PackageFolder = "AgentMeter-Gov-$Version"
$BuildRoot = Join-Path $DistRoot ("package-build-" + [guid]::NewGuid().ToString("N"))
$RuntimeStage = Join-Path $BuildRoot "runtime-source"
$PyInstallerDist = Join-Path $BuildRoot "pyinstaller-dist"
$PyInstallerWork = Join-Path $BuildRoot "pyinstaller-work"
$PackageRoot = Join-Path $BuildRoot $PackageFolder
$PayloadRoot = Join-Path $PackageRoot "payload"
$InnoScript = Join-Path $RepoRoot "packaging\windows\AgentMeter-Gov.iss"

function Assert-UnderDist([string]$Path) {
    $resolved = [System.IO.Path]::GetFullPath($Path)
    if (-not $resolved.StartsWith($DistRoot + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to operate on a build path outside the repository dist directory: $resolved"
    }
}

function Copy-CmdWithWindowsLineEndings([string]$Source, [string]$Destination) {
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    $content = [System.IO.File]::ReadAllText($Source, $utf8NoBom)
    $content = $content -replace "`r`n|`r|`n", "`r`n"
    [System.IO.File]::WriteAllText($Destination, $content, $utf8NoBom)

    $written = [System.IO.File]::ReadAllText($Destination, $utf8NoBom)
    if ($written -match "(?<!`r)`n|`r(?!`n)") {
        throw "Windows command file does not use CRLF line endings: $Destination"
    }
}

function Copy-PowerShellWithUtf8Bom([string]$Source, [string]$Destination) {
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    $utf8Bom = [System.Text.UTF8Encoding]::new($true)
    $content = [System.IO.File]::ReadAllText($Source, $utf8NoBom)
    [System.IO.File]::WriteAllText($Destination, $content, $utf8Bom)
}

try {
    if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
        throw "Build Python not found: $Python"
    }
    & $Python -m PyInstaller --version | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller is missing from this Python environment. Install packaging\requirements-build.txt first."
    }
    if ([string]::IsNullOrWhiteSpace($InnoCompiler)) {
        $innoCandidates = @(
            (Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe"),
            (Join-Path $env:ProgramFiles "Inno Setup 6\ISCC.exe"),
            (Join-Path $env:LOCALAPPDATA "Programs\Inno Setup 6\ISCC.exe")
        )
        $InnoCompiler = $innoCandidates | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -First 1
    }
    if (-not $InnoCompiler -or -not (Test-Path -LiteralPath $InnoCompiler -PathType Leaf)) {
        throw "Inno Setup 6 compiler was not found. Install JRSoftware.InnoSetup before building Setup.exe."
    }

    Assert-UnderDist $BuildRoot
    New-Item -ItemType Directory -Path $RuntimeStage, $PayloadRoot, $OutputDir -Force | Out-Null

    Write-Host "[1/6] Collecting Git-tracked backend, frontend and baseline data..." -ForegroundColor Cyan
    $trackedFiles = & git -c core.quotePath=false -C $RepoRoot ls-files -- "AgentMeter-Gov/server.py" "AgentMeter-Gov/agentmeter_gov" "AgentMeter-Gov/frontend" "AgentMeter-Gov/data"
    if ($LASTEXITCODE -ne 0 -or -not $trackedFiles) {
        throw "Could not read the Git-tracked file list."
    }
    foreach ($relativeFile in $trackedFiles) {
        $runtimeRelative = $relativeFile.Substring("AgentMeter-Gov/".Length)
        $source = Join-Path $RepoRoot ($relativeFile -replace '/', '\')
        $destination = Join-Path $RuntimeStage ($runtimeRelative -replace '/', '\')
        New-Item -ItemType Directory -Path (Split-Path $destination -Parent) -Force | Out-Null
        Copy-Item -LiteralPath $source -Destination $destination -Force
    }

    Write-Host "[2/6] Building the standalone Windows backend..." -ForegroundColor Cyan
    $dataArgument = (Join-Path $RuntimeStage "data") + ";data"
    $frontendArgument = (Join-Path $RuntimeStage "frontend") + ";frontend"
    & $Python -m PyInstaller --noconfirm --clean --onedir --noconsole `
        --name AgentMeterGovBackend `
        --distpath $PyInstallerDist `
        --workpath $PyInstallerWork `
        --specpath $BuildRoot `
        --paths $RuntimeStage `
        --add-data $dataArgument `
        --add-data $frontendArgument `
        (Join-Path $RuntimeStage "server.py")
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller backend build failed."
    }

    Write-Host "[3/6] Assembling the plugin and one-click entry points..." -ForegroundColor Cyan
    Copy-Item -LiteralPath (Join-Path $PyInstallerDist "AgentMeterGovBackend") -Destination (Join-Path $PayloadRoot "backend") -Recurse -Force
    New-Item -ItemType Directory -Path (Join-Path $PayloadRoot "plugin") -Force | Out-Null
    $pluginFiles = & git -c core.quotePath=false -C $RepoRoot ls-files -- "agentmeter-gov-openclaw-plugin"
    foreach ($relativeFile in $pluginFiles) {
        if ($relativeFile -match '/(test-|demo-).*\.mjs$') { continue }
        $pluginRelative = $relativeFile.Substring("agentmeter-gov-openclaw-plugin/".Length)
        $source = Join-Path $RepoRoot ($relativeFile -replace '/', '\')
        $destination = Join-Path (Join-Path $PayloadRoot "plugin") ($pluginRelative -replace '/', '\')
        New-Item -ItemType Directory -Path (Split-Path $destination -Parent) -Force | Out-Null
        Copy-Item -LiteralPath $source -Destination $destination -Force
    }
    Copy-CmdWithWindowsLineEndings `
        (Join-Path $RepoRoot "packaging\windows\install.cmd") `
        (Join-Path $PackageRoot "install.cmd")
    Copy-CmdWithWindowsLineEndings `
        (Join-Path $RepoRoot "packaging\windows\uninstall.cmd") `
        (Join-Path $PackageRoot "uninstall.cmd")
    Copy-Item -LiteralPath (Join-Path $RepoRoot "packaging\windows\README-INSTALL.txt") -Destination $PackageRoot -Force
    $installerTarget = Join-Path $PackageRoot "installer"
    New-Item -ItemType Directory -Path $installerTarget -Force | Out-Null
    foreach ($installerScript in @("install.ps1", "uninstall.ps1")) {
        Copy-PowerShellWithUtf8Bom `
            (Join-Path $RepoRoot "packaging\windows\installer\$installerScript") `
            (Join-Path $installerTarget $installerScript)
    }
    $desktopPayload = Join-Path $PayloadRoot "desktop"
    New-Item -ItemType Directory -Path $desktopPayload -Force | Out-Null
    Copy-PowerShellWithUtf8Bom `
        (Join-Path $RepoRoot "scripts\launch_desktop_pet.ps1") `
        (Join-Path $desktopPayload "launch_desktop_pet.ps1")
    Copy-Item -LiteralPath (Join-Path $RepoRoot "scripts\launch_desktop_pet.vbs") -Destination (Join-Path $desktopPayload "launch_desktop_pet.vbs") -Force
    Copy-PowerShellWithUtf8Bom `
        (Join-Path $RepoRoot "scripts\start_desktop_pet.ps1") `
        (Join-Path $desktopPayload "start_desktop_pet.ps1")
    Copy-PowerShellWithUtf8Bom `
        (Join-Path $RepoRoot "scripts\open_security_audit.ps1") `
        (Join-Path $desktopPayload "open_security_audit.ps1")

    $commit = (& git -C $RepoRoot rev-parse --short=12 HEAD).Trim()
    $manifest = [ordered]@{
        product = "AgentMeter-Gov"
        version = $Version
        platform = "windows-x64"
        build_commit = $commit
        built_at = (Get-Date).ToUniversalTime().ToString("o")
        backend = "PyInstaller onedir"
        python_required_on_target = $false
        openclaw_required = $true
        desktop_entry = "AgentMeter-Gov desktop pet"
        installer = "Inno Setup 6"
        upgrade_mode = "transactional-in-place"
        minimum_openclaw_version = "2026.6.5"
    }
    $manifest | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $PackageRoot "package-manifest.json") -Encoding UTF8

    Write-Host "[4/6] Starting the packaged backend and running health checks..." -ForegroundColor Cyan
    $backendExe = Join-Path $PayloadRoot "backend\AgentMeterGovBackend.exe"
    $testPort = 18765
    $previousHost = $env:AGENTMETER_HOST
    $previousPort = $env:AGENTMETER_PORT
    $previousRuntime = $env:AGENTMETER_GOV_HOME
    $env:AGENTMETER_HOST = "127.0.0.1"
    $env:AGENTMETER_PORT = "$testPort"
    $env:AGENTMETER_GOV_HOME = (Join-Path $PayloadRoot "backend\_internal")
    $testProcess = Start-Process -FilePath $backendExe -WorkingDirectory (Join-Path $PayloadRoot "backend\_internal") -WindowStyle Hidden -PassThru
    try {
        $ready = $false
        for ($attempt = 0; $attempt -lt 30; $attempt += 1) {
            try {
                $health = Invoke-RestMethod -Uri "http://127.0.0.1:$testPort/health" -TimeoutSec 1
                if ($health.status -eq "ok" -or $health.ok -eq $true) { $ready = $true; break }
            } catch { Start-Sleep -Milliseconds 500 }
        }
        if (-not $ready) { throw "The packaged backend health check failed." }
        $page = Invoke-WebRequest -Uri "http://127.0.0.1:$testPort/" -TimeoutSec 3 -UseBasicParsing
        if ($page.StatusCode -ne 200) { throw "The monitoring page health check failed." }
    } finally {
        $testProcessStopped = $true
        if ($testProcess -and -not $testProcess.HasExited) {
            Stop-Process -Id $testProcess.Id -Force
            # Stop-Process only signals termination. Compress-Archive can race
            # the final Windows image/file-handle cleanup unless we explicitly
            # wait for the packaged backend to exit.
            $testProcessStopped = $testProcess.WaitForExit(10000)
        }
        $env:AGENTMETER_HOST = $previousHost
        $env:AGENTMETER_PORT = $previousPort
        $env:AGENTMETER_GOV_HOME = $previousRuntime
        if (-not $testProcessStopped) {
            throw "The packaged backend did not exit after its health check."
        }
    }

    Write-Host "      Removing runtime files created by the package health check..." -ForegroundColor DarkGray
    $packagedDataRoot = Join-Path $PayloadRoot "backend\_internal\data"
    Get-ChildItem -LiteralPath $packagedDataRoot -File -Recurse | ForEach-Object {
        $relativeDataPath = $_.FullName.Substring($packagedDataRoot.Length).TrimStart('\')
        $baselinePath = Join-Path (Join-Path $RuntimeStage "data") $relativeDataPath
        if (-not (Test-Path -LiteralPath $baselinePath -PathType Leaf)) {
            Remove-Item -LiteralPath $_.FullName -Force
        }
    }
    $packagedReports = Join-Path $PayloadRoot "backend\_internal\audit_reports"
    if (Test-Path -LiteralPath $packagedReports) {
        Remove-Item -LiteralPath $packagedReports -Recurse -Force
    }
    $forbiddenRuntimeFiles = Get-ChildItem -LiteralPath $packagedDataRoot -File -Recurse | Where-Object {
        $_.Name -match '\.(db|db-wal|db-shm)$' -or
        $_.Name -match '\.jsonl(\.|$)' -or
        $_.Name -in @("openclaw_guard_approvals.json", "user_profiles.json", "review_memory.json")
    }
    if ($forbiddenRuntimeFiles) {
        throw "Runtime data leaked into the package: $($forbiddenRuntimeFiles.FullName -join ', ')"
    }

    Write-Host "[5/6] Creating the diagnostic ZIP and SHA256 file..." -ForegroundColor Cyan
    $zipPath = Join-Path $OutputDir "$PackageName.zip"
    $hashPath = "$zipPath.sha256.txt"
    if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
    Compress-Archive -LiteralPath $PackageRoot -DestinationPath $zipPath -CompressionLevel Optimal
    $hash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $PackageName.zip" | Set-Content -LiteralPath $hashPath -Encoding ASCII
    Write-Host "Package: $zipPath" -ForegroundColor Green
    Write-Host "SHA256: $hash"

    Write-Host "[6/6] Compiling the Windows Setup.exe..." -ForegroundColor Cyan
    & $InnoCompiler "/DPackageRoot=$PackageRoot" "/DOutputDir=$OutputDir" "/DAppVersion=$Version" $InnoScript
    if ($LASTEXITCODE -ne 0) { throw "Inno Setup compilation failed." }
    $setupPath = Join-Path $OutputDir "AgentMeter-Gov-Setup-$Version.exe"
    if (-not (Test-Path -LiteralPath $setupPath -PathType Leaf)) { throw "Setup.exe was not produced: $setupPath" }
    $setupHash = (Get-FileHash -LiteralPath $setupPath -Algorithm SHA256).Hash.ToLowerInvariant()
    "$setupHash  AgentMeter-Gov-Setup-$Version.exe" | Set-Content -LiteralPath "$setupPath.sha256.txt" -Encoding ASCII
    Write-Host "Setup: $setupPath" -ForegroundColor Green
    Write-Host "SHA256: $setupHash"
} finally {
    if (Test-Path -LiteralPath $BuildRoot) {
        Assert-UnderDist $BuildRoot
        Remove-Item -LiteralPath $BuildRoot -Recurse -Force
    }
}
