$ErrorActionPreference = "Stop"

$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$WorkspaceRoot = (Resolve-Path (Join-Path $ProjectRoot "..\..\..")).Path
$PythonExe = Join-Path $WorkspaceRoot ".venvs\agentmeter-gov\Scripts\python.exe"
$Server = Join-Path $ProjectRoot "server.py"

if (-not (Test-Path $PythonExe)) {
    throw "Python environment not found: $PythonExe"
}

$owners = Get-NetTCPConnection -LocalPort 8765 -ErrorAction SilentlyContinue |
    Where-Object { $_.State -eq "Listen" -and $_.OwningProcess -gt 0 } |
    Select-Object -ExpandProperty OwningProcess -Unique

foreach ($owner in $owners) {
    Stop-Process -Id $owner -Force -ErrorAction SilentlyContinue
}

$env:AGENTMETER_SEMANTIC_BACKEND = "bge"
$env:AGENTMETER_SEMANTIC_MODEL = "BAAI/bge-small-zh-v1.5"
$env:AGENTMETER_MODEL_CACHE = Join-Path $WorkspaceRoot "hf-cache\sentence-transformers"
$env:HF_HOME = Join-Path $WorkspaceRoot "hf-cache"
$env:SENTENCE_TRANSFORMERS_HOME = Join-Path $WorkspaceRoot "hf-cache\sentence-transformers"
$env:HF_HUB_DISABLE_SYMLINKS_WARNING = "1"

Start-Process -FilePath $PythonExe -ArgumentList $Server -WorkingDirectory $ProjectRoot -WindowStyle Hidden
Start-Sleep -Seconds 5

$listener = Get-NetTCPConnection -LocalPort 8765 -ErrorAction SilentlyContinue |
    Where-Object { $_.State -eq "Listen" } |
    Select-Object -First 1

if (-not $listener) {
    throw "AgentMeter-Gov did not start on 127.0.0.1:8765"
}

$warmupPayload = @{
    task_id = "agentmeter-warmup"
    title = "BGE warmup"
    user_goal = "read public note"
    input_sources = @(
        @{
            name = "warmup"
            type = "system"
            trust = "high"
            content = "public local read warmup"
        }
    )
    history_events = @()
    proposed_tool_call = @{
        name = "read_document"
        params = @{ path = "agentmeter_demo/public_policy_note.txt" }
        source = "agentmeter_warmup"
        data_level = "public"
        result = "preparing"
        evidence = "Warm up semantic model before live OpenClaw hook traffic."
    }
} | ConvertTo-Json -Depth 8

try {
    Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:8765/api/gate" -Method POST -ContentType "application/json; charset=utf-8" -Body $warmupPayload -TimeoutSec 60 | Out-Null
    Write-Host "BGE warmup request completed."
} catch {
    Write-Warning "BGE warmup failed: $($_.Exception.Message)"
}

Write-Host "AgentMeter-Gov started with BGE backend on http://127.0.0.1:8765"
Write-Host "Python: $PythonExe"
Write-Host "Model cache: $env:AGENTMETER_MODEL_CACHE"
