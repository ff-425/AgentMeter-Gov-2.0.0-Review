param(
    [string]$OpenClaw = "openclaw",
    [int]$TimeoutSeconds = 180
)

$ErrorActionPreference = "Stop"
$runStamp = Get-Date -Format "yyyyMMdd-HHmmss"

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Invoke-WeixinTurn {
    param(
        [string]$SessionKey,
        [string]$Message,
        [string]$MessageId
    )
    $fence = ([char]96).ToString() * 3
    $wrapped = @(
        "Conversation info (untrusted metadata):"
        "${fence}json"
        "{`"chat_id`":`"agentmeter-approval-test@im.wechat`",`"message_id`":`"openclaw-weixin:$MessageId`",`"timestamp`":`"$(Get-Date -Format o)`"}"
        $fence
        ""
        $Message
    ) -join "`n"
    $stderrPath = Join-Path $env:TEMP "agentmeter-weixin-approval-$runStamp-$MessageId.stderr.txt"
    $raw = (& $OpenClaw agent --session-key $SessionKey --message $wrapped --json --timeout $TimeoutSeconds 2>$stderrPath | Out-String)
    if ($LASTEXITCODE -ne 0) {
        $stderr = if (Test-Path -LiteralPath $stderrPath) { Get-Content -LiteralPath $stderrPath -Raw } else { "" }
        throw "OpenClaw turn $MessageId failed: $stderr"
    }
    $payload = $raw | ConvertFrom-Json
    Assert-True ($payload.status -eq "ok") "OpenClaw turn $MessageId returned $($payload.status)"
    $sessionFile = [string]$payload.result.meta.agentMeta.sessionFile
    [pscustomobject]@{
        run_id = [string]$payload.runId
        final_text = (($payload.result.payloads | ForEach-Object { $_.text }) -join "`n")
        session_file = $sessionFile
        session_raw = Get-Content -LiteralPath $sessionFile -Raw
    }
}

$health = (& $OpenClaw health --json | Out-String) | ConvertFrom-Json
Assert-True ($health.ok -eq $true) "OpenClaw gateway health check failed"
Assert-True ($health.plugins.loaded -contains "agentmeter-gov-guard") "agentmeter-gov-guard is not loaded"

$workspace = ((& $OpenClaw config get agents.defaults.workspace | Out-String).Trim())
$relativePath = "agentmeter_weixin_approval/$runStamp/contact.txt"
$targetPath = Join-Path $workspace ($relativePath -replace "/", "\")
$originSessionKey = "agent:main:agentmeter-web:direct:agentmeter-approval-origin-$runStamp"
$approvalSessionKey = "agent:main:openclaw-weixin:direct:agentmeter-approval-mobile-$runStamp@im.wechat"
$content = "AgentMeter approval test contact: 13800000001."
$requestMessage = "Use only the write tool to write this exact content to ${relativePath}:`n${content}`nDo not use exec or another tool. If review is required, report only the approval ID and stop."

$first = Invoke-WeixinTurn -SessionKey $originSessionKey -Message $requestMessage -MessageId "request"
Assert-True (-not (Test-Path -LiteralPath $targetPath)) "Sensitive test file was written before approval"
$approvalMatch = [regex]::Match("$($first.final_text)`n$($first.session_raw)", "AGR-[A-Z0-9-]+")
Assert-True $approvalMatch.Success "The first Weixin-shaped turn did not return an approval ID"
$reviewId = $approvalMatch.Value

# Build the Chinese phrase from JSON escapes so Windows PowerShell 5.1 can
# parse this UTF-8-without-BOM test script on every supported Windows host.
$approvalPrefix = ConvertFrom-Json '"\u5ba1\u6279\u901a\u8fc7"'
$second = Invoke-WeixinTurn -SessionKey $approvalSessionKey -Message "$approvalPrefix $reviewId" -MessageId "approve"
$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
while (-not (Test-Path -LiteralPath $targetPath) -and (Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 500
}
Assert-True (Test-Path -LiteralPath $targetPath) "Approved action was not resumed from the Weixin-shaped reply"
$actualContent = [System.IO.File]::ReadAllText($targetPath).Trim()
Assert-True ($actualContent -eq $content) "Approved continuation did not execute the exact reviewed local-file action"

[pscustomobject]@{
    schema_version = "agentmeter.openclaw.weixin-approval-live.v1"
    execution_mode = "actual_local_openclaw"
    origin_session_key = $originSessionKey
    approval_session_key = $approvalSessionKey
    cross_session_approval = ($originSessionKey -ne $approvalSessionKey)
    review_id = $reviewId
    request_run_id = $first.run_id
    approval_run_id = $second.run_id
    target_path = $targetPath
    exact_reviewed_action_executed = $true
    passed = $true
} | ConvertTo-Json -Depth 5
