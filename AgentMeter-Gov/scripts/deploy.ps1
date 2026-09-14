param(
    [ValidateSet("sqlite", "postgres")]
    [string]$Mode = "sqlite"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    throw "Created .env from .env.example. Set production secrets, then run this script again."
}

if ($Mode -eq "postgres") {
    docker compose up -d --build
} else {
    docker build -t agentmeter-gov:local .
    docker run -d --name agentmeter-gov --restart unless-stopped --env-file .env -p 8765:8765 -v "${Root}/data:/app/data" -v "${Root}/audit_reports:/app/audit_reports" agentmeter-gov:local
}

Write-Host "AgentMeter-Gov is available at http://127.0.0.1:8765"
