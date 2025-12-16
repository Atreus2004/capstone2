param(
    [string]$DashboardPassword = $env:FIM_DASHBOARD_PASSWORD,
    [string]$AdminPassword = $env:FIM_ADMIN_PASSWORD,
    [string]$OpenAiApiKey = $env:OPENAI_API_KEY,
    [string]$ConfigPath = "config\config.yaml",
    [string]$Host = "0.0.0.0",
    [string]$Port = "8000"
)

if (-not $DashboardPassword) { throw "FIM_DASHBOARD_PASSWORD is required (pass via -DashboardPassword or env var)." }
if (-not $AdminPassword)    { throw "FIM_ADMIN_PASSWORD is required (pass via -AdminPassword or env var)." }
if (-not $OpenAiApiKey)     { throw "OPENAI_API_KEY is required (pass via -OpenAiApiKey or env var)." }

$env:FIM_DASHBOARD_PASSWORD = $DashboardPassword
$env:FIM_ADMIN_PASSWORD = $AdminPassword
$env:OPENAI_API_KEY = $OpenAiApiKey

$agent = Start-Process -FilePath "py" -ArgumentList "-m fim_agent.cli.main --config `"$ConfigPath`" run-agent" -PassThru
$web = Start-Process -FilePath "py" -ArgumentList "-m fim_agent.cli.main --config `"$ConfigPath`" serve-web --host $Host --port $Port" -PassThru

Write-Host "Started run-agent (PID $($agent.Id)) and serve-web (PID $($web.Id)). They continue running in the background." -ForegroundColor Green
