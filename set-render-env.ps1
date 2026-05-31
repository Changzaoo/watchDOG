# Le as credenciais do backend/.env e aplica no Render
# Nunca hardcode credenciais - sempre leia de arquivos de ambiente

param(
    [string]$RenderApiKey = $env:RENDER_API_KEY,
    [string]$ServiceId = "srv-d8e4n28js32c73850r3g"
)

if (-not $RenderApiKey) {
    $RenderApiKey = Read-Host "Render API Key"
}

$envFile = "$PSScriptRoot\backend\.env"
if (-not (Test-Path $envFile)) {
    Write-Error "Arquivo nao encontrado: $envFile"
    exit 1
}

$vars = @{}
Get-Content $envFile | ForEach-Object {
    $line = $_.Trim()
    if ($line -and -not $line.StartsWith('#')) {
        $idx = $line.IndexOf('=')
        if ($idx -gt 0) {
            $key = $line.Substring(0, $idx).Trim()
            $val = $line.Substring($idx + 1).Trim().Trim('"')
            $vars[$key] = $val
        }
    }
}

# Sobrescreve apenas os valores de producao que diferem do dev
$vars["NODE_ENV"]          = "production"
$vars["DATABASE_URL"]      = "file:/var/data/watchdog.db"
$vars["ENABLE_LOCAL_SCANS"] = "false"
$vars["CORS_ORIGINS"]      = "https://watchdog-chi.vercel.app"
$vars["AUTH_REQUIRED"]     = "true"

$payload = $vars.GetEnumerator() | ForEach-Object {
    [PSCustomObject]@{ key = $_.Key; value = $_.Value }
} | ConvertTo-Json -Depth 3

$headers = @{
    "Authorization" = "Bearer $RenderApiKey"
    "Accept"        = "application/json"
    "Content-Type"  = "application/json"
}

Write-Host "Aplicando $($vars.Count) variaveis ao servico $ServiceId..." -ForegroundColor Cyan

try {
    $response = Invoke-RestMethod `
        -Uri "https://api.render.com/v1/services/$ServiceId/env-vars" `
        -Method PUT `
        -Headers $headers `
        -Body $payload

    Write-Host "OK! $($response.Count) variaveis configuradas." -ForegroundColor Green
    Write-Host "O Render vai reiniciar o servico. Aguarde ~1 minuto." -ForegroundColor Yellow
}
catch {
    Write-Host "Erro: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ($_.ErrorDetails.Message)
}
