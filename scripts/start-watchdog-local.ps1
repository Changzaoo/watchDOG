param(
  [int]$PreferredFrontendPort = 43173,
  [int]$PreferredBackendPort = 43174,
  [string]$NgrokUrl = 'https://prance-mummified-subscript.ngrok-free.dev',
  [switch]$OpenBrowser,
  [switch]$SkipNgrok,
  [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root = (Resolve-Path (Join-Path $ScriptDir '..')).Path
$LogDir = Join-Path $Root 'logs'
$StatePath = Join-Path $LogDir 'watchdog-local-state.json'
$UrlPath = Join-Path $LogDir 'watchdog-local-url.txt'
$NgrokApiUrl = 'http://127.0.0.1:4040/api/tunnels'

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

function Test-CommandAvailable {
  param([string]$Name)
  return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function ConvertTo-PowerShellLiteral {
  param([string]$Value)
  return "'" + $Value.Replace("'", "''") + "'"
}

function Test-PortAvailable {
  param([int]$Port)

  $listener = $null
  try {
    $address = [System.Net.IPAddress]::Parse('127.0.0.1')
    $listener = [System.Net.Sockets.TcpListener]::new($address, $Port)
    $listener.ExclusiveAddressUse = $true
    $listener.Start()
    return $true
  } catch {
    return $false
  } finally {
    if ($null -ne $listener) {
      $listener.Stop()
    }
  }
}

function Get-FreeHighPort {
  param(
    [int]$PreferredPort,
    [int[]]$ReservedPorts = @()
  )

  if ($PreferredPort -lt 1024 -or $PreferredPort -gt 49151) {
    throw "Preferred port must be between 1024 and 49151. Windows usually reserves 49152-65535 for dynamic client ports."
  }

  for ($port = $PreferredPort; $port -le 49151; $port++) {
    if ($ReservedPorts -contains $port) {
      continue
    }
    if (Test-PortAvailable -Port $port) {
      return $port
    }
  }

  for ($port = 43000; $port -lt $PreferredPort; $port++) {
    if ($ReservedPorts -contains $port) {
      continue
    }
    if (Test-PortAvailable -Port $port) {
      return $port
    }
  }

  throw "No available high port was found in the 43000-49151 range."
}

function Test-ProcessAlive {
  param([int]$ProcessId)

  if ($ProcessId -le 0) {
    return $false
  }

  try {
    Get-Process -Id $ProcessId -ErrorAction Stop | Out-Null
    return $true
  } catch {
    return $false
  }
}

function Test-TcpPortOpen {
  param([int]$Port)

  $client = $null
  try {
    $client = [System.Net.Sockets.TcpClient]::new()
    $connect = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
    if (-not $connect.AsyncWaitHandle.WaitOne(1000, $false)) {
      return $false
    }
    $client.EndConnect($connect)
    return $true
  } catch {
    return $false
  } finally {
    if ($null -ne $client) {
      $client.Close()
    }
  }
}

function Wait-HttpOk {
  param(
    [string]$Url,
    [int]$TimeoutSeconds = 45,
    [int]$RequestTimeoutSeconds = 5
  )

  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  while ((Get-Date) -lt $deadline) {
    try {
      $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec $RequestTimeoutSeconds
      if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 500) {
        return $true
      }
    } catch {
      Start-Sleep -Seconds 1
    }
  }

  return $false
}

function Get-NgrokTunnel {
  try {
    $response = Invoke-RestMethod -Uri $NgrokApiUrl -TimeoutSec 3
    $tunnels = @($response.tunnels)

    if ($NgrokUrl) {
      $match = $tunnels |
        Where-Object { $_.proto -eq 'https' -and $_.public_url -eq $NgrokUrl } |
        Select-Object -First 1
      if ($null -ne $match) {
        return $match
      }
    }

    return $tunnels |
      Where-Object { $_.proto -eq 'https' } |
      Select-Object -First 1
  } catch {
    return $null
  }
}

function Stop-NgrokAgents {
  Get-Process -Name 'ngrok' -ErrorAction SilentlyContinue | Stop-Process -Force
  Start-Sleep -Seconds 2
}

function Wait-NgrokTunnel {
  param(
    [string]$ExpectedBackendUrl,
    [int]$TimeoutSeconds = 30
  )

  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  while ((Get-Date) -lt $deadline) {
    $tunnel = Get-NgrokTunnel
    if ($null -ne $tunnel -and $tunnel.config.addr -eq $ExpectedBackendUrl) {
      return $tunnel
    }
    Start-Sleep -Seconds 1
  }

  return $null
}

function Ensure-NgrokTunnel {
  param([string]$BackendUrl)

  if ($SkipNgrok) {
    return ''
  }

  if (-not (Test-CommandAvailable -Name 'ngrok.exe')) {
    throw 'ngrok was not found in PATH.'
  }

  $existingTunnel = Get-NgrokTunnel
  if ($null -ne $existingTunnel -and $existingTunnel.config.addr -eq $BackendUrl) {
    return [string]$existingTunnel.public_url
  }

  if ($null -ne $existingTunnel) {
    Stop-NgrokAgents
  }

  $ngrokLog = Join-Path $LogDir 'ngrok-watchdog.log'
  $ngrokErr = Join-Path $LogDir 'ngrok-watchdog.err.log'
  $ngrokExe = (Get-Command 'ngrok.exe').Source
  $args = @('http', $BackendUrl, '--url', $NgrokUrl, '--log=stdout', '--log-format=json')

  $ngrokProcess = Start-Process `
    -FilePath $ngrokExe `
    -ArgumentList $args `
    -WorkingDirectory $Root `
    -RedirectStandardOutput $ngrokLog `
    -RedirectStandardError $ngrokErr `
    -PassThru `
    -WindowStyle Hidden

  $tunnel = Wait-NgrokTunnel -ExpectedBackendUrl $BackendUrl
  if ($null -eq $tunnel) {
    throw "ngrok did not start a tunnel to $BackendUrl. Check $ngrokLog and $ngrokErr."
  }

  $publicHealthUrl = "$($tunnel.public_url)/health"
  if (-not (Wait-HttpOk -Url $publicHealthUrl -TimeoutSeconds 30 -RequestTimeoutSeconds 10)) {
    throw "ngrok tunnel started, but backend did not respond through $publicHealthUrl."
  }

  return [string]$tunnel.public_url
}

function Get-ExistingState {
  if (-not (Test-Path -LiteralPath $StatePath)) {
    return $null
  }

  try {
    return Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
  } catch {
    return $null
  }
}

if (-not (Test-CommandAvailable -Name 'node.exe')) {
  throw 'Node.js was not found in PATH.'
}

if (-not (Test-CommandAvailable -Name 'npm.cmd')) {
  throw 'npm was not found in PATH.'
}

$existing = Get-ExistingState
if ($null -ne $existing) {
  $existingBackendProcessId = 0
  $existingFrontendProcessId = 0
  $existingBackendPort = 0
  $existingFrontendPort = 0
  $existingUrl = ''

  if ($null -ne $existing.backendProcessId) {
    $existingBackendProcessId = [int]$existing.backendProcessId
  }
  if ($null -ne $existing.frontendProcessId) {
    $existingFrontendProcessId = [int]$existing.frontendProcessId
  }
  if ($null -ne $existing.url) {
    $existingUrl = [string]$existing.url
  }
  if ($null -ne $existing.backendPort) {
    $existingBackendPort = [int]$existing.backendPort
  }
  if ($null -ne $existing.frontendPort) {
    $existingFrontendPort = [int]$existing.frontendPort
  }

  $backendAlive = Test-ProcessAlive -ProcessId $existingBackendProcessId
  $frontendAlive = Test-ProcessAlive -ProcessId $existingFrontendProcessId
  $backendPortOpen = $existingBackendPort -gt 0 -and (Test-TcpPortOpen -Port $existingBackendPort)
  $frontendPortOpen = $existingFrontendPort -gt 0 -and (Test-TcpPortOpen -Port $existingFrontendPort)

  if ($backendAlive -and $frontendAlive -and $backendPortOpen -and $frontendPortOpen -and $existingUrl) {
    $existingBackendUrl = "http://127.0.0.1:$existingBackendPort"
    if ($DryRun) {
      Set-Content -LiteralPath $UrlPath -Value $existingUrl
      Write-Host "watchDOG already running at $existingUrl"
      exit 0
    }

    $publicNgrokUrl = Ensure-NgrokTunnel -BackendUrl $existingBackendUrl
    $existingStartedAt = (Get-Date).ToString('o')
    if ($null -ne $existing.startedAt) {
      $existingStartedAt = [string]$existing.startedAt
    }

    $state = [ordered]@{
      url = $existingUrl
      backendUrl = $existingBackendUrl
      ngrokUrl = $publicNgrokUrl
      frontendPort = $existingFrontendPort
      backendPort = $existingBackendPort
      frontendProcessId = $existingFrontendProcessId
      backendProcessId = $existingBackendProcessId
      startedAt = $existingStartedAt
    }

    $state | ConvertTo-Json | Set-Content -LiteralPath $StatePath
    Set-Content -LiteralPath $UrlPath -Value $existingUrl
    Write-Host "watchDOG already running at $existingUrl"
    if ($publicNgrokUrl) {
      Write-Host "ngrok backend: $publicNgrokUrl"
    }
    if ($OpenBrowser) {
      Start-Process $existingUrl
    }
    exit 0
  }
}

$frontendPort = Get-FreeHighPort -PreferredPort $PreferredFrontendPort
$backendPort = Get-FreeHighPort -PreferredPort $PreferredBackendPort -ReservedPorts @($frontendPort)
$appUrl = "http://localhost:$frontendPort"
$backendUrl = "http://127.0.0.1:$backendPort"

if ($DryRun) {
  Write-Host "Frontend: $appUrl"
  Write-Host "Backend:  $backendUrl"
  exit 0
}

$rootLiteral = ConvertTo-PowerShellLiteral -Value $Root
$backendLog = Join-Path $LogDir "backend-$backendPort.log"
$backendErr = Join-Path $LogDir "backend-$backendPort.err.log"
$frontendLog = Join-Path $LogDir "frontend-$frontendPort.log"
$frontendErr = Join-Path $LogDir "frontend-$frontendPort.err.log"
$corsOrigins = "http://localhost:$frontendPort,http://127.0.0.1:$frontendPort"

$backendCommand = @(
  '$ErrorActionPreference = ''Stop'''
  "`$env:PORT = '$backendPort'"
  "`$env:HOST = '127.0.0.1'"
  "`$env:NODE_ENV = 'development'"
  "`$env:PUBLIC_BACKEND = 'false'"
  "`$env:ENABLE_LOCAL_SCANS = 'true'"
  "`$env:AUTH_REQUIRED = 'true'"
  "`$env:ALLOW_PUBLIC_LOCAL_SCANS = 'false'"
  "`$env:PUBLIC_REQUEST_HOSTS = 'watchdog-chi.vercel.app,prance-mummified-subscript.ngrok-free.dev'"
  "`$env:CORS_ORIGINS = '$corsOrigins'"
  "Set-Location -LiteralPath $rootLiteral"
  '& npm.cmd run dev:backend'
) -join '; '

$frontendCommand = @(
  '$ErrorActionPreference = ''Stop'''
  "`$env:VITE_DEV_HOST = '127.0.0.1'"
  "`$env:VITE_DEV_PORT = '$frontendPort'"
  "`$env:VITE_STRICT_PORT = 'true'"
  "`$env:BACKEND_URL = '$backendUrl'"
  "Set-Location -LiteralPath $rootLiteral"
  '& npm.cmd run dev:frontend'
) -join '; '

$powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

$backendProcess = Start-Process `
  -FilePath $powershell `
  -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $backendCommand) `
  -WorkingDirectory $Root `
  -RedirectStandardOutput $backendLog `
  -RedirectStandardError $backendErr `
  -PassThru `
  -WindowStyle Hidden

$healthUrl = "$backendUrl/health"
if (-not (Wait-HttpOk -Url $healthUrl -TimeoutSeconds 60)) {
  throw "Backend did not respond at $healthUrl. Check $backendLog and $backendErr."
}

$frontendProcess = Start-Process `
  -FilePath $powershell `
  -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $frontendCommand) `
  -WorkingDirectory $Root `
  -RedirectStandardOutput $frontendLog `
  -RedirectStandardError $frontendErr `
  -PassThru `
  -WindowStyle Hidden

if (-not (Wait-HttpOk -Url $appUrl -TimeoutSeconds 60)) {
  throw "Frontend did not respond at $appUrl. Check $frontendLog and $frontendErr."
}

$publicNgrokUrl = Ensure-NgrokTunnel -BackendUrl $backendUrl

$state = [ordered]@{
  url = $appUrl
  backendUrl = $backendUrl
  ngrokUrl = $publicNgrokUrl
  frontendPort = $frontendPort
  backendPort = $backendPort
  frontendProcessId = $frontendProcess.Id
  backendProcessId = $backendProcess.Id
  startedAt = (Get-Date).ToString('o')
}

$state | ConvertTo-Json | Set-Content -LiteralPath $StatePath
Set-Content -LiteralPath $UrlPath -Value $appUrl

if ($OpenBrowser) {
  Start-Process $appUrl
}

Write-Host "watchDOG started at $appUrl"
Write-Host "Backend health: $healthUrl"
if ($publicNgrokUrl) {
  Write-Host "ngrok backend: $publicNgrokUrl"
}
Write-Host "Logs: $LogDir"
