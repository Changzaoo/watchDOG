param(
  [string]$TaskName = 'watchDOG Local',
  [int]$PreferredFrontendPort = 43173,
  [int]$PreferredBackendPort = 43174,
  [string]$NgrokUrl = 'https://prance-mummified-subscript.ngrok-free.dev',
  [switch]$OpenBrowser,
  [switch]$SkipNgrok,
  [switch]$SkipStartNow
)

$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root = (Resolve-Path (Join-Path $ScriptDir '..')).Path
$StartScript = Join-Path $ScriptDir 'start-watchdog-local.ps1'

if (-not (Test-Path -LiteralPath $StartScript)) {
  throw "Startup script not found: $StartScript"
}

function Quote-Argument {
  param([string]$Value)
  return '"' + $Value.Replace('"', '\"') + '"'
}

$powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$arguments = @(
  '-NoProfile',
  '-ExecutionPolicy',
  'Bypass',
  '-File',
  (Quote-Argument -Value $StartScript),
  '-PreferredFrontendPort',
  $PreferredFrontendPort,
  '-PreferredBackendPort',
  $PreferredBackendPort,
  '-NgrokUrl',
  (Quote-Argument -Value $NgrokUrl)
)

if ($OpenBrowser) {
  $arguments += '-OpenBrowser'
}

if ($SkipNgrok) {
  $arguments += '-SkipNgrok'
}

$action = New-ScheduledTaskAction `
  -Execute $powershell `
  -Argument ($arguments -join ' ') `
  -WorkingDirectory $Root

$trigger = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
$settings = New-ScheduledTaskSettingsSet `
  -AllowStartIfOnBatteries `
  -DontStopIfGoingOnBatteries `
  -MultipleInstances IgnoreNew `
  -RestartCount 3 `
  -RestartInterval (New-TimeSpan -Minutes 1)
$principal = New-ScheduledTaskPrincipal `
  -UserId "$env:USERDOMAIN\$env:USERNAME" `
  -LogonType Interactive `
  -RunLevel Limited

Register-ScheduledTask `
  -TaskName $TaskName `
  -Action $action `
  -Trigger $trigger `
  -Settings $settings `
  -Principal $principal `
  -Description 'Starts watchDOG local automatically when this Windows user logs in.' `
  -Force | Out-Null

if (-not $SkipStartNow) {
  Start-ScheduledTask -TaskName $TaskName
}

Write-Host "Registered Windows startup task: $TaskName"
Write-Host "Preferred frontend port: $PreferredFrontendPort"
Write-Host "Preferred backend port:  $PreferredBackendPort"
if (-not $SkipNgrok) {
  Write-Host "ngrok backend URL:       $NgrokUrl"
}
Write-Host "Project: $Root"
