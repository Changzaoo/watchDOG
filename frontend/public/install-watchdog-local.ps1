param(
  [string]$InstallDir = "$env:USERPROFILE\watchDOG-local",
  [switch]$SkipBrowser
)

$ErrorActionPreference = 'Stop'

$RepoUrl = 'https://github.com/Changzaoo/watchDOG.git'

function Write-Step {
  param([string]$Message)
  Write-Host ""
  Write-Host "==> $Message" -ForegroundColor Cyan
}

function Write-Done {
  param([string]$Message)
  Write-Host "OK  $Message" -ForegroundColor Green
}

function Test-Command {
  param([string]$Name)
  return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Refresh-Path {
  $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
  $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
  $env:Path = "$machinePath;$userPath"
}

function Install-WithWinget {
  param(
    [string]$Id,
    [string]$Name
  )

  if (-not (Test-Command winget)) {
    throw "$Name nao encontrado e winget nao esta disponivel. Instale $Name manualmente e rode este instalador novamente."
  }

  Write-Step "Instalando $Name"
  winget install --id $Id --exact --silent --accept-package-agreements --accept-source-agreements
  Refresh-Path
}

Write-Host "watchDOG - instalador local" -ForegroundColor White
Write-Host "Este script baixa a aplicacao, instala dependencias, sobe backend/frontend e abre localhost." -ForegroundColor DarkGray

if (-not (Test-Command git)) {
  Install-WithWinget -Id 'Git.Git' -Name 'Git'
}
Write-Done "Git disponivel"

if (-not (Test-Command node)) {
  Install-WithWinget -Id 'OpenJS.NodeJS.LTS' -Name 'Node.js LTS'
}
Write-Done "Node.js disponivel"

if (-not (Test-Command npm)) {
  Refresh-Path
}
if (-not (Test-Command npm)) {
  throw "npm nao encontrado. Feche e abra o PowerShell, depois rode o instalador novamente."
}
Write-Done "npm disponivel"

Write-Step "Preparando pasta de instalacao"
if (Test-Path $InstallDir) {
  if (Test-Path (Join-Path $InstallDir '.git')) {
    Write-Step "Atualizando repositorio existente"
    git -C $InstallDir pull --ff-only
  } else {
    $backupDir = "$InstallDir.backup-$(Get-Date -Format yyyyMMddHHmmss)"
    Move-Item -LiteralPath $InstallDir -Destination $backupDir
    Write-Done "Pasta existente movida para $backupDir"
    git clone $RepoUrl $InstallDir
  }
} else {
  git clone $RepoUrl $InstallDir
}
Write-Done "Codigo pronto em $InstallDir"

Set-Location -LiteralPath $InstallDir

Write-Step "Criando arquivos de ambiente local"
if ((Test-Path '.env.example') -and -not (Test-Path '.env')) {
  Copy-Item '.env.example' '.env'
}
if ((Test-Path 'backend\.env.example') -and -not (Test-Path 'backend\.env')) {
  Copy-Item 'backend\.env.example' 'backend\.env'
}
Write-Done "Ambiente local configurado"

Write-Step "Instalando dependencias"
npm install
Write-Done "Dependencias instaladas"

Write-Step "Preparando banco de dados e pacotes"
npm run build --workspace=shared
npm run build --workspace=scanner
npm run prisma:generate --workspace=backend
npm run prisma:migrate:deploy --workspace=backend
Write-Done "Backend local preparado"

Write-Step "Iniciando watchDOG em localhost"
$safeInstallDir = $InstallDir.Replace("'", "''")
$devCommand = "Set-Location -LiteralPath '$safeInstallDir'; npm run dev"
Start-Process powershell -ArgumentList @('-NoExit', '-ExecutionPolicy', 'Bypass', '-Command', $devCommand)

Start-Sleep -Seconds 6
if (-not $SkipBrowser) {
  Start-Process 'http://localhost:5173/scan/url'
}

Write-Done "Instalacao concluida"
Write-Host "Abra http://localhost:5173 para usar o watchDOG local." -ForegroundColor Green
