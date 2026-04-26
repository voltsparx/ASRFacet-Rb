# For use only on systems you own or have explicit
# written authorization to test.
param(
  [string]$Action,
  [string]$Command,
  [switch]$Detach,
  [switch]$Rebuild,
  [switch]$Public,
  [switch]$NoPublic,
  [switch]$WithLab,
  [switch]$NoWithLab,
  [int]$WebPort = 4567,
  [int]$LabPort = 9292
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
$ComposeFile = Join-Path $ScriptDir "docker-compose.yml"

function Get-ComposeCommand {
  if (Get-Command docker -ErrorAction SilentlyContinue) {
    try {
      docker compose version | Out-Null
      return @("docker", "compose")
    } catch {
      $null = $null
    }
  }
  if (Get-Command docker-compose -ErrorAction SilentlyContinue) {
    return @("docker-compose")
  }
  throw "Docker Compose was not found. Install Docker Desktop or docker-compose first."
}

function Show-Usage {
  @"
Usage:
  .\docker\run-docker.ps1 [-Action up|down|restart|logs|ps|shell|cli|build|help] [options]

Options:
  -Action ACTION
  -Command TEXT
  -Detach
  -Rebuild
  -Public
  -NoPublic
  -WithLab
  -NoWithLab
  -WebPort PORT
  -LabPort PORT
"@
}

if (-not $PSBoundParameters.ContainsKey("Action")) {
  Write-Host "Select docker action:"
  Write-Host "  1) up"
  Write-Host "  2) down"
  Write-Host "  3) restart"
  Write-Host "  4) logs"
  Write-Host "  5) ps"
  Write-Host "  6) shell"
  Write-Host "  7) cli"
  Write-Host "  8) build"
  $choice = Read-Host "Choice [1-8]"
  switch ($choice) {
    "1" { $Action = "up" }
    "2" { $Action = "down" }
    "3" { $Action = "restart" }
    "4" { $Action = "logs" }
    "5" { $Action = "ps" }
    "6" { $Action = "shell" }
    "7" { $Action = "cli" }
    "8" { $Action = "build" }
    default { throw "Invalid choice." }
  }

  if ($Action -in @("up", "restart")) {
    $publicReply = Read-Host "Expose deploy publicly on 0.0.0.0? [Y/n]"
    if ($publicReply -match "^[Nn]$") { $NoPublic = $true } else { $Public = $true }
    $labReply = Read-Host "Start the local lab too? [Y/n]"
    if ($labReply -match "^[Nn]$") { $NoWithLab = $true } else { $WithLab = $true }
    $webReply = Read-Host "Web port [4567]"
    if (-not [string]::IsNullOrWhiteSpace($webReply)) { $WebPort = [int]$webReply }
    $labPortReply = Read-Host "Lab port [9292]"
    if (-not [string]::IsNullOrWhiteSpace($labPortReply)) { $LabPort = [int]$labPortReply }
    $detachReply = Read-Host "Run detached? [Y/n]"
    if ($detachReply -notmatch "^[Nn]$") { $Detach = $true }
    $rebuildReply = Read-Host "Force rebuild? [y/N]"
    if ($rebuildReply -match "^[Yy]$") { $Rebuild = $true }
  }

  if ($Action -eq "cli") {
    $commandReply = Read-Host "ASRFacet-Rb CLI command [help]"
    $Command = if ([string]::IsNullOrWhiteSpace($commandReply)) { "help" } else { $commandReply }
  }
}

if ($NoPublic) {
  $Public = $false
} elseif (-not $PSBoundParameters.ContainsKey("Public") -and -not $PSBoundParameters.ContainsKey("NoPublic")) {
  $Public = $true
}

if ($NoWithLab) {
  $WithLab = $false
} elseif (-not $PSBoundParameters.ContainsKey("WithLab") -and -not $PSBoundParameters.ContainsKey("NoWithLab")) {
  $WithLab = $true
}

$deployFlags = New-Object System.Collections.Generic.List[string]
if ($Public) { $deployFlags.Add("--public") }
if (-not $WithLab) { $deployFlags.Add("--no-with-lab") }

$env:ASRFACET_RB_DEPLOY_FLAGS = ($deployFlags -join " ").Trim()
$env:ASRFACET_RB_WEB_PORT = [string]$WebPort
$env:ASRFACET_RB_LAB_PORT = [string]$LabPort
$env:COMPOSE_PROJECT_NAME = "asrfacet_rb"

$baseArgs = @("-f", $ComposeFile)

function Invoke-Compose {
  param([string[]]$Args)
  Push-Location $RepoRoot
  try {
    $compose = Get-ComposeCommand
    $fullArgs = @()
    if ($compose.Length -gt 1) {
      $fullArgs += $compose[1..($compose.Length - 1)]
    }
    $fullArgs += $baseArgs
    $fullArgs += $Args
    & $compose[0] @fullArgs
  } finally {
    Pop-Location
  }
}

switch ($Action) {
  "up" {
    $args = @("up")
    if ($Rebuild) { $args += "--build" }
    if ($Detach) { $args += "-d" }
    Invoke-Compose -Args $args
  }
  "down" { Invoke-Compose -Args @("down") }
  "restart" {
    Invoke-Compose -Args @("down")
    $args = @("up")
    if ($Rebuild) { $args += "--build" }
    if ($Detach) { $args += "-d" }
    Invoke-Compose -Args $args
  }
  "logs" { Invoke-Compose -Args @("logs", "-f") }
  "ps" { Invoke-Compose -Args @("ps") }
  "shell" { Invoke-Compose -Args @("run", "--rm", "asrfacet_rb", "bash") }
  "cli" {
    $cliCommand = if ([string]::IsNullOrWhiteSpace($Command)) { "help" } else { $Command }
    Invoke-Compose -Args @("run", "--rm", "asrfacet_rb", "bash", "-lc", "bundle exec ruby bin/asrfacet-rb $cliCommand")
  }
  "build" { Invoke-Compose -Args @("build") }
  "help" {
    Show-Usage
  }
  default {
    Show-Usage
    throw "Unsupported action: $Action"
  }
}
