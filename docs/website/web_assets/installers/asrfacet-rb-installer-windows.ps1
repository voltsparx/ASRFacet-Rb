# Part of ASRFacet-Rb - authorized testing only

[CmdletBinding()]
param(
  [Parameter(Position = 0)]
  [ValidateSet("install", "test", "update", "uninstall")]
  [string]$Mode,
  [switch]$Yes,
  [switch]$NoPrompt,
  [switch]$KeepTemp,
  [switch]$VerboseInstaller
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoUrl = "https://github.com/voltsparx/ASRFacet-Rb.git"
$Branch = "main"
$WorkDir = $null

function Write-Labelled {
  param(
    [string]$Label,
    [string]$Message,
    [ConsoleColor]$Color = [ConsoleColor]::Gray
  )
  Write-Host ("[{0}] {1}" -f $Label, $Message) -ForegroundColor $Color
}

function Write-Info { param([string]$Message) Write-Labelled -Label "INFO" -Message $Message -Color ([ConsoleColor]::Cyan) }
function Write-Ok { param([string]$Message) Write-Labelled -Label " OK " -Message $Message -Color ([ConsoleColor]::Green) }
function Write-Warn { param([string]$Message) Write-Labelled -Label "WARN" -Message $Message -Color ([ConsoleColor]::Yellow) }
function Stop-Installer {
  param([string]$Message)
  Write-Labelled -Label "FAIL" -Message $Message -Color ([ConsoleColor]::Red)
  exit 1
}

function Resolve-Mode {
  if ($Mode) {
    return $Mode
  }

  if ($Yes -or $NoPrompt) {
    return "install"
  }

  Write-Host "Select mode:"
  Write-Host "  1) install"
  Write-Host "  2) test"
  Write-Host "  3) update"
  Write-Host "  4) uninstall"
  $choice = Read-Host "Choice [1-4, default 1]"
  switch ($choice.Trim()) {
    "2" { return "test" }
    "3" { return "update" }
    "4" { return "uninstall" }
    default { return "install" }
  }
}

function Confirm-Requirements {
  if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Stop-Installer "git is required but was not found in PATH."
  }
}

function Invoke-Step {
  param(
    [string]$CommandName,
    [scriptblock]$Command
  )

  if ($VerboseInstaller) {
    Write-Info $CommandName
  }

  & $Command
}

function Get-TempWorkDir {
  $base = Join-Path $env:TEMP "asrfacet-rb-installer"
  $name = "run-{0}" -f ([Guid]::NewGuid().ToString("N"))
  return Join-Path $base $name
}

function Cleanup {
  if ($KeepTemp) {
    if ($WorkDir) {
      Write-Info "Keeping temp directory: $WorkDir"
    }
    return
  }

  if ($WorkDir -and (Test-Path -LiteralPath $WorkDir)) {
    try {
      Remove-Item -LiteralPath $WorkDir -Recurse -Force -ErrorAction Stop
    } catch {
      Write-Warn "Unable to remove temp directory: $WorkDir"
    }
  }
}

$selectedMode = Resolve-Mode

try {
  Confirm-Requirements
  $WorkDir = Get-TempWorkDir
  Invoke-Step -CommandName "Creating temp workspace $WorkDir" -Command {
    New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
  }

  $repoDir = Join-Path $WorkDir "source"
  Invoke-Step -CommandName "Cloning ASRFacet-Rb from GitHub" -Command {
    & git clone --depth 1 --branch $Branch $RepoUrl $repoDir
    if ($LASTEXITCODE -ne 0) {
      throw "git clone failed."
    }
  }

  $installScript = Join-Path $repoDir "install\windows.ps1"
  if (-not (Test-Path -LiteralPath $installScript)) {
    throw "Expected installer script not found: $installScript"
  }

  Write-Info "Starting lifecycle mode: $selectedMode"
  & $installScript -Mode $selectedMode
  if ($LASTEXITCODE -ne 0) {
    throw "ASRFacet-Rb install script returned a non-zero exit code."
  }

  Write-Ok "ASRFacet-Rb website installer completed ($selectedMode)."
} catch {
  Stop-Installer $_.Exception.Message
} finally {
  Cleanup
}
