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
$ThemeTag = "ASRFacet-Rb"

function Write-Labelled {
  param(
    [string]$Label,
    [string]$Message,
    [ConsoleColor]$Color = [ConsoleColor]::Gray
  )
  Write-Host ("[{0}][{1}] {2}" -f $ThemeTag, $Label, $Message) -ForegroundColor $Color
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

function Get-RequiredPaths {
  param([string]$SelectedMode)

  $paths = @("/install")
  if ($SelectedMode -in @("install", "update", "test")) {
    $paths += @(
      "/bin",
      "/config",
      "/lib",
      "/man",
      "/wordlists",
      "/docs/images",
      "/Gemfile",
      "/Gemfile.lock",
      "/asrfacet-rb.gemspec",
      "/README.md",
      "/LICENSE"
    )

    if ($SelectedMode -eq "test") {
      $paths += "/spec"
    }
  }

  return @($paths)
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
  $tempRoot = if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) { $env:TEMP } else { Join-Path $env:LOCALAPPDATA "Temp" }
  $base = Join-Path $tempRoot "afrb"
  $name = "r-{0}" -f ([Guid]::NewGuid().ToString("N").Substring(0, 8))
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
  Invoke-Step -CommandName "Cloning required ASRFacet-Rb files from GitHub" -Command {
    & git clone --depth 1 --filter=blob:none --sparse --branch $Branch $RepoUrl $repoDir
    if ($LASTEXITCODE -ne 0) {
      throw "git clone failed."
    }

    Push-Location $repoDir
    try {
      $paths = [string[]](Get-RequiredPaths -SelectedMode $selectedMode)
      & git sparse-checkout init --no-cone
      if ($LASTEXITCODE -ne 0) {
        throw "git sparse-checkout init failed."
      }

      $setArgs = @("sparse-checkout", "set", "--no-cone") + $paths
      & git @setArgs
      if ($LASTEXITCODE -ne 0) {
        throw "git sparse-checkout set failed."
      }
    } catch {
      Pop-Location
      Write-Warn "Sparse checkout is unavailable in this git environment. Falling back to full shallow clone."
      Remove-Item -LiteralPath $repoDir -Recurse -Force -ErrorAction SilentlyContinue
      & git clone --depth 1 --branch $Branch $RepoUrl $repoDir
      if ($LASTEXITCODE -ne 0) {
        throw "git clone fallback failed."
      }
      return
    } finally {
      if ((Get-Location).Path -eq $repoDir) {
        Pop-Location
      }
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
