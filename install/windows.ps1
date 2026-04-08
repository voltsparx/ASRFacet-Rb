# SPDX-License-Identifier: Proprietary
#
# ASRFacet-Rb: Attack Surface Reconnaissance Framework
# Copyright (c) 2026 voltsparx
#
# Author: voltsparx
# Repository: https://github.com/voltsparx/ASRFacet-Rb
# Contact: voltsparx@gmail.com
# License: See LICENSE file in the project root
#
# This file is part of ASRFacet-Rb and is subject to the terms
# and conditions defined in the LICENSE file.

[CmdletBinding()]
param(
  [Parameter(Position = 0)]
  [ValidateSet("install", "test", "uninstall", "update")]
  [string]$Mode = "install"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$AppName = "asrfacet-rb"
$AliasName = "asrfrb"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
$InstallRoot = Join-Path $env:LOCALAPPDATA "Programs\$AppName"
$UserBinDir = Join-Path $HOME ".local\bin"
$SystemLauncher = Join-Path $UserBinDir "$AppName.cmd"
$AliasLauncher = Join-Path $UserBinDir "$AliasName.cmd"
$TestBase = Join-Path $ScriptDir "test-root"
$TestRoot = Join-Path $TestBase $AppName
$TestBinDir = Join-Path $TestBase "bin"
$TestLauncher = Join-Path $TestBinDir "$AppName.cmd"
$TestAliasLauncher = Join-Path $TestBinDir "$AliasName.cmd"
$UserConfigRoot = Join-Path $HOME ".asrfacet_rb"
$UserConfigPath = Join-Path $UserConfigRoot "config.yml"
$DefaultOutputRoot = Join-Path $UserConfigRoot "output"
$ManifestName = ".asrfacet-install.json"
$RuntimePayload = @(
  "bin",
  "config",
  "lib",
  "man",
  "Gemfile",
  "Gemfile.lock",
  "README.md",
  "LICENSE",
  "asrfacet-rb.gemspec"
)

function Write-Labelled {
  param(
    [string]$Label,
    [string]$Message,
    [ConsoleColor]$Color = [ConsoleColor]::Gray
  )

  Write-Host ("[{0}] {1}" -f $Label, $Message) -ForegroundColor $Color
}

function Write-Info {
  param([string]$Message)
  Write-Labelled -Label "INFO" -Message $Message -Color ([ConsoleColor]::Cyan)
}

function Write-Success {
  param([string]$Message)
  Write-Labelled -Label " OK " -Message $Message -Color ([ConsoleColor]::Green)
}

function Write-WarningLine {
  param([string]$Message)
  Write-Labelled -Label "WARN" -Message $Message -Color ([ConsoleColor]::Yellow)
}

function Stop-Step {
  param([string]$Message)
  Write-Labelled -Label "FAIL" -Message $Message -Color ([ConsoleColor]::Red)
  exit 1
}

function Read-Confirmation {
  param(
    [string]$Prompt,
    [bool]$Default = $true
  )

  if (-not [Environment]::UserInteractive) {
    return $true
  }

  $suffix = if ($Default) { "[Y/n]" } else { "[y/N]" }
  $answer = Read-Host "$Prompt $suffix"
  if ([string]::IsNullOrWhiteSpace($answer)) {
    return $Default
  }

  $normalized = $answer.Trim().ToLowerInvariant()
  return $normalized -in @("y", "yes")
}

function Confirm-CommandAvailable {
  param([string]$Name)

  if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
    Stop-Step "$Name is required but was not found in PATH."
  }
}

function Install-BundlerIfMissing {
  Confirm-CommandAvailable -Name "ruby"

  if (Get-Command "bundle" -ErrorAction SilentlyContinue) {
    return
  }

  if (-not (Get-Command "gem" -ErrorAction SilentlyContinue)) {
    Stop-Step "Bundler is missing and the gem command is unavailable to install it."
  }

  if (-not (Read-Confirmation -Prompt "Bundler is required but missing. Install it now for this user?")) {
    Stop-Step "Bundler installation was declined. Install bundler manually and re-run this script."
  }

  Write-Info "Bundler was not found. Attempting a user-level bundler install."
  & gem install bundler --no-document
  if ($LASTEXITCODE -ne 0) {
    Stop-Step "Bundler installation failed. Install bundler manually and re-run this script."
  }
}

function Get-ManifestPath {
  param([string]$Root)
  Join-Path $Root $ManifestName
}

function Test-ManagedInstall {
  param([string]$Root)
  Test-Path -LiteralPath (Get-ManifestPath -Root $Root)
}

function Confirm-ManagedInstallTarget {
  param([string]$Root)

  if ((Test-Path -LiteralPath $Root) -and -not (Test-ManagedInstall -Root $Root)) {
    Stop-Step "Refusing to replace '$Root' because it is not marked as an ASRFacet-Rb managed install."
  }
}

function Remove-TreeSafe {
  param([string]$PathToRemove)

  if ([string]::IsNullOrWhiteSpace($PathToRemove)) {
    return
  }

  if (Test-Path -LiteralPath $PathToRemove) {
    Remove-Item -LiteralPath $PathToRemove -Recurse -Force -ErrorAction Stop
  }
}

function Copy-Payload {
  param(
    [string]$DestinationRoot,
    [switch]$IncludeSpecs
  )

  New-Item -ItemType Directory -Path $DestinationRoot -Force | Out-Null

  foreach ($entry in $RuntimePayload) {
    $source = Join-Path $RepoRoot $entry
    if (Test-Path -LiteralPath $source) {
      Copy-Item -LiteralPath $source -Destination $DestinationRoot -Recurse -Force
    }
  }

  $wordlists = Join-Path $RepoRoot "wordlists"
  if (Test-Path -LiteralPath $wordlists) {
    Copy-Item -LiteralPath $wordlists -Destination $DestinationRoot -Recurse -Force
  }

  $docsImages = Join-Path $RepoRoot "docs\images"
  if (Test-Path -LiteralPath $docsImages) {
    $docsRoot = Join-Path $DestinationRoot "docs"
    New-Item -ItemType Directory -Path $docsRoot -Force | Out-Null
    Copy-Item -LiteralPath $docsImages -Destination $docsRoot -Recurse -Force
  }

  if ($IncludeSpecs) {
    $specDir = Join-Path $RepoRoot "spec"
    if (Test-Path -LiteralPath $specDir) {
      Copy-Item -LiteralPath $specDir -Destination $DestinationRoot -Recurse -Force
    }
  }

  $rootReadme = Join-Path $DestinationRoot "README.md"
  Get-ChildItem -Path $DestinationRoot -Recurse -File -Filter "README.md" -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_.FullName -ine $rootReadme) {
      Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop
    }
  }

  foreach ($dir in @("output", "tmp", "vendor")) {
    New-Item -ItemType Directory -Path (Join-Path $DestinationRoot $dir) -Force | Out-Null
  }
}

function Invoke-BundleSetup {
  param([string]$AppRoot)

  Install-BundlerIfMissing
  if (-not (Read-Confirmation -Prompt "Install or refresh Ruby dependencies into the ASRFacet-Rb application folder?")) {
    Stop-Step "Dependency installation was declined."
  }

  Write-Info "Installing runtime dependencies into $AppRoot\vendor\bundle"

  Push-Location $AppRoot
  try {
    & bundle config set --local path vendor/bundle
    if ($LASTEXITCODE -ne 0) {
      Stop-Step "Unable to configure bundler path for $AppRoot."
    }

    & bundle config set --local without development
    if ($LASTEXITCODE -ne 0) {
      Stop-Step "Unable to configure bundler groups for $AppRoot."
    }

    & bundle install
    if ($LASTEXITCODE -ne 0) {
      Stop-Step "bundle install failed for $AppRoot."
    }
  } finally {
    Pop-Location
  }
}

function Write-Manifest {
  param(
    [string]$AppRoot,
    [string]$InstallMode
  )

  $manifest = [ordered]@{
    app_name     = $AppName
    installed_at = (Get-Date).ToUniversalTime().ToString("o")
    install_mode = $InstallMode
    source_repo  = $RepoRoot
    ruby_version = (& ruby -e "print RUBY_VERSION" 2>$null)
  }

  $manifest | ConvertTo-Json | Set-Content -LiteralPath (Get-ManifestPath -Root $AppRoot) -Encoding UTF8
}

function Write-UserConfig {
  param([string]$OutputRoot)

  New-Item -ItemType Directory -Path $UserConfigRoot -Force | Out-Null
  New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null

  @"
threads:
  default: 50
output:
  directory: $($OutputRoot -replace '\\', '/')
  format: cli
"@ | Set-Content -LiteralPath $UserConfigPath -Encoding UTF8
}

function Write-Launcher {
  param(
    [string]$AppRoot,
    [string]$LauncherPath,
    [string]$EntryScript = "asrfacet-rb"
  )

  $launcherDir = Split-Path -Parent $LauncherPath
  New-Item -ItemType Directory -Path $launcherDir -Force | Out-Null

  $content = @"
@echo off
setlocal
set "APP_ROOT=$AppRoot"
if not exist "%APP_ROOT%\Gemfile" (
  echo [FAIL] ASRFacet-Rb is not installed correctly at "%APP_ROOT%".
  exit /b 1
)
where ruby >nul 2>nul || (
  echo [FAIL] Ruby 3.2 or newer is required.
  exit /b 1
)
where bundle >nul 2>nul || (
  echo [FAIL] Bundler is required. Re-run the installer to repair this installation.
  exit /b 1
)
set "BUNDLE_GEMFILE=%APP_ROOT%\Gemfile"
set "BUNDLE_APP_CONFIG=%APP_ROOT%\.bundle"
set "BUNDLE_WITHOUT=development"
bundle exec ruby "%APP_ROOT%\bin\asrfacet-rb" %*
"@

  Set-Content -LiteralPath $LauncherPath -Value $content -Encoding ASCII
}

function Write-Launchers {
  param(
    [string]$AppRoot,
    [string[]]$LauncherPaths
  )

  foreach ($launcherPath in $LauncherPaths) {
    Write-Launcher -AppRoot $AppRoot -LauncherPath $launcherPath
  }
}

function Add-UserPathEntry {
  param([string]$Directory)

  New-Item -ItemType Directory -Path $Directory -Force | Out-Null

  $current = [Environment]::GetEnvironmentVariable("Path", "User")
  $entries = @()
  if (-not [string]::IsNullOrWhiteSpace($current)) {
    $entries = $current.Split(";") | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
  }

  $alreadyPresent = $false
  foreach ($entry in $entries) {
    if ($entry.TrimEnd("\") -ieq $Directory.TrimEnd("\")) {
      $alreadyPresent = $true
      break
    }
  }

  if (-not $alreadyPresent) {
    $newPath = (($entries + $Directory) | Select-Object -Unique) -join ";"
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    if ($env:Path -notlike "*$Directory*") {
      $env:Path = "$Directory;$env:Path"
    }
    Write-Success "Added $Directory to the user PATH."
  } else {
    Write-Info "$Directory is already present in the user PATH."
  }
}

function Remove-UserPathEntry {
  param([string]$Directory)

  $current = [Environment]::GetEnvironmentVariable("Path", "User")
  if ([string]::IsNullOrWhiteSpace($current)) {
    return
  }

  $entries = $current.Split(";") | Where-Object {
    -not [string]::IsNullOrWhiteSpace($_) -and $_.TrimEnd("\") -ine $Directory.TrimEnd("\")
  }

  [Environment]::SetEnvironmentVariable("Path", ($entries -join ";"), "User")
}

function Invoke-SmokeTest {
  param([string]$LauncherPath)

  Write-Info "Running a launcher smoke test."
  & cmd.exe /c "`"$LauncherPath`" help" *> $null
  if ($LASTEXITCODE -ne 0) {
    Stop-Step "Smoke test failed for $LauncherPath."
  }
  Write-Success "Launcher smoke test passed."
}

function Show-InstallSummary {
  param(
    [string]$InstallMode,
    [string]$AppRoot,
    [string[]]$LauncherPaths,
    [string]$OutputRoot
  )

  Write-Success "ASRFacet-Rb $InstallMode completed successfully."
  Write-Info "Installed application: $AppRoot"
  Write-Info "System commands: $AppName, $AliasName"
  Write-Info "Launcher paths: $($LauncherPaths -join ', ')"
  Write-Info "Stored reports root: $OutputRoot"
  Write-Info "Built-in manual command: asrfacet-rb manual"
}

function Install-Application {
  param(
    [string]$TargetRoot,
    [string[]]$LauncherPaths,
    [string]$InstallMode,
    [switch]$AddToPath,
    [switch]$IncludeSpecs
  )

  Confirm-ManagedInstallTarget -Root $TargetRoot

  $parent = Split-Path -Parent $TargetRoot
  $stageRoot = Join-Path $parent ".$AppName-staging-$PID"
  $stageApp = Join-Path $stageRoot $AppName
  $backupRoot = Join-Path $parent ".$AppName-backup-$PID"
  $restored = $false

  Remove-TreeSafe -PathToRemove $stageRoot
  Remove-TreeSafe -PathToRemove $backupRoot
  New-Item -ItemType Directory -Path $stageRoot -Force | Out-Null

  try {
    Write-Info "Preparing staged files for $InstallMode."
    Copy-Payload -DestinationRoot $stageApp -IncludeSpecs:$IncludeSpecs
    Invoke-BundleSetup -AppRoot $stageApp
    Write-Manifest -AppRoot $stageApp -InstallMode $InstallMode

    if (Test-Path -LiteralPath $TargetRoot) {
      Move-Item -LiteralPath $TargetRoot -Destination $backupRoot -Force
    }

    Move-Item -LiteralPath $stageApp -Destination $TargetRoot -Force
    Write-Launchers -AppRoot $TargetRoot -LauncherPaths $LauncherPaths

    if ($AddToPath) {
      Add-UserPathEntry -Directory $UserBinDir
      Write-UserConfig -OutputRoot $DefaultOutputRoot
    }

    foreach ($launcherPath in $LauncherPaths) {
      Invoke-SmokeTest -LauncherPath $launcherPath
    }

    Remove-TreeSafe -PathToRemove $backupRoot
    Remove-TreeSafe -PathToRemove $stageRoot
    Show-InstallSummary -InstallMode $InstallMode -AppRoot $TargetRoot -LauncherPaths $LauncherPaths -OutputRoot $DefaultOutputRoot
  } catch {
    Write-WarningLine "Attempting to restore the previous installation state."
    if (Test-Path -LiteralPath $backupRoot) {
      if (Test-Path -LiteralPath $TargetRoot) {
        Remove-TreeSafe -PathToRemove $TargetRoot
      }

      if (-not (Test-Path -LiteralPath $TargetRoot)) {
        Move-Item -LiteralPath $backupRoot -Destination $TargetRoot -Force
        $restored = $true
      }
    }

    Remove-TreeSafe -PathToRemove $stageRoot
    if (-not $restored) {
      Remove-TreeSafe -PathToRemove $backupRoot
    }

    Stop-Step $_.Exception.Message
  }
}

function Uninstall-Application {
  if (-not (Test-Path -LiteralPath $InstallRoot)) {
    Write-WarningLine "No managed installation was found at $InstallRoot."
  } elseif (-not (Test-ManagedInstall -Root $InstallRoot)) {
    Stop-Step "Refusing to remove $InstallRoot because it is not marked as managed by this installer."
  } else {
    Remove-TreeSafe -PathToRemove $InstallRoot
    Write-Success "Removed $InstallRoot"
  }

  foreach ($launcher in @($SystemLauncher, $AliasLauncher)) {
    if (Test-Path -LiteralPath $launcher) {
      Remove-Item -LiteralPath $launcher -Force
      Write-Success "Removed launcher $launcher"
    }
  }

  Remove-UserPathEntry -Directory $UserBinDir
  Write-Success "User PATH cleaned up."
}

switch ($Mode) {
  "install" {
    Install-Application -TargetRoot $InstallRoot -LauncherPaths @($SystemLauncher, $AliasLauncher) -InstallMode "install" -AddToPath
  }
  "test" {
    Install-Application -TargetRoot $TestRoot -LauncherPaths @($TestLauncher, $TestAliasLauncher) -InstallMode "test" -IncludeSpecs
    Write-Info "Repo-local test launchers: $TestLauncher, $TestAliasLauncher"
  }
  "update" {
    if (-not (Test-ManagedInstall -Root $InstallRoot)) {
      Stop-Step "No managed installation was found to update. Run install first."
    }

    Install-Application -TargetRoot $InstallRoot -LauncherPaths @($SystemLauncher, $AliasLauncher) -InstallMode "update" -AddToPath
  }
  "uninstall" {
    Uninstall-Application
  }
  default {
    Stop-Step "Unsupported mode: $Mode"
  }
}
