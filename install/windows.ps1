# Part of ASRFacet-Rb - authorized testing only
[CmdletBinding()]
param(
  [Parameter(Position = 0)]
  [ValidateSet("install", "test", "uninstall", "update")]
  [string]$Mode = "install"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$AppName = "asrfacet-rb"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
$InstallRoot = Join-Path $env:LOCALAPPDATA "Programs\$AppName"
$UserBinDir = Join-Path $HOME ".local\bin"
$SystemLauncher = Join-Path $UserBinDir "$AppName.cmd"
$TestBase = Join-Path $ScriptDir "test-root"
$TestRoot = Join-Path $TestBase $AppName
$TestBinDir = Join-Path $TestBase "bin"
$TestLauncher = Join-Path $TestBinDir "$AppName.cmd"
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

function Fail-Step {
  param([string]$Message)
  Write-Labelled -Label "FAIL" -Message $Message -Color ([ConsoleColor]::Red)
  exit 1
}

function Ensure-Command {
  param([string]$Name)

  if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
    Fail-Step "$Name is required but was not found in PATH."
  }
}

function Ensure-Bundler {
  Ensure-Command -Name "ruby"

  if (Get-Command "bundle" -ErrorAction SilentlyContinue) {
    return
  }

  if (-not (Get-Command "gem" -ErrorAction SilentlyContinue)) {
    Fail-Step "Bundler is missing and the gem command is unavailable to install it."
  }

  Write-Info "Bundler was not found. Attempting a user-level bundler install."
  & gem install bundler --no-document
  if ($LASTEXITCODE -ne 0) {
    Fail-Step "Bundler installation failed. Install bundler manually and re-run this script."
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

function Ensure-ManagedOrMissing {
  param([string]$Root)

  if ((Test-Path -LiteralPath $Root) -and -not (Test-ManagedInstall -Root $Root)) {
    Fail-Step "Refusing to replace '$Root' because it is not marked as an ASRFacet-Rb managed install."
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

  if ($IncludeSpecs) {
    $specDir = Join-Path $RepoRoot "spec"
    if (Test-Path -LiteralPath $specDir) {
      Copy-Item -LiteralPath $specDir -Destination $DestinationRoot -Recurse -Force
    }
  }

  foreach ($dir in @("output", "tmp", "vendor")) {
    New-Item -ItemType Directory -Path (Join-Path $DestinationRoot $dir) -Force | Out-Null
  }
}

function Invoke-BundleSetup {
  param([string]$AppRoot)

  Ensure-Bundler
  Write-Info "Installing runtime dependencies into $AppRoot\vendor\bundle"

  Push-Location $AppRoot
  try {
    & bundle config set --local path vendor/bundle
    if ($LASTEXITCODE -ne 0) {
      Fail-Step "Unable to configure bundler path for $AppRoot."
    }

    & bundle config set --local without development
    if ($LASTEXITCODE -ne 0) {
      Fail-Step "Unable to configure bundler groups for $AppRoot."
    }

    & bundle install
    if ($LASTEXITCODE -ne 0) {
      Fail-Step "bundle install failed for $AppRoot."
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

function Write-Launcher {
  param(
    [string]$AppRoot,
    [string]$LauncherPath
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

function Ensure-UserPathContains {
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
    Fail-Step "Smoke test failed for $LauncherPath."
  }
  Write-Success "Launcher smoke test passed."
}

function Install-Application {
  param(
    [string]$TargetRoot,
    [string]$LauncherPath,
    [string]$InstallMode,
    [switch]$AddToPath,
    [switch]$IncludeSpecs
  )

  Ensure-ManagedOrMissing -Root $TargetRoot

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
    Write-Launcher -AppRoot $TargetRoot -LauncherPath $LauncherPath

    if ($AddToPath) {
      Ensure-UserPathContains -Directory $UserBinDir
    }

    Invoke-SmokeTest -LauncherPath $LauncherPath

    Remove-TreeSafe -PathToRemove $backupRoot
    Remove-TreeSafe -PathToRemove $stageRoot
    Write-Success "ASRFacet-Rb $InstallMode completed successfully."
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

    Fail-Step $_.Exception.Message
  }
}

function Uninstall-Application {
  if (-not (Test-Path -LiteralPath $InstallRoot)) {
    Write-WarningLine "No managed installation was found at $InstallRoot."
  } elseif (-not (Test-ManagedInstall -Root $InstallRoot)) {
    Fail-Step "Refusing to remove $InstallRoot because it is not marked as managed by this installer."
  } else {
    Remove-TreeSafe -PathToRemove $InstallRoot
    Write-Success "Removed $InstallRoot"
  }

  if (Test-Path -LiteralPath $SystemLauncher) {
    Remove-Item -LiteralPath $SystemLauncher -Force
    Write-Success "Removed launcher $SystemLauncher"
  }

  Remove-UserPathEntry -Directory $UserBinDir
  Write-Success "User PATH cleaned up."
}

switch ($Mode) {
  "install" {
    Install-Application -TargetRoot $InstallRoot -LauncherPath $SystemLauncher -InstallMode "install" -AddToPath
  }
  "test" {
    Install-Application -TargetRoot $TestRoot -LauncherPath $TestLauncher -InstallMode "test" -IncludeSpecs
    Write-Success "Repo-local test install is ready at $TestRoot"
    Write-Info "Launcher: $TestLauncher"
  }
  "update" {
    if (-not (Test-ManagedInstall -Root $InstallRoot)) {
      Fail-Step "No managed installation was found to update. Run install first."
    }

    Install-Application -TargetRoot $InstallRoot -LauncherPath $SystemLauncher -InstallMode "update" -AddToPath
  }
  "uninstall" {
    Uninstall-Application
  }
  default {
    Fail-Step "Unsupported mode: $Mode"
  }
}
