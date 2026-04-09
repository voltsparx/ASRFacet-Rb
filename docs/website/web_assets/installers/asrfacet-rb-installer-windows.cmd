@echo off
REM Part of ASRFacet-Rb - authorized testing only
setlocal EnableExtensions EnableDelayedExpansion

set "SCRIPT_DIR=%~dp0"
set "SCRIPT_NAME=%~nx0"
set "PS_SCRIPT=%SCRIPT_DIR%asrfacet-rb-installer-windows.ps1"
set "PS_EXE="
set "MODE="
set "FLAG_YES="
set "FLAG_NOPROMPT="
set "FLAG_KEEPTEMP="
set "FLAG_VERBOSE="
set "SHOW_HELP="
set "EXTRA_ARGS="

if not exist "%PS_SCRIPT%" (
  echo [FAIL] Missing installer script: %PS_SCRIPT%
  exit /b 1
)

if /I "%~1"=="-h" set "SHOW_HELP=1"
if /I "%~1"=="--help" set "SHOW_HELP=1"
if /I "%~1"=="/?" set "SHOW_HELP=1"
if defined SHOW_HELP goto :usage

:parse_args
if "%~1"=="" goto :args_done
set "ARG=%~1"

if /I "%ARG%"=="install" (
  if defined MODE (
    echo [FAIL] Multiple modes provided. Use one of: install, test, update, uninstall.
    exit /b 1
  )
  set "MODE=install"
  shift
  goto :parse_args
)
if /I "%ARG%"=="test" (
  if defined MODE (
    echo [FAIL] Multiple modes provided. Use one of: install, test, update, uninstall.
    exit /b 1
  )
  set "MODE=test"
  shift
  goto :parse_args
)
if /I "%ARG%"=="update" (
  if defined MODE (
    echo [FAIL] Multiple modes provided. Use one of: install, test, update, uninstall.
    exit /b 1
  )
  set "MODE=update"
  shift
  goto :parse_args
)
if /I "%ARG%"=="uninstall" (
  if defined MODE (
    echo [FAIL] Multiple modes provided. Use one of: install, test, update, uninstall.
    exit /b 1
  )
  set "MODE=uninstall"
  shift
  goto :parse_args
)
if /I "%ARG%"=="--yes" (
  set "FLAG_YES=1"
  shift
  goto :parse_args
)
if /I "%ARG%"=="--no-prompt" (
  set "FLAG_NOPROMPT=1"
  shift
  goto :parse_args
)
if /I "%ARG%"=="--keep-temp" (
  set "FLAG_KEEPTEMP=1"
  shift
  goto :parse_args
)
if /I "%ARG%"=="--verbose" (
  set "FLAG_VERBOSE=1"
  shift
  goto :parse_args
)
if /I "%ARG%"=="-h" (
  set "SHOW_HELP=1"
  shift
  goto :parse_args
)
if /I "%ARG%"=="--help" (
  set "SHOW_HELP=1"
  shift
  goto :parse_args
)
if /I "%ARG%"=="/?" (
  set "SHOW_HELP=1"
  shift
  goto :parse_args
)

echo [FAIL] Unknown argument: %ARG%
echo [INFO] Run "%SCRIPT_NAME% --help" for usage.
exit /b 1

:args_done
if defined SHOW_HELP goto :usage

where powershell >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  set "PS_EXE=powershell"
) else (
  where pwsh >nul 2>nul
  if %ERRORLEVEL% EQU 0 (
    set "PS_EXE=pwsh"
  ) else (
    echo [FAIL] Neither powershell nor pwsh was found in PATH.
    exit /b 1
  )
)

if defined MODE set "EXTRA_ARGS=!EXTRA_ARGS! -Mode !MODE!"
if defined FLAG_YES set "EXTRA_ARGS=!EXTRA_ARGS! -Yes"
if defined FLAG_NOPROMPT set "EXTRA_ARGS=!EXTRA_ARGS! -NoPrompt"
if defined FLAG_KEEPTEMP set "EXTRA_ARGS=!EXTRA_ARGS! -KeepTemp"
if defined FLAG_VERBOSE set "EXTRA_ARGS=!EXTRA_ARGS! -VerboseInstaller"

if /I "%PS_EXE%"=="powershell" (
  echo [INFO] Running installer with PowerShell.
  powershell -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%" !EXTRA_ARGS!
) else (
  echo [INFO] Running installer with PowerShell Core (pwsh).
  pwsh -NoProfile -File "%PS_SCRIPT%" !EXTRA_ARGS!
)
set "EXIT_CODE=%ERRORLEVEL%"
if not "%EXIT_CODE%"=="0" (
  echo [FAIL] Installer failed with exit code %EXIT_CODE%.
) else (
  echo [ OK ] Installer completed successfully.
)
exit /b %EXIT_CODE%

:usage
echo ASRFacet-Rb Website Installer (Windows CMD)
echo.
echo Usage:
echo   %SCRIPT_NAME% [install^|test^|update^|uninstall] [--yes] [--no-prompt] [--keep-temp] [--verbose]
echo.
echo Options:
echo   --yes         Run non-interactively where possible
echo   --no-prompt   Alias for non-interactive flow
echo   --keep-temp   Keep downloaded temp files for troubleshooting
echo   --verbose     Print command-level progress
echo   --help, -h    Show this help
exit /b 0
