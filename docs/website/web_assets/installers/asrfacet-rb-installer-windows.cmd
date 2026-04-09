@echo off
REM Part of ASRFacet-Rb - authorized testing only
setlocal EnableExtensions

set "SCRIPT_DIR=%~dp0"
set "SCRIPT_NAME=%~nx0"
set "PS_SCRIPT=%SCRIPT_DIR%asrfacet-rb-installer-windows.ps1"
set "PS_EXE="
set "MODE="
set "FLAG_YES="
set "FLAG_NOPROMPT="
set "FLAG_KEEPTEMP="
set "FLAG_VERBOSE="
set "PS_ARGS="

if not exist "%PS_SCRIPT%" (
  echo [FAIL] Missing installer script: %PS_SCRIPT%
  exit /b 1
)

:parse_args
if "%~1"=="" goto :args_done

if /I "%~1"=="-h" goto :usage
if /I "%~1"=="--help" goto :usage
if /I "%~1"=="/?" goto :usage

if /I "%~1"=="install" goto :set_mode_install
if /I "%~1"=="test" goto :set_mode_test
if /I "%~1"=="update" goto :set_mode_update
if /I "%~1"=="uninstall" goto :set_mode_uninstall

if /I "%~1"=="--yes" (
  set "FLAG_YES=1"
  shift
  goto :parse_args
)

if /I "%~1"=="--no-prompt" (
  set "FLAG_NOPROMPT=1"
  shift
  goto :parse_args
)

if /I "%~1"=="--keep-temp" (
  set "FLAG_KEEPTEMP=1"
  shift
  goto :parse_args
)

if /I "%~1"=="--verbose" (
  set "FLAG_VERBOSE=1"
  shift
  goto :parse_args
)

echo [FAIL] Unknown argument: %~1
echo [INFO] Run "%SCRIPT_NAME% --help" for usage.
exit /b 1

:set_mode_install
if defined MODE goto :multiple_mode
set "MODE=install"
shift
goto :parse_args

:set_mode_test
if defined MODE goto :multiple_mode
set "MODE=test"
shift
goto :parse_args

:set_mode_update
if defined MODE goto :multiple_mode
set "MODE=update"
shift
goto :parse_args

:set_mode_uninstall
if defined MODE goto :multiple_mode
set "MODE=uninstall"
shift
goto :parse_args

:multiple_mode
echo [FAIL] Multiple modes provided. Use one of: install, test, update, uninstall.
exit /b 1

:args_done
if defined MODE set "PS_ARGS=%PS_ARGS% -Mode %MODE%"
if defined FLAG_YES set "PS_ARGS=%PS_ARGS% -Yes"
if defined FLAG_NOPROMPT set "PS_ARGS=%PS_ARGS% -NoPrompt"
if defined FLAG_KEEPTEMP set "PS_ARGS=%PS_ARGS% -KeepTemp"
if defined FLAG_VERBOSE set "PS_ARGS=%PS_ARGS% -VerboseInstaller"

where powershell >nul 2>nul
if not errorlevel 1 set "PS_EXE=powershell"

if not defined PS_EXE where pwsh >nul 2>nul
if not defined PS_EXE if not errorlevel 1 set "PS_EXE=pwsh"

if not defined PS_EXE (
  echo [FAIL] Neither powershell nor pwsh was found in PATH.
  exit /b 1
)

if /I "%PS_EXE%"=="powershell" goto :run_powershell
goto :run_pwsh

:run_powershell
echo [INFO] Running installer with PowerShell.
powershell -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%" %PS_ARGS%
set "EXIT_CODE=%ERRORLEVEL%"
goto :finish

:run_pwsh
echo [INFO] Running installer with PowerShell Core (pwsh).
pwsh -NoProfile -File "%PS_SCRIPT%" %PS_ARGS%
set "EXIT_CODE=%ERRORLEVEL%"
goto :finish

:finish
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
