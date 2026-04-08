@echo off
REM Part of ASRFacet-Rb - authorized testing only
setlocal

set "SCRIPT_DIR=%~dp0"
set "PS_SCRIPT=%SCRIPT_DIR%asrfacet-rb-installer-windows.ps1"

if not exist "%PS_SCRIPT%" (
  echo [FAIL] Missing installer script: %PS_SCRIPT%
  exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%" %*
exit /b %ERRORLEVEL%
