@echo off
REM For use only on systems you own or have explicit
REM written authorization to test.
set SCRIPT_DIR=%~dp0
powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%run-docker.ps1" %*
exit /b %ERRORLEVEL%
