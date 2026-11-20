@echo off
rem All domains, read-only. Language follows the system culture; pass -Lang to override.
setlocal
set DIR=%~dp0
pwsh -NoProfile -ExecutionPolicy Bypass -File "%DIR%src\SecSweep.ps1" %*
if errorlevel 1 (
  echo.
  echo pwsh did not start, retrying with Windows PowerShell 5.1
  powershell -NoProfile -ExecutionPolicy Bypass -File "%DIR%src\SecSweep.ps1" %*
)
endlocal