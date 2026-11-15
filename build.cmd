@echo off
rem 默认中文、全域、只读，报告落在 out\
setlocal
set DIR=%~dp0
pwsh -NoProfile -ExecutionPolicy Bypass -File "%DIR%src\SecSweep.ps1" %*
if errorlevel 1 (
  echo.
  echo 没跑起来。退回到 Windows PowerShell 5.1 再试一次。
  powershell -NoProfile -ExecutionPolicy Bypass -File "%DIR%src\SecSweep.ps1" %*
)
endlocal
