@echo off
REM Double-click launcher for D2R Saver. Bypasses PowerShell execution policy
REM for this one script only (does not change any system setting).
powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -File "%~dp0d2r_saver.ps1"
