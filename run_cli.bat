@echo off
title Universal Forensic Scanner v7.0 CLI
cd /d "%~dp0"
if not exist "venv\Scripts\python.exe" (
  echo [ERROR] Virtual environment not found. Run setup.bat first.
  pause
  exit /b 1
)
"venv\Scripts\python.exe" cli.py
set "EXIT_CODE=%ERRORLEVEL%"
echo.
echo CLI finished with exit code %EXIT_CODE%.
pause
exit /b %EXIT_CODE%
