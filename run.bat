@echo off
title Universal Forensic Scanner
cd /d "%~dp0"

if not exist "venv\Scripts\python.exe" (
    echo [ERROR] Virtual environment not found.
    echo Run setup.bat first to install dependencies.
    pause
    exit /b 1
)

echo ============================================
echo   Universal Forensic Scanner
echo ============================================
echo.
echo   Connect your phone via USB and ensure
echo   USB Debugging is enabled.
echo.
echo   Starting scanner...
echo.

start "" venv\Scripts\pythonw.exe app.py
