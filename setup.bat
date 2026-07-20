@echo off
title Forensic Scanner Multi-Plateforme - Setup
cd /d "%~dp0"
echo ============================================
echo   Forensic Scanner Multi-Plateforme Setup
echo ============================================
echo.

:: Check Python
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python not found.
    echo Please install Python 3.10+ from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation.
    pause
    exit /b 1
)

echo [1/4] Creating virtual environment...
python -m venv venv
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to create virtual environment.
    pause
    exit /b 1
)

echo [2/4] Activating virtual environment...
call venv\Scripts\activate.bat

echo [3/4] Installing Python dependencies...
pip install -r requirements.txt
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to install dependencies.
    pause
    exit /b 1
)

echo [4/4] Checking tools...
adb --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [WARNING] ADB not found. Android scanning requires ADB.
    echo Install: https://developer.android.com/tools/releases/platform-tools
)

echo.
echo ============================================
echo   Setup Complete!
echo ============================================
echo.
echo To run the scanner:
echo   1. Activate venv:  venv\Scripts\activate.bat
echo   2. Run GUI:        python gui\main_gui.py
echo.
pause
