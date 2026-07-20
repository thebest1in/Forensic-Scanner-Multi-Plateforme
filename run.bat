@echo off
title Forensic Scanner Multi-Plateforme
cd /d "%~dp0"

if not exist "venv\Scripts\python.exe" (
    echo [ERROR] Virtual environment not found.
    echo Run setup.bat first to install dependencies.
    pause
    exit /b 1
)

echo ============================================
echo   Forensic Scanner Multi-Plateforme
echo ============================================
echo.
echo   Starting scanner GUI...
echo.

start "" venv\Scripts\pythonw.exe gui\main_gui.py
