@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul

set "ROOT_DIR=%~dp0"
if "%ROOT_DIR:~-1%"=="\" set "ROOT_DIR=%ROOT_DIR:~0,-1%"

set "PYTHONPATH=%ROOT_DIR%"
set "WORKBENCH_HOST=127.0.0.1"
set "WORKBENCH_PORT=8790"
if not defined STAGING_ROOT set "STAGING_ROOT=D:\MigrationJobs"

echo ============================================================
echo   CloudVault Concierge - Local Operator PC Workbench
echo   Bind URL     : http://127.0.0.1:%WORKBENCH_PORT%
echo   Staging Root : %STAGING_ROOT%
echo ============================================================

where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH.
    pause
    exit /b 1
)

if /I "%~1"=="--install" (
    echo [INFO] Installing workbench Python dependencies...
    python -m pip install -r "%ROOT_DIR%\workbench\requirements.txt"
)

start "" "http://127.0.0.1:%WORKBENCH_PORT%"
python -m workbench.server
endlocal
