@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo ============================================================
echo   Evil Twin Wi-Fi Attack Detection System - Web Launcher
echo ============================================================
echo.

REM Activate existing virtual environment if present
if exist ".venv\Scripts\activate.bat" (
    echo [1/3] Activating .venv virtual environment...
    call ".venv\Scripts\activate.bat"
) else if exist "venv\Scripts\activate.bat" (
    echo [1/3] Activating venv virtual environment...
    call "venv\Scripts\activate.bat"
) else (
    echo [1/3] Using system Python environment...
)

where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH.
    pause
    exit /b 1
)

echo [2/3] Verifying required Python dependencies...
python -c "import flask, pandas, numpy, sklearn, joblib" >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Missing required dependencies.
    echo Run: pip install -r requirements.txt
    pause
    exit /b 1
)

echo [3/3] Starting Flask web server at http://127.0.0.1:5000 ...
echo Press Ctrl+C in this window to stop the server.
echo.
start "" "http://127.0.0.1:5000"
python app.py

if errorlevel 1 (
    echo.
    echo [ERROR] Application exited with an error.
    pause
    exit /b 1
)
