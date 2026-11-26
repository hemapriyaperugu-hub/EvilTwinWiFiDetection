@echo off
cd /d "%~dp0"
echo ============================================================
echo   Building Standalone Windows Software (.exe via PyInstaller)
echo ============================================================
python -c "import EvilTwinDetector as d; d.ensure_app_icon()"
python -m PyInstaller --version >nul 2>nul
if errorlevel 1 (
    echo Installing PyInstaller...
    python -m pip install pyinstaller
    if errorlevel 1 (
        echo [ERROR] Failed to install PyInstaller. Check internet/pip and retry.
        pause
        exit /b 1
    )
)
python -m PyInstaller --noconfirm EvilTwinDetector.spec
if errorlevel 1 (
    echo [ERROR] PyInstaller build failed.
    pause
    exit /b 1
)
echo.
echo Build complete! Standalone software folder:
echo   %~dp0dist\EvilTwinDetector\EvilTwinDetector.exe
if /i "%~1" NEQ "--nopause" pause
