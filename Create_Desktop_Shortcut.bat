@echo off
cd /d "%~dp0"
echo Creating Desktop shortcut for Evil Twin Wi-Fi Attack Detection Software...
python -c "import EvilTwinDetector as d; p = d.create_windows_desktop_shortcut(); print('Shortcut created at:', p)"
if errorlevel 1 (
    echo [ERROR] Could not create Desktop shortcut.
    pause
    exit /b 1
)
echo Done! Double-click "Evil Twin Wi-Fi Detector" on your Desktop to launch.
if /i "%~1" NEQ "--nopause" pause
