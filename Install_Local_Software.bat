@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

set "APP_DIR=%LOCALAPPDATA%\Programs\EvilTwinDetector"
set "DIST_DIR=%~dp0dist\EvilTwinDetector"

echo ============================================================
echo   Evil Twin Wi-Fi Attack Detection Software - Installer
echo ============================================================
echo.

if not exist "%DIST_DIR%\EvilTwinDetector.exe" (
    echo [1/3] Standalone .exe not found yet. Building software first...
    call "%~dp0build_exe.bat"
    if errorlevel 1 exit /b 1
) else (
    echo [1/3] Found standalone build at "%DIST_DIR%"
)

echo [2/3] Installing software to "%APP_DIR%" ...
if not exist "%APP_DIR%" mkdir "%APP_DIR%"
robocopy "%DIST_DIR%" "%APP_DIR%" /E /IS /IT >nul
if errorlevel 8 (
    echo [ERROR] Failed to copy software files to "%APP_DIR%".
    pause
    exit /b 1
)

echo [3/3] Creating Desktop and Start Menu shortcuts...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ws = New-Object -ComObject WScript.Shell; $d = [Environment]::GetFolderPath('Desktop'); $sc = $ws.CreateShortcut((Join-Path $d 'Evil Twin Wi-Fi Detector.lnk')); $sc.TargetPath = '%APP_DIR%\EvilTwinDetector.exe'; $sc.WorkingDirectory = '%APP_DIR%'; $sc.IconLocation = '%APP_DIR%\EvilTwinDetector.exe,0'; $sc.Description = 'Evil Twin Wi-Fi Attack Detection Software'; $sc.Save()"
if errorlevel 1 (
    echo [ERROR] Failed to create Desktop shortcut.
    if /i "%~1" NEQ "--nopause" pause
    exit /b 1
)
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ws = New-Object -ComObject WScript.Shell; $m = [Environment]::GetFolderPath('Programs'); $sc = $ws.CreateShortcut((Join-Path $m 'Evil Twin Wi-Fi Detector.lnk')); $sc.TargetPath = '%APP_DIR%\EvilTwinDetector.exe'; $sc.WorkingDirectory = '%APP_DIR%'; $sc.IconLocation = '%APP_DIR%\EvilTwinDetector.exe,0'; $sc.Description = 'Evil Twin Wi-Fi Attack Detection Software'; $sc.Save()"
if errorlevel 1 (
    echo [ERROR] Failed to create Start Menu shortcut.
    if /i "%~1" NEQ "--nopause" pause
    exit /b 1
)

echo.
echo Installation complete!
echo   Installed Folder : %APP_DIR%
echo   Desktop Shortcut : Evil Twin Wi-Fi Detector
echo   Start Menu Entry : Evil Twin Wi-Fi Detector
echo.
if /i "%~1" NEQ "--nopause" pause
