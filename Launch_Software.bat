@echo off
cd /d "%~dp0"

if exist ".venv\Scripts\pythonw.exe" (
    start "" ".venv\Scripts\pythonw.exe" "%~dp0EvilTwinDetector.pyw"
    exit /b 0
)
if exist "venv\Scripts\pythonw.exe" (
    start "" "venv\Scripts\pythonw.exe" "%~dp0EvilTwinDetector.pyw"
    exit /b 0
)

where pythonw >nul 2>nul
if not errorlevel 1 (
    start "" pythonw "%~dp0EvilTwinDetector.pyw"
    exit /b 0
)

start "" python "%~dp0EvilTwinDetector.pyw"
exit /b 0
