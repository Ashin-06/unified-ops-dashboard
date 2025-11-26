@echo off
:: Check for Administrator privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [Admin] Privileges confirmed.
) else (
    echo [Request] Requesting Administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
echo [+] Working Directory: %CD%
echo.
echo [+] Starting Dashboard...
echo.
python -m uvicorn main:app --host 0.0.0.0 --port 8081
pause
