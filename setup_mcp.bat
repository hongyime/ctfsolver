@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"

uv run python scripts\setup.py --write --auth-check %*
set "SETUP_EXIT=%ERRORLEVEL%"
if not "%SETUP_EXIT%"=="0" (
  endlocal & exit /b %SETUP_EXIT%
)

echo.
echo Running ctfsolver doctor...
uv run python scripts\doctor.py
set "DOCTOR_EXIT=%ERRORLEVEL%"
if not "%DOCTOR_EXIT%"=="0" (
  echo Doctor reported hard failures above. MCP config generation already completed.
)
endlocal
