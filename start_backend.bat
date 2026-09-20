@echo off
setlocal EnableDelayedExpansion
chcp 65001 >nul
set "ROOT=%~dp0"
cd /d "%ROOT%"

set "PYTHONUTF8=1"
if defined PYTHONPATH (
  set "PYTHONPATH=%ROOT%src;%PYTHONPATH%"
) else (
  set "PYTHONPATH=%ROOT%src"
)

rem ── workdir: --workdir flag > CTF_WORKDIR env > fallback to error (no repo default)
set "_WORKDIR_ARG="
if /I "%~1"=="--workdir" (
  set "CTF_WORKDIR=%~2"
  shift /1
  shift /1
)
if defined CTF_WORKDIR (
  set "CTFTOOLKIT_WORKSPACE=%CTF_WORKDIR%"
) else if not defined CTFTOOLKIT_WORKSPACE (
  echo [ERROR] No working directory set. Use --workdir ^<path^> or set CTF_WORKDIR.
  endlocal & exit /b 1
)
if not defined CTFTOOLKIT_DB_PATH set "CTFTOOLKIT_DB_PATH=%CTFTOOLKIT_WORKSPACE%\ctf_state.db"
if not defined CTFTOOLKIT_DOWNLOADS set "CTFTOOLKIT_DOWNLOADS=%CTFTOOLKIT_WORKSPACE%\downloads"

if not exist "%CTFTOOLKIT_WORKSPACE%" mkdir "%CTFTOOLKIT_WORKSPACE%"
if not exist "%CTFTOOLKIT_DOWNLOADS%" mkdir "%CTFTOOLKIT_DOWNLOADS%"
if not exist "%ROOT%logs" mkdir "%ROOT%logs"

if /I "%~1"=="--doctor" (
  uv run python scripts\doctor.py
  endlocal & exit /b !ERRORLEVEL!
)

if /I "%~1"=="--smoke" (
  if exist "%ROOT%scripts\mcp_smoke.py" (
    uv run python scripts\mcp_smoke.py
  ) else (
    echo No MCP smoke script found; running doctor instead.
    uv run python scripts\doctor.py
  )
  endlocal & exit /b !ERRORLEVEL!
)

if /I "%~1"=="--http" (
  shift /1
  uv run python scripts\mcp_http.py %*
  set "HTTP_EXIT=!ERRORLEVEL!"
  endlocal & exit /b !HTTP_EXIT!
)

uv run python -m ctf_core.server %*
endlocal
