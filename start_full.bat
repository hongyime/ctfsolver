@echo off
setlocal
chcp 65001 >nul
set "ROOT=%~dp0"
cd /d "%ROOT%"

set "PYTHONUTF8=1"
if defined PYTHONPATH (
  set "PYTHONPATH=%ROOT%src;%PYTHONPATH%"
) else (
  set "PYTHONPATH=%ROOT%src"
)

rem -- workdir: --workdir flag > CTF_WORKDIR env > fallback to error (no repo default)
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
if not defined CTF_HARNESS_AGENT_MCP_URL set "CTF_HARNESS_AGENT_MCP_URL=http://127.0.0.1:8000/mcp"

if not exist "%CTFTOOLKIT_WORKSPACE%" mkdir "%CTFTOOLKIT_WORKSPACE%"
if not exist "%CTFTOOLKIT_DOWNLOADS%" mkdir "%CTFTOOLKIT_DOWNLOADS%"
if not exist "%ROOT%logs" mkdir "%ROOT%logs"

if /I not "%CTF_HARNESS_START_AGENT_MCP%"=="0" (
  echo Starting ctfsolver backend MCP HTTP server for dashboard agents...
  start "ctfsolver-mcp" /min "%ComSpec%" /c ""%ROOT%start_backend.bat" --http --host 127.0.0.1 --port 8000 --path /mcp"
  timeout /t 2 /nobreak >nul
)

uv run streamlit run "%ROOT%streamlit_app.py" %*
endlocal
