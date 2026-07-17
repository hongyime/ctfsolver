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

if not defined CTFTOOLKIT_WORKSPACE set "CTFTOOLKIT_WORKSPACE=%ROOT%workspace"
if not defined CTFTOOLKIT_DB_PATH set "CTFTOOLKIT_DB_PATH=%ROOT%ctf_state.db"
if not defined CTFTOOLKIT_DOWNLOADS set "CTFTOOLKIT_DOWNLOADS=%ROOT%downloads"

if not exist "%CTFTOOLKIT_WORKSPACE%" mkdir "%CTFTOOLKIT_WORKSPACE%"
if not exist "%CTFTOOLKIT_DOWNLOADS%" mkdir "%CTFTOOLKIT_DOWNLOADS%"
if not exist "%ROOT%logs" mkdir "%ROOT%logs"

uv run streamlit run "%ROOT%streamlit_app.py" %*
endlocal
