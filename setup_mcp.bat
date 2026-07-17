@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"

uv run python scripts\setup.py --write --auth-check %*
endlocal
