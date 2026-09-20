#!/usr/bin/env bash
# setup_mcp.sh — Unix equivalent of setup_mcp.bat
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

uv run python scripts/setup.py --write --auth-check "$@"
SETUP_EXIT=$?
if [ $SETUP_EXIT -ne 0 ]; then
  exit $SETUP_EXIT
fi

echo ""
echo "Running ctfsolver doctor..."
uv run python scripts/doctor.py
DOCTOR_EXIT=$?
if [ $DOCTOR_EXIT -ne 0 ]; then
  echo "Doctor reported hard failures above. MCP config generation already completed."
fi
