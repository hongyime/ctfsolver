#!/usr/bin/env bash
# start_backend.sh — Unix equivalent of start_backend.bat
# Usage:
#   ./start_backend.sh --workdir /path/to/ctf         # start MCP stdio server
#   ./start_backend.sh --workdir /path/to/ctf --doctor
#   ./start_backend.sh --workdir /path/to/ctf --smoke
#   ./start_backend.sh --workdir /path/to/ctf --http --port 8000 --path /mcp
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

export PYTHONUTF8=1
if [ -n "${PYTHONPATH:-}" ]; then
  export PYTHONPATH="$ROOT/src:$PYTHONPATH"
else
  export PYTHONPATH="$ROOT/src"
fi

# -- workdir: --workdir flag > CTF_WORKDIR env > fallback to error (no repo default)
if [ "${1:-}" = "--workdir" ]; then
  export CTF_WORKDIR="$2"
  shift 2
fi
if [ -n "${CTF_WORKDIR:-}" ]; then
  export CTFTOOLKIT_WORKSPACE="$CTF_WORKDIR"
elif [ -z "${CTFTOOLKIT_WORKSPACE:-}" ]; then
  echo "[ERROR] No working directory set. Use --workdir <path> or set CTF_WORKDIR." >&2
  exit 1
fi
: "${CTFTOOLKIT_DB_PATH:=$CTFTOOLKIT_WORKSPACE/ctf_state.db}"
: "${CTFTOOLKIT_DOWNLOADS:=$CTFTOOLKIT_WORKSPACE/downloads}"
export CTFTOOLKIT_DB_PATH CTFTOOLKIT_DOWNLOADS

mkdir -p "$CTFTOOLKIT_WORKSPACE" "$CTFTOOLKIT_DOWNLOADS" "$ROOT/logs"

if [ "${1:-}" = "--doctor" ]; then
  uv run python scripts/doctor.py
  exit $?
fi

if [ "${1:-}" = "--smoke" ]; then
  if [ -f "$ROOT/scripts/mcp_smoke.py" ]; then
    uv run python scripts/mcp_smoke.py
  else
    echo "No MCP smoke script found; running doctor instead."
    uv run python scripts/doctor.py
  fi
  exit $?
fi

if [ "${1:-}" = "--http" ]; then
  shift
  uv run python scripts/mcp_http.py "$@"
  exit $?
fi

uv run python -m ctf_core.server "$@"
