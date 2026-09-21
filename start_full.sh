#!/usr/bin/env bash
# start_full.sh — Unix equivalent of start_full.bat
# Usage:
#   ./start_full.sh --workdir /path/to/ctf
#   ./start_full.sh --workdir /path/to/ctf --port 8001   # parallel second session
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

export PYTHONUTF8=1
if [ -n "${PYTHONPATH:-}" ]; then
  export PYTHONPATH="$ROOT/src:$PYTHONPATH"
else
  export PYTHONPATH="$ROOT/src"
fi

# -- Docker socket auto-detection (macOS / Linux / WSL2 / Colima / Rancher)
# Probes in priority order; user can always override via DOCKER_SOCKET or
# DOCKER_HOST in the environment or .env.
if [ -z "${DOCKER_SOCKET:-}" ] && [ -z "${DOCKER_HOST:-}" ]; then
  for _sock in \
      "${HOME}/.docker/run/docker.sock" \
      "${HOME}/.colima/default/docker.sock" \
      "${HOME}/.rd/docker.sock" \
      "/var/run/docker.sock" \
      "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/docker.sock"; do
    if [ -S "$_sock" ]; then
      export DOCKER_SOCKET="$_sock"
      export DOCKER_HOST="unix://$_sock"
      break
    fi
  done
fi
if [ -n "${DOCKER_SOCKET:-}" ]; then
  echo "  Docker socket: $DOCKER_SOCKET"
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

# -- mcp port: --port <n> flag (default 8000) for parallel sessions
MCP_PORT=8000
if [ "${1:-}" = "--port" ]; then
  MCP_PORT="$2"
  shift 2
fi
: "${CTF_HARNESS_AGENT_MCP_URL:=http://127.0.0.1:${MCP_PORT}/mcp}"
export CTF_HARNESS_AGENT_MCP_URL

mkdir -p "$CTFTOOLKIT_WORKSPACE" "$CTFTOOLKIT_DOWNLOADS" "$ROOT/logs"

# Start MCP HTTP backend in background (unless disabled)
if [ "${CTF_HARNESS_START_AGENT_MCP:-1}" != "0" ]; then
  echo "Starting ctfsolver backend MCP HTTP server for dashboard agents..."
  nohup uv run python scripts/mcp_http.py \
    --host 127.0.0.1 --port "$MCP_PORT" --path /mcp \
    > "$ROOT/logs/mcp-http-${MCP_PORT}.log" 2>&1 &
  MCP_PID=$!
  echo "  MCP backend PID $MCP_PID → logs/mcp-http-${MCP_PORT}.log"
  sleep 2
fi

uv run streamlit run "$ROOT/streamlit_app.py" "$@"
