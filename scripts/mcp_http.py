from __future__ import annotations

import argparse
import ipaddress
import sys
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


def is_loopback_host(host: str) -> bool:
    normalized = host.strip().lower()
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized.strip("[]")).is_loopback
    except ValueError:
        return False


def normalize_path(path: str) -> str:
    cleaned = path.strip() or "/mcp"
    return cleaned if cleaned.startswith("/") else f"/{cleaned}"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0].lower() == "--http":
        argv = argv[1:]
    parser = argparse.ArgumentParser(
        description="Run ctfsolver MCP over localhost streamable HTTP."
    )
    parser.add_argument("--host", default="127.0.0.1", help="Loopback host only.")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--path", default="/mcp", help="HTTP MCP mount path.")
    return parser.parse_args(argv)


def configure_http_server(mcp_server: Any, *, host: str, port: int, path: str) -> None:
    if not is_loopback_host(host):
        raise ValueError("HTTP MCP mode only binds to localhost or loopback addresses.")
    if port <= 0 or port > 65535:
        raise ValueError("port must be between 1 and 65535")

    mcp_server.settings.host = host
    mcp_server.settings.port = port
    mcp_server.settings.streamable_http_path = normalize_path(path)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    from ctf_core.server import mcp  # noqa: E402

    try:
        configure_http_server(mcp, host=args.host, port=args.port, path=args.path)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    print(
        "Starting ctfsolver MCP HTTP server at "
        f"http://{mcp.settings.host}:{mcp.settings.port}{mcp.settings.streamable_http_path}",
        file=sys.stderr,
    )
    mcp.run(transport="streamable-http")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
