from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


def load_http_module():
    script = Path(__file__).resolve().parents[1] / "scripts" / "mcp_http.py"
    spec = importlib.util.spec_from_file_location("ctfsolver_mcp_http", script)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class DummySettings:
    host = ""
    port = 0
    streamable_http_path = ""


class DummyMCP:
    settings = DummySettings()


def test_http_launcher_only_allows_loopback_hosts() -> None:
    launcher = load_http_module()

    assert launcher.is_loopback_host("127.0.0.1")
    assert launcher.is_loopback_host("localhost")
    assert launcher.is_loopback_host("::1")
    assert not launcher.is_loopback_host("0.0.0.0")
    assert not launcher.is_loopback_host("example.com")


def test_http_launcher_configures_streamable_http_settings() -> None:
    launcher = load_http_module()
    mcp = DummyMCP()

    launcher.configure_http_server(mcp, host="127.0.0.1", port=8765, path="mcp")

    assert mcp.settings.host == "127.0.0.1"
    assert mcp.settings.port == 8765
    assert mcp.settings.streamable_http_path == "/mcp"


def test_http_launcher_accepts_batch_mode_prefix() -> None:
    launcher = load_http_module()

    args = launcher.parse_args(["--http", "--host", "127.0.0.1", "--port", "8765"])

    assert args.host == "127.0.0.1"
    assert args.port == 8765


def test_http_launcher_rejects_non_loopback_bind() -> None:
    launcher = load_http_module()

    with pytest.raises(ValueError, match="loopback"):
        launcher.configure_http_server(DummyMCP(), host="0.0.0.0", port=8000, path="/mcp")
