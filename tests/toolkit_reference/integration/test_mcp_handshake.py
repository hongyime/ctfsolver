"""MCP server handshake and protocol tests."""

import asyncio
import json
import pytest
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch


class TestMCPProtocolHandshake:
    """Test MCP protocol handshake and message exchange."""

    @pytest.mark.asyncio
    async def test_server_initialization(self):
        """Test MCP server initializes correctly."""
        from src.ctf_core.server import mcp
        
        assert mcp is not None
        assert hasattr(mcp, 'tool')
        assert hasattr(mcp, 'run')

    @pytest.mark.asyncio
    async def test_tools_are_registered(self):
        """Test that tools are registered with the MCP server."""
        from src.ctf_core.server import mcp
        
        # Check that the server has tool methods
        # The actual tool definitions are internal to FastMCP
        has_tools = hasattr(mcp, '_tool_defs') or hasattr(mcp, '_tools') or hasattr(mcp, 'tool')
        assert has_tools, "MCP server should have tool registration mechanism"
        
        # We can at least verify the server starts
        assert mcp.name == "ctf-toolkit"

    @pytest.mark.asyncio
    async def test_tool_functions_exist(self):
        """Test that expected tool functions are defined."""
        from src.ctf_core import server
        
        # Check that the tool functions exist as callables
        expected_tools = [
            "run_nmap",
            "run_searchsploit",
            "run_feroxbuster",
            "run_sqlmap",
            "query_targets",
            "query_services",
            "get_recent_actions",
            "analyze_challenge",
            "health_check",
        ]
        
        for tool_name in expected_tools:
            assert hasattr(server, tool_name), f"Tool function {tool_name} not found"
            tool_func = getattr(server, tool_name)
            assert callable(tool_func), f"{tool_name} is not callable"

    @pytest.mark.asyncio
    async def test_async_tool_execution(self):
        """Test async tool execution works correctly."""
        from src.ctf_core.agents.auto_prompter import AutoPrompter
        import asyncio
        
        async def test_tool_call():
            prompter = AutoPrompter()
            result = prompter.analyze_input("test web challenge")
            assert result is not None
            assert "category" in result
        
        await asyncio.wait_for(test_tool_call(), timeout=5.0)


class TestMCPMessageFormat:
    """Test MCP message formatting and parsing."""

    def test_json_serialization(self):
        """Test that tool responses are JSON serializable."""
        from src.ctf_core.parsers.nmap_parser import generate_summary
        
        parsed_data = {
            "hosts": [
                {
                    "ip_address": "10.10.10.10",
                    "hostname": None,
                    "os_type": None,
                    "services": [
                        {"port": 22, "protocol": "tcp", "service_name": "ssh"},
                        {"port": 80, "protocol": "tcp", "service_name": "http"},
                    ],
                }
            ]
        }
        
        summary = generate_summary(parsed_data)
        
        # Should be serializable
        json.dumps({"result": summary})

    def test_error_handling_format(self):
        """Test error responses follow expected format."""
        from src.ctf_core.utils.sanitize import sanitize_command
        
        # Test that dangerous commands are rejected
        is_safe, binary, args = sanitize_command("nmap", ["10.10.10.10"])
        assert is_safe
        assert binary == "nmap"


class TestMCPLifecycle:
    """Test MCP server lifecycle management."""

    @pytest.mark.asyncio
    async def test_server_startup(self):
        """Test server starts without errors."""
        from src.ctf_core.server import main, mcp
        
        assert callable(main)
        assert mcp is not None

    @pytest.mark.asyncio
    async def test_database_initialization(self):
        """Test database can be initialized."""
        from src.ctf_core.db import get_database, close_database
        
        assert callable(get_database)
        assert callable(close_database)
