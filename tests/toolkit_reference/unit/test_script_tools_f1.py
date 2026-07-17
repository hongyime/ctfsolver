"""F1 regression: script-exec tool families (run_z3/run_pwntools/run_gdb_script/decode_stego).

run_z3 was additionally verified end-to-end against a real ctf-crypto container
(z3 solved x*x==49 -> x=7); these mocked tests pin the wiring/routing."""

import tempfile
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

import src.ctf_core.server as srv


def _capture_runner():
    calls = []

    async def fake(tool, args, timeout=120, image=None):
        calls.append({"tool": tool, "args": list(args), "image": image})
        return {"stdout": f"<{tool}:{image}>", "stderr": "", "exit_code": 0}

    runner = AsyncMock()
    runner.run_tool = AsyncMock(side_effect=fake)
    return runner, calls


class TestScriptToolsF1:
    @pytest.mark.asyncio
    async def test_run_z3_routes_to_crypto(self):
        srv.docker_runner, calls = _capture_runner()
        try:
            out = await srv.run_z3("print(1)")
        finally:
            srv.docker_runner = None
        assert calls and calls[0]["tool"] == "python3"
        assert calls[0]["image"] == "ctftoolkit/ctf-crypto"
        assert calls[0]["args"][-1].startswith("/workspace/_f1_")
        assert "<python3:ctftoolkit/ctf-crypto>" in out

    @pytest.mark.asyncio
    async def test_run_pwntools_routes_to_pwn(self):
        srv.docker_runner, calls = _capture_runner()
        try:
            await srv.run_pwntools("print('x')")
        finally:
            srv.docker_runner = None
        assert calls[0]["tool"] == "python3" and calls[0]["image"] == "ctftoolkit/ctf-pwn"

    @pytest.mark.asyncio
    async def test_run_gdb_script_batch(self):
        srv.docker_runner, calls = _capture_runner()
        try:
            await srv.run_gdb_script("bin", "info functions")
        finally:
            srv.docker_runner = None
        a = calls[0]
        assert a["tool"] == "gdb" and a["image"] == "ctftoolkit/ctf-pwn"
        assert "-batch" in a["args"] and "-x" in a["args"]
        assert "/workspace/bin" in a["args"]

    @pytest.mark.asyncio
    async def test_decode_stego_runs_tools(self):
        srv.docker_runner, calls = _capture_runner()
        try:
            out = await srv.decode_stego("img.png")
        finally:
            srv.docker_runner = None
        tools = {c["tool"] for c in calls}
        assert {"exiftool", "strings", "steghide"} <= tools
        assert all("/workspace/img.png" in c["args"] for c in calls)
        assert "# Stego analysis: img.png" in out

    @pytest.mark.asyncio
    async def test_run_sage_routes_to_sage(self):
        srv.docker_runner, calls = _capture_runner()
        try:
            out = await srv.run_sage("print(1)")
        finally:
            srv.docker_runner = None
        assert calls and calls[0]["tool"] == "sage"
        assert calls[0]["image"] == "ctftoolkit/ctf-sage"
        assert calls[0]["args"][-1].startswith("/workspace/_f1_")
        assert calls[0]["args"][-1].endswith(".sage")
        assert "<sage:ctftoolkit/ctf-sage>" in out
