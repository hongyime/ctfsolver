"""P5 regression: docker_runner records metrics (tracing.MetricsCollector is wired)."""

from unittest.mock import patch, MagicMock

import pytest


@pytest.mark.asyncio
async def test_tool_run_records_metrics():
    with patch("src.ctf_core.docker_runner.get_platform") as mp, \
         patch("src.ctf_core.docker_runner.docker") as md:
        from src.ctf_core.docker_runner import DockerRunner
        from src.ctf_core.observability.tracing import get_metrics

        mpi = MagicMock()
        mpi.platform.value = "windows"
        mpi.wsl_available = False
        mpi.get_docker_socket.return_value = None
        mp.return_value = mpi

        client = MagicMock()
        md.from_env.return_value = client
        md.errors.APIError = Exception
        md.errors.NotFound = Exception
        client.images.get.return_value = MagicMock()
        cont = MagicMock()
        cont.wait.return_value = {"StatusCode": 0}
        cont.logs.return_value = [b"x"]
        client.containers.run.return_value = cont

        runner = DockerRunner()
        await runner.run_tool("searchsploit", ["test"])

        names = {pt.name for pt in get_metrics()._metrics}
        assert "tool.executions" in names
        assert "tool.duration_ms" in names
