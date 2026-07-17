"""Sprint-4 container hardening regression tests (P1-001/P1-002/F2).

Asserts the security kwargs actually reach docker `containers.run`. Real-container
behaviour (uid=1000, /workspace writable, mem cgroup enforced) was verified
out-of-band; these guard against silent regression of the config.
"""

import pytest
from unittest.mock import patch, MagicMock


def _patched_docker():
    """Context managers + mock client wired so run_tool() reaches containers.run."""
    p_platform = patch("src.ctf_core.docker_runner.get_platform")
    p_docker = patch("src.ctf_core.docker_runner.docker")
    return p_platform, p_docker


def _wire(mock_platform, mock_docker):
    mpi = MagicMock()
    mpi.platform.value = "windows"
    mpi.wsl_available = False
    mpi.get_docker_socket.return_value = None
    mock_platform.return_value = mpi

    client = MagicMock()
    mock_docker.from_env.return_value = client
    mock_docker.errors.APIError = Exception
    mock_docker.errors.NotFound = Exception
    client.images.get.return_value = MagicMock()  # image exists
    container = MagicMock()
    container.wait.return_value = {"StatusCode": 0}
    container.logs.return_value = [b"ok"]
    client.containers.run.return_value = container
    return client


class TestContainerHardening:
    @pytest.mark.asyncio
    async def test_runs_nonroot_with_limits(self):
        from src.ctf_core.docker_runner import DockerRunner

        p_platform, p_docker = _patched_docker()
        with p_platform as mock_platform, p_docker as mock_docker:
            client = _wire(mock_platform, mock_docker)
            runner = DockerRunner()
            await runner.run_tool("searchsploit", ["test"])

            assert client.containers.run.called
            kwargs = client.containers.run.call_args.kwargs
            assert kwargs.get("user") == "1000:1000"            # P1-001
            assert kwargs.get("mem_limit")                       # P1-002
            assert kwargs.get("pids_limit")                      # P1-002
            assert kwargs.get("cap_drop") == ["ALL"]
            assert "no-new-privileges:true" in kwargs.get("security_opt", [])

    @pytest.mark.asyncio
    async def test_nmap_keeps_net_raw_while_nonroot(self):
        from src.ctf_core.docker_runner import DockerRunner

        p_platform, p_docker = _patched_docker()
        with p_platform as mock_platform, p_docker as mock_docker:
            client = _wire(mock_platform, mock_docker)
            runner = DockerRunner()
            await runner.run_tool("nmap", ["-sV", "scanme.nmap.org"])

            kwargs = client.containers.run.call_args.kwargs
            assert kwargs.get("cap_add") == ["NET_RAW"]          # F2: SYN scans, no sudo
            assert kwargs.get("user") == "1000:1000"             # still non-root

    @pytest.mark.asyncio
    async def test_offline_tool_has_network_disabled(self):
        """P1-003: offline tools (searchsploit) run with network_disabled=True."""
        from src.ctf_core.docker_runner import DockerRunner

        p_platform, p_docker = _patched_docker()
        with p_platform as mock_platform, p_docker as mock_docker:
            client = _wire(mock_platform, mock_docker)
            runner = DockerRunner()
            await runner.run_tool("searchsploit", ["test"])
            assert client.containers.run.call_args.kwargs.get("network_disabled") is True

    @pytest.mark.asyncio
    async def test_network_tool_keeps_network(self):
        """P1-003: network tools (sqlmap) keep network access."""
        from src.ctf_core.docker_runner import DockerRunner

        p_platform, p_docker = _patched_docker()
        with p_platform as mock_platform, p_docker as mock_docker:
            client = _wire(mock_platform, mock_docker)
            runner = DockerRunner()
            await runner.run_tool("sqlmap", ["-u", "http://example.com/?id=1", "--batch"])
            assert client.containers.run.call_args.kwargs.get("network_disabled") is False
