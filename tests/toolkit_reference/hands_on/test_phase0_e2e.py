"""Phase 0 real-Docker E2E test.

Verifies the Phase 0 Definition-of-Done: the ctf-tools image builds and the tools
that were previously *mapped but missing* actually run inside it. Marked so it is
skipped automatically when Docker is unavailable, keeping the offline suite green.

Run explicitly:
    pytest tests/hands_on/test_phase0_e2e.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
SRC = PROJECT_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def _docker_available() -> bool:
    try:
        import docker
        client = docker.from_env()
        client.ping()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _docker_available(),
    reason="Docker daemon not reachable; Phase 0 E2E requires a running Docker engine.",
)


@pytest.fixture(scope="module")
def runner():
    from ctf_core.docker_runner import DockerRunner
    return DockerRunner()


@pytest.fixture(scope="module")
def ctf_tools_built(runner):
    """Ensure the ctf-tools image exists (lazy-build if missing)."""
    import asyncio
    ok = asyncio.run(runner._ensure_image("ctftoolkit/ctf-tools"))
    assert ok, "ctf-tools image failed to build"
    return ok


# Binaries whose presence in the built ctf-tools image IS the Phase 0 DoD
# ("every existing MCP tool runs against a built image"). We check the image
# directly via docker exec because the app's command whitelist deliberately
# rejects probe flags like --version (defense in depth) — that is correct
# behaviour, so we verify image *contents*, not the sanitizer, here.
PHASE0_TOOLS = [
    "nmap", "sqlmap", "nikto", "gobuster", "ffuf", "hydra", "whatweb",
    "feroxbuster", "httpx", "amass", "assetfinder", "wfuzz",
    "checksec",            # (in ctf-pwn, checked separately below)
    "spiderfoot", "theHarvester",  # dockerized OSINT (replaces host subprocess)
]


def _binary_in_image(runner, image: str, binary: str) -> str:
    """Return the resolved path of `binary` in `image`, or '' if absent."""
    container = runner.client.containers.run(
        image, command=["sh", "-c", f"command -v {binary} || true"],
        remove=True, network_disabled=True, stdout=True, stderr=True,
    )
    return container.decode("utf-8", "replace").strip()


def test_ctf_tools_binaries_present(runner, ctf_tools_built):
    """Every web/recon/OSINT tool mapped to ctf-tools resolves to a real binary."""
    missing = []
    for tool in PHASE0_TOOLS:
        if tool == "checksec":
            continue  # lives in ctf-pwn, asserted in its own test
        path = _binary_in_image(runner, "ctftoolkit/ctf-tools", tool)
        if not path:
            missing.append(tool)
    assert not missing, f"ctf-tools missing binaries: {missing}"


def test_checksec_in_pwn_image(runner):
    """checksec is mapped to ctf-pwn and must exist there (Phase 0 mapping fix)."""
    import asyncio
    assert asyncio.run(runner._ensure_image("ctftoolkit/ctf-pwn")), "ctf-pwn build failed"
    path = _binary_in_image(runner, "ctftoolkit/ctf-pwn", "checksec")
    assert path, "checksec not found in ctf-pwn image"


@pytest.mark.asyncio
async def test_nmap_runs_through_runner(runner, ctf_tools_built):
    """Full sanitized DockerRunner path accepts a whitelisted nmap invocation.

    Proves the sanitize -> whitelist -> net_guard -> container pipeline is wired:
    the command passes sanitization/whitelisting and reaches the network guard.
    A blocked loopback target is itself evidence the guarded path executed.
    """
    result = await runner.run_tool("nmap", ["-p", "22", "127.0.0.1"], timeout=120)
    combined = (result.get("stdout", "") + result.get("stderr", "")).lower()
    # Must NOT be rejected by sanitize/whitelist (those would raise/explain differently)
    # and the image must exist. Reaching the net_guard (loopback block) or running nmap
    # both prove the full pipeline executed.
    assert result.get("error") != "image_not_found", "ctf-tools image missing"
    assert ("nmap" in combined or "scan report" in combined
            or result.get("error") == "network_blocked"
            or "loopback" in combined), (
        f"sanitized nmap path did not execute as expected: {combined[:200]}")
