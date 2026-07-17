from __future__ import annotations

import pytest

from ctf_core import server


class FakeDockerRunner:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def run_tool(self, tool, args, timeout=0, image=None):
        self.calls.append(
            {
                "tool": tool,
                "args": list(args),
                "timeout": timeout,
                "image": image,
            }
        )
        return {"stdout": f"{tool} ok\n", "stderr": "", "exit_code": 0}


@pytest.mark.asyncio
async def test_web_api_and_secret_wrappers_route_with_scope(tmp_path, monkeypatch) -> None:
    workspace = tmp_path / "workspace"
    fake = FakeDockerRunner()
    monkeypatch.setattr(server, "_workspace_root", lambda: workspace)
    monkeypatch.setattr(server, "_is_target_in_scope", lambda target: "blocked" not in target)
    monkeypatch.setattr(server, "docker_runner", fake)
    monkeypatch.setattr(server, "db", object())

    katana = await server.run_katana("https://challenge.local")
    arjun = await server.run_arjun("https://challenge.local/login")
    linkfinder = await server.run_linkfinder("files/app.js")
    git_dumper = await server.run_git_dumper("https://challenge.local/.git/")
    gitleaks = await server.run_gitleaks("derived/git-dumper")
    schemathesis = await server.run_schemathesis(
        "files/openapi.json",
        base_url="https://challenge.local/api",
    )
    graphql = await server.run_graphql_cop("https://challenge.local/graphql")
    blocked = await server.run_katana("https://blocked.local")

    assert "katana ok" in katana
    assert "arjun ok" in arjun
    assert "linkfinder ok" in linkfinder
    assert "git-dumper ok" in git_dumper
    assert "gitleaks ok" in gitleaks
    assert "schemathesis ok" in schemathesis
    assert "graphql-cop ok" in graphql
    assert "Target out of scope" in blocked
    assert [call["tool"] for call in fake.calls] == [
        "katana",
        "arjun",
        "linkfinder",
        "git-dumper",
        "gitleaks",
        "schemathesis",
        "graphql-cop",
    ]
    assert fake.calls[2]["args"][:2] == ["-i", "/workspace/files/app.js"]
    assert fake.calls[3]["args"] == [
        "https://challenge.local/.git/",
        "/workspace/derived/git-dumper",
    ]
    assert fake.calls[4]["args"][:3] == ["detect", "--source", "/workspace/derived/git-dumper"]
    assert fake.calls[5]["args"][:4] == [
        "run",
        "/workspace/files/openapi.json",
        "--base-url",
        "https://challenge.local/api",
    ]


@pytest.mark.asyncio
async def test_capinfos_wrapper_routes_to_forensics_image(tmp_path, monkeypatch) -> None:
    workspace = tmp_path / "workspace"
    fake = FakeDockerRunner()
    monkeypatch.setattr(server, "_workspace_root", lambda: workspace)
    monkeypatch.setattr(server, "docker_runner", fake)
    monkeypatch.setattr(server, "db", object())

    out = await server.run_capinfos("pcap/capture.pcapng")
    blocked = await server.run_capinfos("../capture.pcapng")

    assert "capinfos ok" in out
    assert "outside workspace" in blocked
    assert fake.calls == [
        {
            "tool": "capinfos",
            "args": ["-a", "-c", "-d", "-e", "-H", "/workspace/pcap/capture.pcapng"],
            "timeout": 120,
            "image": "ctftoolkit/ctf-forensics",
        }
    ]
