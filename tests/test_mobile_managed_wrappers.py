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
async def test_mobile_and_managed_wrappers_route_to_lazy_image(tmp_path, monkeypatch) -> None:
    workspace = tmp_path / "workspace"
    fake = FakeDockerRunner()
    monkeypatch.setattr(server, "_workspace_root", lambda: workspace)
    monkeypatch.setattr(server, "docker_runner", fake)
    monkeypatch.setattr(server, "db", object())

    apktool = await server.run_apktool("apps/challenge.apk")
    jadx = await server.run_jadx("apps/challenge.apk")
    ilspy = await server.run_ilspycmd("managed/challenge.dll")
    pyinst = await server.run_pyinstxtractor("managed/challenge.exe")
    blocked = await server.run_jadx("../escape.apk")

    assert "apktool ok" in apktool
    assert "jadx ok" in jadx
    assert "ilspycmd ok" in ilspy
    assert "pyinstxtractor ok" in pyinst
    assert "outside workspace" in blocked
    assert [call["tool"] for call in fake.calls] == [
        "apktool",
        "jadx",
        "ilspycmd",
        "pyinstxtractor",
    ]
    assert all(call["image"] == "ctftoolkit/ctf-mobile" for call in fake.calls)
    assert fake.calls[0]["args"][:4] == [
        "d",
        "-f",
        "-o",
        "/workspace/derived/apktool_challenge",
    ]
    assert fake.calls[1]["args"][:2] == ["-d", "/workspace/derived/jadx_challenge"]
    assert fake.calls[2]["args"][:3] == ["-p", "-o", "/workspace/derived/ilspy_challenge"]
