from __future__ import annotations

from hashlib import sha256

from ctf_core.artifact_triage import triage_artifact
from ctf_core.workflows import suggest_next_tools


def _tool_names(recommendations: list[dict]) -> list[str]:
    return [str(item["tool"]) for item in recommendations]


def test_suggest_next_tools_web_path() -> None:
    recommendations = suggest_next_tools(
        description="Login bypass with SQL injection, JWT cookie, and hidden admin endpoints",
        category="web",
        target="http://challenge.local:8080",
        files=["app.py"],
        findings=["SQL error near UNION SELECT"],
    )
    tools = _tool_names(recommendations)

    assert tools.index("run_sqlmap") < tools.index("run_nuclei")
    assert "run_feroxbuster" in tools
    assert "run_ffuf" in tools
    assert "run_jwt_tool" in tools


def test_suggest_next_tools_reverse_engineering_path() -> None:
    recommendations = suggest_next_tools(
        description="Reverse this wasm checker and recover the validation constraints",
        category="rev",
        files=["checker.wasm", "runner"],
        findings=["WebAssembly module with exported verify function"],
    )
    tools = _tool_names(recommendations)

    assert tools[0] == "run_wasm2wat"
    assert "run_binary_analysis" in tools
    assert "run_z3" in tools


def test_suggest_next_tools_crypto_path() -> None:
    recommendations = suggest_next_tools(
        description="RSA public key with n, e, and ciphertext; maybe Fermat factorization",
        category="crypto",
        files=["public.pem", "cipher.txt"],
    )
    tools = _tool_names(recommendations)

    assert tools[0] == "run_rsactftool"
    assert "run_sage" in tools
    assert "run_z3" in tools


def test_suggest_next_tools_forensics_path() -> None:
    recommendations = suggest_next_tools(
        description="Hidden flag in a PNG LSB stego image",
        category="forensics",
        files=["image.png"],
        findings=["zlib stream and suspicious appended data"],
    )
    tools = _tool_names(recommendations)

    assert tools[0] == "run_zsteg"
    assert "decode_stego" in tools
    assert "run_binary_analysis" in tools


def test_triage_artifact_png_temp_file(tmp_path) -> None:
    data = b"\x89PNG\r\n\x1a\n\x00hidden marker CTF{sample_flag}\x00"
    path = tmp_path / "image.png"
    path.write_bytes(data)

    result = triage_artifact(path)
    tools = _tool_names(result["recommended_next_tools"])

    assert result["sha256"] == sha256(data).hexdigest()
    assert result["size"] == len(data)
    assert result["suffix"] == ".png"
    assert "png image" in result["type_hints"]
    assert "hidden marker CTF{sample_flag}" in result["string_samples"]
    assert "run_zsteg" in tools
    assert "run_binary_analysis" in tools


def test_triage_artifact_text_crypto_temp_file(tmp_path) -> None:
    data = b"-----BEGIN PUBLIC KEY-----\nRSA modulus n = 3233\ne = 17\nciphertext = 855\n"
    path = tmp_path / "public.pem"
    path.write_bytes(data)

    result = triage_artifact(path)
    tools = _tool_names(result["recommended_next_tools"])

    assert result["sha256"] == sha256(data).hexdigest()
    assert result["size"] == len(data)
    assert "text" in result["type_hints"]
    assert "pem key" in result["type_hints"]
    assert result["category_hint"] == "crypto"
    assert tools[0] == "run_rsactftool"
