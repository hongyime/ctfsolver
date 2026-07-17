from __future__ import annotations

import json
from pathlib import Path

from ctf_core.manifest import build_manifest


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_manifest_generation_preserves_known_inventory() -> None:
    manifest = build_manifest(repo_root())

    assert manifest["counts"] == {
        "mcp_tools": 94,
        "registry_tools": 60,
        "skill_docs": 33,
        "dockerfiles": 7,
        "schemas": 2,
        "launchers": 5,
        "docs_toolkit_assets": 13,
    }

    inventory = manifest["inventory"]
    assert inventory["mcp_tools"] == sorted(inventory["mcp_tools"], key=str.casefold)
    assert inventory["registry_tools"] == sorted(
        inventory["registry_tools"], key=str.casefold
    )
    assert inventory["skill_docs"] == sorted(inventory["skill_docs"], key=str.casefold)
    assert inventory["dockerfiles"] == sorted(inventory["dockerfiles"], key=str.casefold)

    assert "run_nmap" in inventory["mcp_tools"]
    assert "get_playbook" in inventory["mcp_tools"]
    assert "nmap" in inventory["registry_tools"]
    assert "zsteg" in inventory["registry_tools"]
    assert "skills/web/ctf-web-sqli.md" in inventory["skill_docs"]
    assert "Dockerfile.ctf-tools" in inventory["dockerfiles"]
    assert "docker/ctf-tools/Dockerfile" in inventory["dockerfiles"]
    assert "schema/init_db.sql" in inventory["schemas"]
    assert "start_backend.bat" in inventory["launchers"]
    assert "mcp.json" in inventory["launchers"]
    assert "mcp.local.json" not in inventory["launchers"]
    assert "docs/toolkit/README.ctftoolkit.md" in inventory["docs_toolkit_assets"]


def test_committed_toolkit_manifest_matches_generated_output() -> None:
    root = repo_root()
    committed = json.loads((root / "toolkit_manifest.json").read_text(encoding="utf-8"))

    assert committed == build_manifest(root)
