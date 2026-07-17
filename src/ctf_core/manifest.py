"""Deterministic preservation manifest for absorbed toolkit assets."""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any, Iterable

MCP_SERVER = Path("src") / "ctf_core" / "server.py"
MAIN_MCP_CONFIGS = ("mcp.json", "mcp-windows.json")
ROOT_DOCKERFILES = ("Dockerfile.ctf-tools",)


def repo_root() -> Path:
    """Return the flattened solver repository root."""
    return Path(__file__).resolve().parents[2]


def _sort_strings(values: Iterable[str]) -> list[str]:
    return sorted(values, key=lambda value: value.casefold())


def _relative(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _existing_relative_files(root: Path, paths: Iterable[Path]) -> list[str]:
    return _sort_strings(_relative(path, root) for path in paths if path.is_file())


def _is_mcp_tool_decorator(decorator: ast.expr) -> bool:
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    return (
        isinstance(target, ast.Attribute)
        and target.attr == "tool"
        and isinstance(target.value, ast.Name)
        and target.value.id == "mcp"
    )


def discover_mcp_tools(root: Path | None = None) -> list[str]:
    """Parse server.py and return names decorated with @mcp.tool."""
    project_root = root or repo_root()
    server_path = project_root / MCP_SERVER
    if not server_path.is_file():
        return []

    tree = ast.parse(server_path.read_text(encoding="utf-8"), filename=str(server_path))
    names = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        and any(_is_mcp_tool_decorator(decorator) for decorator in node.decorator_list)
    }
    return _sort_strings(names)


def discover_registry_tools() -> list[str]:
    """Return tool names from ctf_core.registry without touching Docker."""
    from .registry import TOOL_REGISTRY

    return _sort_strings(entry.name for entry in TOOL_REGISTRY)


def discover_skill_docs(root: Path | None = None) -> list[str]:
    project_root = root or repo_root()
    skills_dir = project_root / "skills"
    if not skills_dir.is_dir():
        return []
    return _existing_relative_files(project_root, skills_dir.rglob("*.md"))


def discover_dockerfiles(root: Path | None = None) -> list[str]:
    project_root = root or repo_root()
    paths: list[Path] = []
    docker_dir = project_root / "docker"
    if docker_dir.is_dir():
        paths.extend(docker_dir.rglob("Dockerfile"))
    paths.extend(project_root / name for name in ROOT_DOCKERFILES)
    return _existing_relative_files(project_root, paths)


def discover_schemas(root: Path | None = None) -> list[str]:
    project_root = root or repo_root()
    schema_dir = project_root / "schema"
    if not schema_dir.is_dir():
        return []
    return _existing_relative_files(project_root, schema_dir.glob("*"))


def discover_launchers(root: Path | None = None) -> list[str]:
    project_root = root or repo_root()
    paths = list(project_root.glob("*.bat"))
    paths.extend(project_root / name for name in MAIN_MCP_CONFIGS)
    return _existing_relative_files(project_root, paths)


def discover_docs_toolkit_assets(root: Path | None = None) -> list[str]:
    project_root = root or repo_root()
    docs_dir = project_root / "docs" / "toolkit"
    if not docs_dir.is_dir():
        return []
    return _existing_relative_files(project_root, docs_dir.rglob("*"))


def build_manifest(root: Path | None = None) -> dict[str, Any]:
    """Build the full preservation manifest with stable counts and ordering."""
    project_root = root or repo_root()
    inventory = {
        "mcp_tools": discover_mcp_tools(project_root),
        "registry_tools": discover_registry_tools(),
        "skill_docs": discover_skill_docs(project_root),
        "dockerfiles": discover_dockerfiles(project_root),
        "schemas": discover_schemas(project_root),
        "launchers": discover_launchers(project_root),
        "docs_toolkit_assets": discover_docs_toolkit_assets(project_root),
    }
    return {
        "schema_version": 1,
        "generated_by": "ctf_core.manifest.build_manifest",
        "sources": {
            "mcp_tools": MCP_SERVER.as_posix(),
            "registry_tools": "src/ctf_core/registry.py",
            "skill_docs": "skills/**/*.md",
            "dockerfiles": "docker/**/Dockerfile and Dockerfile.ctf-tools",
            "schemas": "schema/*",
            "launchers": "*.bat, mcp.json, mcp-windows.json",
            "docs_toolkit_assets": "docs/toolkit/**/*",
        },
        "counts": {name: len(values) for name, values in inventory.items()},
        "inventory": inventory,
    }


def dumps_manifest(manifest: dict[str, Any]) -> str:
    """Serialize a manifest deterministically."""
    return json.dumps(manifest, indent=2, sort_keys=True) + "\n"


def write_manifest(root: Path | None = None, output_path: Path | None = None) -> Path:
    """Generate and write toolkit_manifest.json."""
    project_root = root or repo_root()
    destination = output_path or project_root / "toolkit_manifest.json"
    destination.write_text(
        dumps_manifest(build_manifest(project_root)),
        encoding="utf-8",
        newline="\n",
    )
    return destination
