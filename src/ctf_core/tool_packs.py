"""Optional tool-pack metadata.

Tool packs describe heavier or riskier capability bundles that can be wired
into registry and image coverage later. This module is metadata-only and does
not install packages, build images, or execute tools.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
import re
from typing import Any


_VALID_RISKS = frozenset({"low", "medium", "high"})
_PACK_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]*$")


@dataclass(frozen=True)
class ToolPack:
    pack_id: str
    name: str
    category: str
    tools: tuple[str, ...]
    docker_image_hint: str
    risk: str
    install_notes: tuple[str, ...]
    build_notes: tuple[str, ...]
    enabled_by_default: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "pack_id": self.pack_id,
            "name": self.name,
            "category": self.category,
            "tools": list(self.tools),
            "docker_image_hint": self.docker_image_hint,
            "risk": self.risk,
            "install_notes": list(self.install_notes),
            "build_notes": list(self.build_notes),
            "enabled_by_default": self.enabled_by_default,
        }


TOOL_PACKS: tuple[ToolPack, ...] = (
    ToolPack(
        pack_id="mobile",
        name="Mobile Reverse Engineering",
        category="mobile",
        tools=(
            "apktool",
            "jadx",
            "dex2jar",
            "apksigner",
            "adb",
            "frida-tools",
            "objection",
            "MobSF",
        ),
        docker_image_hint="ctfsolver/ctf-mobile:optional",
        risk="medium",
        install_notes=(
            "Install only when Android or iOS challenge artifacts are expected.",
            "Keep device bridge tools opt-in; do not expose host devices by default.",
        ),
        build_notes=(
            "Use a separate optional image with Android tooling and Java runtime.",
            "Add registry entries and binary probes before enabling MCP wrappers.",
        ),
        enabled_by_default=False,
    ),
    ToolPack(
        pack_id="cloud",
        name="Cloud and Container Audit",
        category="cloud",
        tools=(
            "prowler",
            "scout-suite",
            "cloudsplaining",
            "trivy",
            "kubectl",
            "helm",
            "aws",
            "az",
            "gcloud",
        ),
        docker_image_hint="ctfsolver/ctf-cloud:optional",
        risk="high",
        install_notes=(
            "Install only for cloud-themed CTF tasks or local lab credentials.",
            "Credentials must be challenge-scoped and supplied at runtime.",
        ),
        build_notes=(
            "Split cloud CLIs from default images to avoid large base layers.",
            "Add scope checks for account IDs, projects, clusters, and regions.",
        ),
        enabled_by_default=False,
    ),
    ToolPack(
        pack_id="malware",
        name="Malware Triage",
        category="malware",
        tools=(
            "yara",
            "capa",
            "floss",
            "pefile",
            "oletools",
            "lief",
            "clamav",
            "radare2",
        ),
        docker_image_hint="ctfsolver/ctf-malware:optional",
        risk="high",
        install_notes=(
            "Install only for offline malware-style reverse engineering tasks.",
            "Samples must stay inside the workspace and never be auto-executed.",
        ),
        build_notes=(
            "Build as an offline analysis image with no default network access.",
            "Add probes for YARA rules, capa rules, and signature database presence.",
        ),
        enabled_by_default=False,
    ),
    ToolPack(
        pack_id="gpu-cracking",
        name="GPU Cracking",
        category="crypto",
        tools=(
            "hashcat",
            "john",
            "hashid",
            "hcxtools",
            "nvidia-smi",
            "clinfo",
        ),
        docker_image_hint="ctfsolver/ctf-gpu-cracking:optional",
        risk="high",
        install_notes=(
            "Install only on hosts where GPU cracking is allowed and expected.",
            "Require explicit runtime configuration for GPU device access.",
        ),
        build_notes=(
            "Keep GPU runtime dependencies out of default CPU-only images.",
            "Add probes for OpenCL/CUDA visibility before enabling cracking flows.",
        ),
        enabled_by_default=False,
    ),
    ToolPack(
        pack_id="osint",
        name="OSINT Expansion",
        category="osint",
        tools=(
            "theHarvester",
            "spiderfoot",
            "amass",
            "assetfinder",
            "sherlock",
            "maigret",
            "holehe",
            "ghunt",
        ),
        docker_image_hint="ctfsolver/ctf-osint:optional",
        risk="medium",
        install_notes=(
            "Install only for OSINT challenges where external lookups are allowed.",
            "Document required API keys and rate limits per provider.",
        ),
        build_notes=(
            "Separate passive OSINT from active enumeration wrappers.",
            "Add provider-specific network scope and secret-redaction tests.",
        ),
        enabled_by_default=False,
    ),
)


_PACK_BY_ID = {pack.pack_id: pack for pack in TOOL_PACKS}


def get_tool_pack(pack_id: str) -> dict[str, Any]:
    """Return one optional tool pack by id as a plain dictionary."""

    return _PACK_BY_ID[pack_id].to_dict()


def list_tool_packs() -> list[dict[str, Any]]:
    """Return optional tool packs in stable order."""

    return [pack.to_dict() for pack in TOOL_PACKS]


def validate_tool_packs(
    packs: Iterable[ToolPack] = TOOL_PACKS,
) -> list[str]:
    """Return metadata validation errors for optional tool packs."""

    errors: list[str] = []
    seen_ids: set[str] = set()
    for pack in packs:
        prefix = f"pack {pack.pack_id!r}"
        if not pack.pack_id:
            errors.append("pack id is required")
        elif not _PACK_ID_PATTERN.match(pack.pack_id):
            errors.append(f"{prefix}: pack_id must be lowercase kebab-case")

        if pack.pack_id in seen_ids:
            errors.append(f"{prefix}: duplicate pack id")
        seen_ids.add(pack.pack_id)

        if not pack.name or not pack.category:
            errors.append(f"{prefix}: name and category are required")
        if not pack.tools:
            errors.append(f"{prefix}: at least one tool is required")
        if len(set(pack.tools)) != len(pack.tools):
            errors.append(f"{prefix}: tools must be unique")
        if any(not str(tool).strip() for tool in pack.tools):
            errors.append(f"{prefix}: tool names must be non-empty")
        if not pack.docker_image_hint:
            errors.append(f"{prefix}: docker_image_hint is required")
        if pack.risk not in _VALID_RISKS:
            errors.append(f"{prefix}: risk must be one of {sorted(_VALID_RISKS)}")
        if not pack.install_notes:
            errors.append(f"{prefix}: install_notes are required")
        if not pack.build_notes:
            errors.append(f"{prefix}: build_notes are required")
        if pack.risk in {"medium", "high"} and pack.enabled_by_default:
            errors.append(f"{prefix}: medium/high risk packs must be opt-in")
    return errors


__all__ = [
    "TOOL_PACKS",
    "ToolPack",
    "get_tool_pack",
    "list_tool_packs",
    "validate_tool_packs",
]
