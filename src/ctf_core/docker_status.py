"""Docker image inventory, local status, and binary probe planning helpers."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence


PROJECT_ROOT = Path(__file__).resolve().parents[2]
INSPECT_TIMEOUT_SECONDS = 10
PROBE_TIMEOUT_SECONDS = 30
LAZY_IMAGES = frozenset({"ctftoolkit/ctf-mobile", "ctftoolkit/ctf-sage"})


@dataclass(frozen=True, slots=True)
class DockerImageDefinition:
    """Static image metadata discovered from registry entries and Docker files."""

    image: str
    dockerfile: str | None = None
    expected_binaries: tuple[str, ...] = ()
    service: str | None = None
    source: tuple[str, ...] = ()
    base_image: str | None = None
    base_digest: str | None = None
    lazy: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class DockerImageStatus:
    """Local status for one expected Docker image."""

    image: str
    dockerfile: str | None
    expected_binaries: tuple[str, ...]
    exists: bool | None
    missing: bool | None
    stale: bool | None
    stale_reason: str | None = None
    image_id: str | None = None
    tags: tuple[str, ...] = ()
    created: str | None = None
    repo_digests: tuple[str, ...] = ()
    digest: str | None = None
    service: str | None = None
    lazy: bool = False
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class DockerStatusMatrix:
    """Full Docker status matrix plus non-fatal diagnostics."""

    images: tuple[DockerImageStatus, ...]
    warnings: tuple[str, ...] = ()
    docker_available: bool = False
    docker_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def missing_images(self) -> tuple[DockerImageStatus, ...]:
        return tuple(status for status in self.images if status.missing)

    @property
    def stale_images(self) -> tuple[DockerImageStatus, ...]:
        return tuple(status for status in self.images if status.stale)


@dataclass(frozen=True, slots=True)
class BinaryProbe:
    """Planned or executed health probe for one binary inside one image."""

    image: str
    binary: str
    command: tuple[str, ...]
    status: str = "planned"
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    warnings: tuple[str, ...] = ()

    @property
    def ok(self) -> bool | None:
        if self.status == "planned":
            return None
        if self.returncode is None:
            return None
        return self.returncode == 0

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["ok"] = self.ok
        return data


def repo_root() -> Path:
    return PROJECT_ROOT


def _which(command: str) -> str | None:
    return shutil.which(command)


def _run_command(args: Sequence[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def expected_binaries_by_image() -> dict[str, tuple[str, ...]]:
    """Return expected registry binaries grouped by Docker image."""

    from .registry import TOOL_REGISTRY

    grouped: dict[str, set[str]] = {}
    for entry in TOOL_REGISTRY:
        if entry.image:
            grouped.setdefault(entry.image, set()).add(entry.binary)
    return {
        image: tuple(sorted(binaries, key=str.casefold))
        for image, binaries in sorted(grouped.items(), key=lambda item: item[0])
    }


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _normalize_rel(path: str) -> str:
    return path.strip().strip("'\"").replace("\\", "/")


def _parse_compose_images(root: Path) -> dict[str, dict[str, str]]:
    """Parse the repository's simple compose file without adding YAML dependency."""

    compose = root / "docker-compose.yml"
    if not compose.is_file():
        return {}

    current_service: str | None = None
    services: dict[str, dict[str, str]] = {}
    for raw_line in _read_text(compose).splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        service_match = re.match(r"^  ([A-Za-z0-9_.-]+):\s*$", raw_line)
        if service_match:
            current_service = service_match.group(1)
            services.setdefault(current_service, {})
            continue
        if current_service is None:
            continue
        image_match = re.match(r"^\s+image:\s*(.+?)\s*$", raw_line)
        if image_match:
            services[current_service]["image"] = image_match.group(1).strip().strip("'\"")
            continue
        dockerfile_match = re.match(r"^\s+dockerfile:\s*(.+?)\s*$", raw_line)
        if dockerfile_match:
            services[current_service]["dockerfile"] = _normalize_rel(dockerfile_match.group(1))

    by_image: dict[str, dict[str, str]] = {}
    for service, values in services.items():
        image = values.get("image")
        if image:
            by_image[image] = {
                "service": service,
                "dockerfile": values.get("dockerfile", ""),
            }
    return by_image


def _dockerfile_image_fallbacks(root: Path) -> dict[str, str]:
    docker_dir = root / "docker"
    if not docker_dir.is_dir():
        return {}
    fallbacks: dict[str, str] = {}
    for dockerfile in sorted(docker_dir.glob("*/Dockerfile")):
        image = f"ctftoolkit/{dockerfile.parent.name}"
        fallbacks[image] = dockerfile.relative_to(root).as_posix()
    return fallbacks


def _parse_base_image(dockerfile: Path) -> tuple[str | None, str | None]:
    if not dockerfile.is_file():
        return None, None
    for raw_line in _read_text(dockerfile).splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if not line.upper().startswith("FROM "):
            continue
        base = line.split(None, 1)[1].split(" AS ", 1)[0].split(" as ", 1)[0].strip()
        digest = base.split("@", 1)[1] if "@" in base else None
        return base, digest
    return None, None


def discover_image_definitions(project_root: Path | None = None) -> tuple[DockerImageDefinition, ...]:
    """Discover known toolkit images from registry mappings, compose, and Dockerfiles."""

    root = (project_root or PROJECT_ROOT).resolve()
    binaries = expected_binaries_by_image()
    compose = _parse_compose_images(root)
    dockerfile_fallbacks = _dockerfile_image_fallbacks(root)
    images = set(binaries) | set(compose) | set(dockerfile_fallbacks)

    definitions: list[DockerImageDefinition] = []
    for image in sorted(images, key=str.casefold):
        sources: list[str] = []
        if image in binaries:
            sources.append("registry")
        if image in compose:
            sources.append("compose")
        if image in dockerfile_fallbacks:
            sources.append("dockerfile")

        dockerfile_rel = compose.get(image, {}).get("dockerfile") or dockerfile_fallbacks.get(image)
        dockerfile_path = root / dockerfile_rel if dockerfile_rel else None
        base_image, base_digest = _parse_base_image(dockerfile_path) if dockerfile_path else (None, None)
        definitions.append(
            DockerImageDefinition(
                image=image,
                dockerfile=dockerfile_rel or None,
                expected_binaries=binaries.get(image, ()),
                service=compose.get(image, {}).get("service"),
                source=tuple(sources),
                base_image=base_image,
                base_digest=base_digest,
                lazy=image in LAZY_IMAGES,
            )
        )
    return tuple(definitions)


def _parse_docker_created(value: str | None) -> float | None:
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    if "." in text:
        prefix, suffix = text.split(".", 1)
        tz = ""
        if "+" in suffix:
            fraction, tz_part = suffix.split("+", 1)
            tz = "+" + tz_part
        elif "-" in suffix:
            fraction, tz_part = suffix.split("-", 1)
            tz = "-" + tz_part
        else:
            fraction = suffix
        text = f"{prefix}.{fraction[:6]}{tz}"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _digestish(image_info: Mapping[str, Any]) -> str | None:
    repo_digests = image_info.get("RepoDigests") or ()
    if repo_digests:
        first = str(repo_digests[0])
        return first.split("@", 1)[1] if "@" in first else first
    image_id = str(image_info.get("Id") or "")
    if image_id.startswith("sha256:"):
        return image_id[:19]
    return image_id or None


def _inspect_image(docker: str, image: str) -> tuple[Mapping[str, Any] | None, str | None, bool]:
    try:
        result = _run_command(
            [docker, "image", "inspect", image],
            timeout=INSPECT_TIMEOUT_SECONDS,
        )
    except Exception as exc:  # noqa: BLE001 - status helper must not crash on Docker failures.
        return None, f"{image}: docker image inspect failed: {exc}", False

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        missing_markers = ("No such image", "No such object", "not found")
        if any(marker.casefold() in detail.casefold() for marker in missing_markers):
            return None, None, True
        return None, f"{image}: docker image inspect failed: {detail or 'nonzero exit'}", False

    try:
        payload = json.loads(result.stdout or "[]")
    except json.JSONDecodeError as exc:
        return None, f"{image}: docker image inspect returned invalid JSON: {exc}", False
    if not isinstance(payload, list) or not payload or not isinstance(payload[0], Mapping):
        return None, f"{image}: docker image inspect returned no image metadata", False
    return payload[0], None, False


def _docker_available(docker: str) -> tuple[bool, str | None]:
    try:
        result = _run_command(
            [docker, "info", "--format", "{{.ServerVersion}}"],
            timeout=INSPECT_TIMEOUT_SECONDS,
        )
    except Exception as exc:  # noqa: BLE001
        return False, f"docker info failed: {exc}"
    if result.returncode == 0:
        return True, None
    detail = (result.stderr or result.stdout or "").strip()
    return False, f"docker is installed but not reachable: {detail or 'docker info failed'}"


def _stale_status(root: Path, definition: DockerImageDefinition, created: str | None) -> tuple[bool | None, str | None]:
    if not definition.dockerfile:
        return None, None
    dockerfile = root / definition.dockerfile
    if not dockerfile.is_file():
        return None, f"Dockerfile is missing: {definition.dockerfile}"
    created_ts = _parse_docker_created(created)
    if created_ts is None:
        return None, None
    dockerfile_ts = dockerfile.stat().st_mtime
    if dockerfile_ts > created_ts + 1:
        return True, f"{definition.dockerfile} changed after local image was created"
    return False, None


def build_status_matrix(
    project_root: Path | None = None,
    *,
    inspect_local: bool = True,
) -> DockerStatusMatrix:
    """Build a status matrix; Docker absence is reported as a warning."""

    root = (project_root or PROJECT_ROOT).resolve()
    warnings: list[str] = []
    definitions = discover_image_definitions(root)

    docker = _which("docker") if inspect_local else None
    docker_ready = False
    if inspect_local:
        if docker is None:
            warnings.append("docker executable was not found; local image state is unknown")
        else:
            docker_ready, docker_warning = _docker_available(docker)
            if docker_warning:
                warnings.append(docker_warning)

    statuses: list[DockerImageStatus] = []
    for definition in definitions:
        info: Mapping[str, Any] | None = None
        inspect_warning: str | None = None
        inspect_missing = False
        if docker_ready and docker is not None:
            info, inspect_warning, inspect_missing = _inspect_image(docker, definition.image)

        if info is None and inspect_missing:
            statuses.append(
                DockerImageStatus(
                    image=definition.image,
                    dockerfile=definition.dockerfile,
                    expected_binaries=definition.expected_binaries,
                    exists=False,
                    missing=True,
                    stale=None,
                    service=definition.service,
                    lazy=definition.lazy,
                    warnings=tuple(filter(None, (inspect_warning,))),
                )
            )
            continue

        if info is None:
            statuses.append(
                DockerImageStatus(
                    image=definition.image,
                    dockerfile=definition.dockerfile,
                    expected_binaries=definition.expected_binaries,
                    exists=None,
                    missing=None,
                    stale=None,
                    service=definition.service,
                    lazy=definition.lazy,
                    warnings=tuple(filter(None, (inspect_warning,))),
                )
            )
            continue

        created = str(info.get("Created") or "")
        stale, stale_reason = _stale_status(root, definition, created)
        image_warnings = tuple(filter(None, (inspect_warning, stale_reason if stale is None else None)))
        statuses.append(
            DockerImageStatus(
                image=definition.image,
                dockerfile=definition.dockerfile,
                expected_binaries=definition.expected_binaries,
                exists=True,
                missing=False,
                stale=stale,
                stale_reason=stale_reason if stale else None,
                image_id=str(info.get("Id") or "") or None,
                tags=tuple(str(tag) for tag in (info.get("RepoTags") or ())),
                created=created or None,
                repo_digests=tuple(str(digest) for digest in (info.get("RepoDigests") or ())),
                digest=_digestish(info),
                service=definition.service,
                lazy=definition.lazy,
                warnings=image_warnings,
            )
        )

    return DockerStatusMatrix(
        images=tuple(statuses),
        warnings=tuple(warnings),
        docker_available=docker_ready,
        docker_path=docker,
    )


def image_status_matrix(
    project_root: Path | None = None,
    *,
    inspect_local: bool = True,
) -> list[dict[str, Any]]:
    """Compatibility wrapper returning only image rows as dictionaries."""

    return [status.to_dict() for status in build_status_matrix(project_root, inspect_local=inspect_local).images]


def _probe_command(image: str, binary: str) -> tuple[str, ...]:
    return ("docker", "run", "--rm", image, "which", binary)


def expected_binary_probe_commands(
    project_root: Path | None = None,
    *,
    image: str | None = None,
) -> tuple[BinaryProbe, ...]:
    """Generate per-binary Docker probe commands without running Docker."""

    probes: list[BinaryProbe] = []
    for definition in discover_image_definitions(project_root):
        if image is not None and definition.image != image:
            continue
        for binary in definition.expected_binaries:
            probes.append(
                BinaryProbe(
                    image=definition.image,
                    binary=binary,
                    command=_probe_command(definition.image, binary),
                )
            )
    return tuple(probes)


def probe_commands_by_image(
    project_root: Path | None = None,
) -> dict[str, tuple[tuple[str, ...], ...]]:
    grouped: dict[str, list[tuple[str, ...]]] = {}
    for probe in expected_binary_probe_commands(project_root):
        grouped.setdefault(probe.image, []).append(probe.command)
    return {image: tuple(commands) for image, commands in grouped.items()}


def run_binary_probes(
    project_root: Path | None = None,
    *,
    image: str | None = None,
    run: bool = False,
    timeout: int = PROBE_TIMEOUT_SECONDS,
) -> tuple[BinaryProbe, ...]:
    """Return planned probes by default; execute them only when run=True."""

    probes = expected_binary_probe_commands(project_root, image=image)
    if not run:
        return probes

    docker = _which("docker")
    if docker is None:
        warning = "docker executable was not found; probes were not run"
        return tuple(
            BinaryProbe(
                image=probe.image,
                binary=probe.binary,
                command=probe.command,
                status="warning",
                warnings=(warning,),
            )
            for probe in probes
        )

    results: list[BinaryProbe] = []
    for probe in probes:
        command = (docker, *probe.command[1:])
        try:
            completed = _run_command(command, timeout=timeout)
        except Exception as exc:  # noqa: BLE001 - per-probe diagnostics, not crash.
            results.append(
                BinaryProbe(
                    image=probe.image,
                    binary=probe.binary,
                    command=command,
                    status="error",
                    stderr=str(exc),
                    warnings=(f"probe failed to execute: {exc}",),
                )
            )
            continue
        results.append(
            BinaryProbe(
                image=probe.image,
                binary=probe.binary,
                command=command,
                status="pass" if completed.returncode == 0 else "fail",
                returncode=completed.returncode,
                stdout=completed.stdout or "",
                stderr=completed.stderr or "",
            )
        )
    return tuple(results)


get_docker_status_matrix = build_status_matrix
generate_binary_probe_commands = expected_binary_probe_commands
generate_health_probe_commands = expected_binary_probe_commands
run_health_probes = run_binary_probes


__all__ = [
    "BinaryProbe",
    "DockerImageDefinition",
    "DockerImageStatus",
    "DockerStatusMatrix",
    "build_status_matrix",
    "discover_image_definitions",
    "expected_binaries_by_image",
    "expected_binary_probe_commands",
    "generate_binary_probe_commands",
    "generate_health_probe_commands",
    "get_docker_status_matrix",
    "image_status_matrix",
    "probe_commands_by_image",
    "repo_root",
    "run_binary_probes",
    "run_health_probes",
]
