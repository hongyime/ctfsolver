"""Offline target scope storage and checks."""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit


SCOPE_STATE_VERSION = 1


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def scope_state_path(workspace: str | Path) -> Path:
    return Path(workspace) / "state" / "scope.json"


def _to_idna(host: str) -> str:
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def _normalize_host(host: str) -> str:
    normalized = host.strip().strip("[]").rstrip(".").lower()
    if normalized.startswith("*."):
        return "*." + _to_idna(normalized[2:])
    return _to_idna(normalized)


def _hostname_from_target(raw: str) -> str:
    if "://" in raw:
        parsed = urlsplit(raw)
        return parsed.hostname or raw

    stripped = raw.strip()
    bracketless = stripped.strip("[]")
    try:
        return ipaddress.ip_address(bracketless).compressed
    except ValueError:
        pass

    if stripped.startswith("[") or "/" in stripped or "?" in stripped or "#" in stripped:
        parsed = urlsplit("//" + stripped)
        return parsed.hostname or stripped

    if stripped.count(":") == 1:
        host, port = stripped.rsplit(":", 1)
        if host and port.isdigit():
            return host

    return stripped


def normalize_target(target: str | Path | None) -> str:
    """Normalize a domain, URL, IP address, or CIDR without network lookups."""
    if target is None:
        return ""
    raw = str(target).strip()
    if not raw:
        return ""

    if "://" not in raw:
        try:
            if "/" in raw:
                return ipaddress.ip_network(raw, strict=False).with_prefixlen
            return ipaddress.ip_address(raw.strip("[]")).compressed
        except ValueError:
            pass

    host = _hostname_from_target(raw)
    normalized = _normalize_host(host)
    try:
        return ipaddress.ip_address(normalized).compressed
    except ValueError:
        return normalized


def normalize_targets(targets: Iterable[str | Path] | None) -> list[str]:
    seen: set[str] = set()
    normalized_targets: list[str] = []
    for target in targets or []:
        normalized = normalize_target(target)
        if normalized and normalized not in seen:
            normalized_targets.append(normalized)
            seen.add(normalized)
    return normalized_targets


def load_scope(workspace: str | Path) -> dict[str, Any]:
    path = scope_state_path(workspace)
    if not path.exists():
        return {"version": SCOPE_STATE_VERSION, "allowed_targets": [], "metadata": {}}
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    data["allowed_targets"] = normalize_targets(data.get("allowed_targets", []))
    data.setdefault("version", SCOPE_STATE_VERSION)
    data.setdefault("metadata", {})
    return data


def save_scope(
    workspace: str | Path,
    allowed_targets: Iterable[str | Path],
    *,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    state = {
        "version": SCOPE_STATE_VERSION,
        "updated_at": utc_timestamp(),
        "allowed_targets": normalize_targets(allowed_targets),
        "metadata": dict(metadata or {}),
    }
    path = scope_state_path(workspace)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return state


def load_allowed_targets(workspace: str | Path) -> list[str]:
    return list(load_scope(workspace).get("allowed_targets", []))


def save_allowed_targets(
    workspace: str | Path,
    allowed_targets: Iterable[str | Path],
    *,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return save_scope(workspace, allowed_targets, metadata=metadata)


def _as_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _target_matches_allowed(target: str, allowed: str) -> bool:
    target_ip = _as_ip(target)
    try:
        network = ipaddress.ip_network(allowed, strict=False)
        return target_ip is not None and target_ip in network
    except ValueError:
        pass

    allowed_ip = _as_ip(allowed)
    if allowed_ip is not None:
        return target_ip == allowed_ip

    if allowed.startswith("*."):
        base = allowed[2:]
        return target.endswith("." + base)

    return target == allowed or target.endswith("." + allowed)


def is_target_allowed(
    target: str | Path | None,
    *,
    allowed_targets: Iterable[str | Path] | None = None,
    workspace: str | Path | None = None,
) -> bool:
    """Return True when target falls within the saved or provided scope."""
    normalized_target = normalize_target(target)
    if not normalized_target:
        return False

    if allowed_targets is None:
        if workspace is None:
            return False
        allowed = load_allowed_targets(workspace)
    else:
        allowed = normalize_targets(allowed_targets)

    return any(_target_matches_allowed(normalized_target, item) for item in allowed)
