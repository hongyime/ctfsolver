from __future__ import annotations

from .base import PlatformConnector
from .ctfd import CTFdConnector
from .manual import ManualConnector
from .rctf import RCTFConnector

_REGISTRY: dict[str, type[PlatformConnector]] = {
    "ctfd": CTFdConnector,
    "rctf": RCTFConnector,
    "manual": ManualConnector,
}


def get_connector(platform_id: str) -> PlatformConnector:
    """Return a new instance of the connector for the given platform_id."""
    cls = _REGISTRY.get(platform_id)
    if cls is None:
        raise ValueError(f"Unknown platform: {platform_id!r}. Known: {sorted(_REGISTRY)}")
    return cls()


def list_platforms() -> list[dict]:
    """Return [{id, display_name}, ...] for all registered platforms."""
    return [{"id": pid, "display_name": cls.display_name} for pid, cls in _REGISTRY.items()]
