"""Public API for the platforms package."""

from ctf_harness_app.platforms.base import (
    AuthError,
    ChallengeSummary,
    PlatformConnector,
    SubmitResult,
)
from ctf_harness_app.platforms.registry import get_connector, list_platforms

__all__ = [
    "AuthError",
    "ChallengeSummary",
    "PlatformConnector",
    "SubmitResult",
    "get_connector",
    "list_platforms",
]