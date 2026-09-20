from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

from .base import AuthError, ChallengeSummary, PlatformConnector, SubmitResult


@dataclasses.dataclass
class ManualChallenge:
    id: str | int
    name: str
    category: str
    value: int | None
    description: str
    connection_info: str
    files: list[str]
    tags: list[str]
    hints: list[Any]
    raw: dict[str, Any]


class ManualConnector(PlatformConnector):
    platform_id = "manual"
    display_name = "Manual"

    def __init__(self) -> None:
        self._challenges: list[dict] = []

    def authenticate(self, url: str, username: str, password: str) -> None:
        """No-op — manual mode requires no authentication."""

    def add_challenge(self, data: dict) -> None:
        """Append a challenge dict to the internal list (for programmatic use)."""
        self._challenges.append(data)

    def list_challenges(self) -> list[ChallengeSummary]:
        return [
            ChallengeSummary(
                id=c.get("id", ""),
                name=str(c.get("name") or ""),
                category=str(c.get("category") or ""),
                value=c.get("value") if isinstance(c.get("value"), int) else None,
                solved=bool(c.get("solved", False)),
            )
            for c in self._challenges
        ]

    def get_challenge(self, challenge_id: str | int) -> ManualChallenge:
        target = str(challenge_id)
        for c in self._challenges:
            if str(c.get("id")) == target:
                return ManualChallenge(
                    id=c.get("id", ""),
                    name=str(c.get("name") or ""),
                    category=str(c.get("category") or ""),
                    value=c.get("value") if isinstance(c.get("value"), int) else None,
                    description=str(c.get("description") or ""),
                    connection_info=str(c.get("connection_info") or ""),
                    files=list(c.get("files") or []),
                    tags=[str(t) for t in (c.get("tags") or [])],
                    hints=list(c.get("hints") or []),
                    raw=c,
                )
        raise KeyError(f"Manual challenge not found: {challenge_id!r}")

    def download_files(self, challenge: Any, dest: Path) -> list[Path]:
        # Files are already on disk in manual mode.
        return []

    def solved_ids(self) -> set[str | int]:
        return set()

    def submit_flag(self, challenge_id: str | int, flag: str) -> SubmitResult:
        return SubmitResult(False, "Manual mode: check flag locally")
