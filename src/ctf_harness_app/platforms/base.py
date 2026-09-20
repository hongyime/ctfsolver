from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar, NamedTuple


class AuthError(Exception):
    """Raised by PlatformConnector.authenticate() on bad credentials."""


class SubmitResult(NamedTuple):
    accepted: bool
    message: str


@dataclass(frozen=True)
class ChallengeSummary:
    id: str | int
    name: str
    category: str
    value: int | None
    solved: bool


class PlatformConnector(ABC):
    platform_id: ClassVar[str]
    display_name: ClassVar[str]

    @abstractmethod
    def authenticate(self, url: str, username: str, password: str) -> None:
        """Authenticate against the platform. Raise AuthError on failure."""

    @abstractmethod
    def list_challenges(self) -> list[ChallengeSummary]: ...

    @abstractmethod
    def get_challenge(self, challenge_id: str | int) -> Any:
        """Return a Challenge-like object with id/name/category/value/description/files/tags/hints/connection_info."""

    @abstractmethod
    def download_files(self, challenge: Any, dest: Path) -> list[Path]: ...

    @abstractmethod
    def solved_ids(self) -> set[str | int]: ...

    @abstractmethod
    def submit_flag(self, challenge_id: str | int, flag: str) -> SubmitResult: ...
