from __future__ import annotations

from pathlib import Path
from typing import Any

from ctf_harness_app.ctfd import CTFdClient, Challenge
from ctf_harness_app.util import HarnessError

from .base import AuthError, ChallengeSummary, PlatformConnector, SubmitResult


class CTFdConnector(PlatformConnector):
    platform_id = "ctfd"
    display_name = "CTFd"

    def __init__(self) -> None:
        self._client: CTFdClient | None = None

    def authenticate(self, url: str, username: str, password: str) -> None:
        """Create a CTFdClient and verify credentials by listing challenges.

        The *username* parameter is ignored — CTFd uses token-based auth.
        *password* should be the CTFd API token.
        """
        client = CTFdClient(url, token=password)
        try:
            client.list_challenges()
        except HarnessError as exc:
            raise AuthError(str(exc)) from exc
        self._client = client

    def list_challenges(self) -> list[ChallengeSummary]:
        assert self._client is not None, "Call authenticate() first"
        raw_list = self._client.list_challenges()
        return [
            ChallengeSummary(
                id=int(c["id"]),
                name=str(c.get("name") or f"challenge-{c['id']}"),
                category=str(c.get("category") or ""),
                value=c.get("value") if isinstance(c.get("value"), int) else None,
                solved=bool(c.get("solved_by_me")),
            )
            for c in raw_list
            if isinstance(c, dict) and "id" in c
        ]

    def get_challenge(self, challenge_id: str | int) -> Challenge:
        assert self._client is not None, "Call authenticate() first"
        return self._client.get_challenge(int(challenge_id))

    def download_files(self, challenge: Any, dest: Path) -> list[Path]:
        assert self._client is not None, "Call authenticate() first"
        dest.mkdir(parents=True, exist_ok=True)
        paths: list[Path] = []
        for file_url in getattr(challenge, "files", []):
            paths.append(self._client.download_file(file_url, dest))
        return paths

    def solved_ids(self) -> set[str | int]:
        assert self._client is not None, "Call authenticate() first"
        return self._client.solved_challenge_ids()

    def submit_flag(self, challenge_id: str | int, flag: str) -> SubmitResult:
        # CTFd client has no submit API yet — instruct user to use the browser.
        return SubmitResult(False, "Submit via browser")
