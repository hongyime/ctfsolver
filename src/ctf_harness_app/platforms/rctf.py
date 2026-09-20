from __future__ import annotations

import dataclasses
import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .base import AuthError, ChallengeSummary, PlatformConnector, SubmitResult


@dataclasses.dataclass(frozen=True)
class RCTFChallenge:
    id: str
    name: str
    category: str
    value: int | None
    description: str
    connection_info: str
    files: list[str]
    tags: list[str]
    hints: list[Any]
    raw: dict[str, Any]


class RCTFConnector(PlatformConnector):
    platform_id = "rctf"
    display_name = "rCTF"

    def __init__(self) -> None:
        self._base_url: str = ""
        self._auth_token: str = ""

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: dict | None = None,
        authenticated: bool = True,
        timeout: int = 15,
    ) -> dict[str, Any]:
        url = f"{self._base_url}{path}"
        data: bytes | None = None
        headers: dict[str, str] = {"Content-Type": "application/json", "Accept": "application/json"}
        if authenticated and self._auth_token:
            headers["Authorization"] = f"Bearer {self._auth_token}"
        if body is not None:
            data = json.dumps(body).encode()
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            raw_body = exc.read().decode("utf-8", errors="replace")
            try:
                return json.loads(raw_body)
            except json.JSONDecodeError:
                raise AuthError(f"HTTP {exc.code}: {raw_body[:200]}") from exc

    def _download_unauthenticated(self, url: str, dest: Path) -> Path:
        req = urllib.request.Request(url, headers={"User-Agent": "ctfsolver/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            filename = url.rstrip("/").rsplit("/", 1)[-1] or "attachment.bin"
            out_path = dest / filename
            out_path.write_bytes(resp.read())
            return out_path

    # ------------------------------------------------------------------
    # PlatformConnector interface
    # ------------------------------------------------------------------

    def authenticate(self, url: str, username: str, password: str) -> None:
        """Authenticate using a rCTF team token (*password*). *username* is unused."""
        self._base_url = url.rstrip("/")
        self._auth_token = ""
        resp = self._request(
            "POST",
            "/api/v1/auth/login",
            body={"teamToken": password},
            authenticated=False,
        )
        if resp.get("kind") == "goodUserToken":
            data = resp.get("data") or {}
            self._auth_token = str(data.get("authToken", ""))
        else:
            raise AuthError(resp.get("message", "Authentication failed"))

    def list_challenges(self) -> list[ChallengeSummary]:
        resp = self._request("GET", "/api/v1/challs")
        items = resp.get("data") or []
        if not isinstance(items, list):
            return []
        return [
            ChallengeSummary(
                id=str(c["id"]),
                name=str(c.get("name") or ""),
                category=str(c.get("category") or ""),
                value=c.get("points") if isinstance(c.get("points"), int) else None,
                solved=False,
            )
            for c in items
            if isinstance(c, dict) and "id" in c
        ]

    def get_challenge(self, challenge_id: str | int) -> RCTFChallenge:
        resp = self._request("GET", "/api/v1/challs")
        items = resp.get("data") or []
        target_id = str(challenge_id)
        for c in items:
            if not isinstance(c, dict):
                continue
            if str(c.get("id")) == target_id:
                files = [str(f) for f in (c.get("files") or []) if f]
                return RCTFChallenge(
                    id=str(c["id"]),
                    name=str(c.get("name") or ""),
                    category=str(c.get("category") or ""),
                    value=c.get("points") if isinstance(c.get("points"), int) else None,
                    description=str(c.get("description") or ""),
                    connection_info=str(c.get("connection_info") or ""),
                    files=files,
                    tags=[str(t) for t in (c.get("tags") or [])],
                    hints=[],
                    raw=c,
                )
        raise KeyError(f"rCTF challenge not found: {challenge_id!r}")

    def download_files(self, challenge: Any, dest: Path) -> list[Path]:
        dest.mkdir(parents=True, exist_ok=True)
        paths: list[Path] = []
        for file_url in getattr(challenge, "files", []):
            paths.append(self._download_unauthenticated(str(file_url), dest))
        return paths

    def solved_ids(self) -> set[str | int]:
        # rCTF v1 API does not expose per-user solved state easily.
        return set()

    def submit_flag(self, challenge_id: str | int, flag: str) -> SubmitResult:
        resp = self._request(
            "POST",
            f"/api/v1/challs/{challenge_id}/submit",
            body={"flag": flag},
        )
        if resp.get("kind") == "goodFlag":
            return SubmitResult(True, resp.get("message", "Correct flag!"))
        return SubmitResult(False, resp.get("message", "Incorrect flag"))
