"""CTFd challenge downloader (Phase 4, optional — clank-the-flag borrow).

Pulls a challenge's metadata (name, category, value, tags, hints, connection info)
and attached files from a CTFd instance via its JSON API, lays them down in a
per-challenge workspace (challenge.py), and writes a PROMPT.md the agent can read.

Auth: pass a session token (CTFd `session` cookie value) or an API token. Network
access is required; this runs on the HOST (it only writes into the workspace, it does
not execute challenge code).
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin

logger = logging.getLogger(__name__)


def _slugify(name: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9._-]+", "-", name.strip().lower()).strip("-")
    return s or "challenge"


class CTFdDownloader:
    """Minimal CTFd API client for pulling a single challenge into a workspace."""

    def __init__(self, base_url: str, token: Optional[str] = None,
                 session_cookie: Optional[str] = None):
        self.base_url = base_url.rstrip("/") + "/"
        self.token = token
        self.session_cookie = session_cookie

    def _headers(self) -> dict:
        h = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.token:
            h["Authorization"] = f"Token {self.token}"
        if self.session_cookie:
            h["Cookie"] = f"session={self.session_cookie}"
        return h

    def _get(self, path: str):
        import requests
        url = urljoin(self.base_url, path.lstrip("/"))
        r = requests.get(url, headers=self._headers(), timeout=30)
        r.raise_for_status()
        return r

    def list_challenges(self) -> list[dict]:
        data = self._get("api/v1/challenges").json()
        return data.get("data", [])

    def get_challenge(self, challenge_id: int) -> dict:
        data = self._get(f"api/v1/challenges/{challenge_id}").json()
        return data.get("data", {})

    async def download_challenge(self, challenge_id: int) -> dict:
        """Download one challenge into a per-challenge workspace + PROMPT.md."""
        from ..challenge import create_challenge, challenge_dir
        meta = self.get_challenge(challenge_id)
        if not meta:
            return {"error": f"challenge {challenge_id} not found"}

        name = meta.get("name", f"challenge-{challenge_id}")
        category = meta.get("category", "misc")
        slug = _slugify(name)

        info = await create_challenge(name=name, category=category,
                                      description=meta.get("description", ""))
        base = challenge_dir(slug)
        files_dir = base / "files"
        files_dir.mkdir(parents=True, exist_ok=True)

        # Download attached files.
        downloaded = []
        for fpath in meta.get("files", []):
            try:
                import requests
                furl = urljoin(self.base_url, fpath.lstrip("/"))
                fr = requests.get(furl, headers={"Cookie": f"session={self.session_cookie}"}
                                  if self.session_cookie else {}, timeout=60)
                fr.raise_for_status()
                fname = Path(fpath.split("?")[0]).name
                (files_dir / fname).write_bytes(fr.content)
                downloaded.append(fname)
            except Exception as e:
                logger.warning("file download failed (%s): %s", fpath, e)

        # Write PROMPT.md with everything the agent needs.
        prompt = base / "PROMPT.md"
        hints = meta.get("hints", [])
        tags = [t.get("value", t) if isinstance(t, dict) else t for t in meta.get("tags", [])]
        conn = meta.get("connection_info") or ""
        prompt.write_text(
            f"# {name}\n\n"
            f"- Category: {category}\n"
            f"- Value: {meta.get('value', '?')}\n"
            f"- Tags: {', '.join(str(t) for t in tags) or '(none)'}\n"
            f"- Connection: {conn or '(none)'}\n\n"
            f"## Description\n\n{meta.get('description', '(none)')}\n\n"
            "## Files\n\n" + ("\n".join(f"- files/{f}" for f in downloaded) or "(none)") + "\n\n"
            "## Hints\n\n" + ("\n".join(f"- {h.get('content', h)}" for h in hints) or "(none)") + "\n",
            encoding="utf-8")

        return {
            "challenge_id": slug,
            "name": name,
            "category": category,
            "files": downloaded,
            "connection": conn,
            "workspace": info["container_path"],
            "prompt": str(prompt),
        }
