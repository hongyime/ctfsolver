from __future__ import annotations

import dataclasses
import html
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from .util import HarnessError, sanitize_folder_name, slugify, unique_path


@dataclasses.dataclass(frozen=True)
class Challenge:
    id: int
    name: str
    category: str
    value: int | None
    description: str
    connection_info: str | None
    files: list[str]
    tags: list[str]
    hints: list[Any]
    raw: dict[str, Any]

    @property
    def slug(self) -> str:
        """Legacy identifier retained for state.json / DB keys (id+category+slug form)."""
        category = slugify(self.category) if self.category else "misc"
        return f"{self.id:04d}-{category}-{slugify(self.name)}"

    @property
    def folder_name(self) -> str:
        """Filesystem folder name for the challenge — matches organiser's given name.

        Layout convention: <output_dir>/<challenge folder_name>/ (files, README, etc.).
        For the flatter slug-based layout, opt in via
        CTF_HARNESS_CHALLENGE_LAYOUT=slug (default is 'name').
        """
        layout = os.environ.get("CTF_HARNESS_CHALLENGE_LAYOUT", "name").strip().lower()
        if layout == "slug":
            return self.slug
        return sanitize_folder_name(self.name, fallback=self.slug)


class CTFdClient:
    def __init__(
        self,
        base_url: str,
        token: str | None = None,
        cookie: str | None = None,
        timeout: int = 30,
    ) -> None:
        self.base_url = normalize_base_url(base_url)
        self.token = token or os.environ.get("CTFD_TOKEN")
        self.cookie = cookie or os.environ.get("CTFD_COOKIE")
        self.timeout = timeout

    def list_challenges(self) -> list[dict[str, Any]]:
        challenges: list[dict[str, Any]] = []
        seen_urls: set[str] = set()
        next_path: str | None = "/api/v1/challenges"
        while next_path:
            if next_path in seen_urls:
                raise HarnessError(f"CTFd pagination loop detected at {next_path}")
            seen_urls.add(next_path)
            data = self.api_get(next_path)
            page_challenges = data.get("data")
            if not isinstance(page_challenges, list):
                raise HarnessError(f"CTFd {next_path} did not return a data list")
            challenges.extend(
                challenge
                for challenge in page_challenges
                if isinstance(challenge, dict)
            )
            next_path = self.next_page_path(data)
            if next_path:
                continue
            pagination = data.get("meta", {}).get("pagination", {}) if isinstance(data.get("meta"), dict) else {}
            current_page = int(pagination.get("page") or pagination.get("current_page") or len(seen_urls)) if isinstance(pagination, dict) else len(seen_urls)
            if (
                isinstance(pagination, dict)
                and pagination.get("pages")
                and current_page < int(pagination["pages"])
            ):
                next_path = f"/api/v1/challenges?page={current_page + 1}"
        return challenges

    def solved_challenge_ids(self) -> set[int]:
        solved: set[int] = set()
        for challenge in self.list_challenges():
            if challenge.get("solved_by_me"):
                solved.add(int(challenge["id"]))
        return solved

    def get_challenge(self, challenge_id: int) -> Challenge:
        data = self.api_get(f"/api/v1/challenges/{challenge_id}")
        raw = data.get("data")
        if not isinstance(raw, dict):
            raise HarnessError(f"CTFd challenge {challenge_id} did not return a data object")
        return challenge_from_raw(challenge_id, raw)

    def api_get(self, path: str) -> dict[str, Any]:
        body, headers = self.fetch_bytes(path, accept="application/json")
        try:
            data = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            content_type = headers.get("Content-Type", "unknown") if headers else "unknown"
            snippet = body.decode("utf-8", errors="replace").strip()[:300]
            token_hint = "with CTFD_TOKEN" if self.token else "without CTFD_TOKEN"
            raise HarnessError(
                f"Invalid JSON from {path} {token_hint}; content-type={content_type}; "
                f"response starts with: {snippet!r}"
            ) from exc
        if data.get("success") is False:
            raise HarnessError(f"CTFd API error from {path}: {data.get('message') or data}")
        return data

    def next_page_path(self, data: dict[str, Any]) -> str | None:
        meta = data.get("meta")
        pagination = meta.get("pagination") if isinstance(meta, dict) else None
        if not isinstance(pagination, dict):
            return None
        next_value = pagination.get("next")
        if isinstance(next_value, str) and next_value:
            return self.relative_api_path(next_value)
        links = pagination.get("links")
        if isinstance(links, dict):
            next_link = links.get("next")
            if isinstance(next_link, str) and next_link:
                return self.relative_api_path(next_link)
        next_num = pagination.get("next_num")
        if isinstance(next_num, int) and next_num > 0:
            return f"/api/v1/challenges?page={next_num}"
        return None

    def relative_api_path(self, value: str) -> str:
        if re.match(r"^https?://", value):
            parsed = urllib.parse.urlparse(value)
            return urllib.parse.urlunparse(("", "", parsed.path, "", parsed.query, ""))
        return value

    def download_file(self, url: str, destination_dir: Path) -> Path:
        body, headers = self.fetch_bytes(url, authenticated=False)
        filename = filename_from_headers(headers) or self.filename_for_url(url)
        path = unique_path(destination_dir / filename)
        path.write_bytes(body)
        return path

    def filename_for_url(self, url: str) -> str:
        return filename_from_url(url)

    def fetch_bytes(
        self,
        path_or_url: str,
        accept: str | None = None,
        authenticated: bool | None = None,
        retries: int = 3,
    ) -> tuple[bytes, Any]:
        url = self.normalize_url(path_or_url)
        headers = self.headers_for(url, accept=accept, authenticated=authenticated)
        request = urllib.request.Request(url, headers=headers)
        
        last_exc: Exception | None = None
        for attempt in range(retries):
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    return response.read(), response.headers
            except urllib.error.HTTPError as exc:
                detail_body = exc.read()
                detail = detail_body.decode("utf-8", errors="replace")[:500]
                if (
                    authenticated is not False
                    and exc.code == 400
                    and "Missing x-amz-content-sha256" in detail
                ):
                    return self.fetch_bytes(path_or_url, accept=accept, authenticated=False)
                if exc.code not in {408, 429, 500, 502, 503, 504}:
                    raise HarnessError(f"HTTP {exc.code} fetching {request.full_url}: {detail}") from exc
                last_exc = HarnessError(f"HTTP {exc.code} fetching {request.full_url}: {detail}")
            except urllib.error.URLError as exc:
                last_exc = HarnessError(f"Failed to fetch {request.full_url}: {exc.reason}")
            
            if attempt < retries - 1:
                time.sleep(2 ** attempt)

        if last_exc:
            raise last_exc
        raise HarnessError(f"Failed to fetch {url} after {retries} attempts")

    def normalize_url(self, path_or_url: str) -> str:
        if re.match(r"^https?://", path_or_url):
            return path_or_url
        if path_or_url.startswith("/"):
            return f"{self.base_url}{path_or_url}"
        return f"{self.base_url}/{path_or_url}"

    def headers_for(
        self,
        url: str,
        accept: str | None = None,
        authenticated: bool | None = None,
    ) -> dict[str, str]:
        parsed = urllib.parse.urlparse(url)
        is_api = parsed.path.startswith("/api/")
        use_auth = is_api if authenticated is None else authenticated
        headers = {"User-Agent": "ctfd-dashboard-harness/1.0"}
        if accept:
            headers["Accept"] = accept
        if is_api and accept == "application/json":
            headers["Content-Type"] = "application/json"
        if use_auth and self.token:
            headers["Authorization"] = f"Token {self.token}"
        if use_auth and self.cookie:
            headers["Cookie"] = self.cookie
        return headers


def challenge_from_raw(challenge_id: int, raw: dict[str, Any]) -> Challenge:
    tags = raw.get("tags") or []
    normalized_tags = [
        str(tag.get("value") if isinstance(tag, dict) else tag)
        for tag in tags
        if tag is not None
    ] if isinstance(tags, list) else []
    files = [str(file_url) for file_url in (raw.get("files") or []) if file_url]
    return Challenge(
        id=int(raw.get("id") or challenge_id),
        name=str(raw.get("name") or f"challenge-{challenge_id}"),
        category=str(raw.get("category") or ""),
        value=raw.get("value") if isinstance(raw.get("value"), int) else None,
        description=str(raw.get("description") or ""),
        connection_info=raw.get("connection_info") or raw.get("connectionInfo"),
        files=files,
        tags=normalized_tags,
        hints=raw.get("hints") or [],
        raw=raw,
    )


def normalize_base_url(base_url: str) -> str:
    base_url = base_url.strip().rstrip("/")
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme and parsed.netloc:
        return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
    return base_url


def challenge_from_metadata(metadata: dict[str, Any]) -> Challenge:
    raw = metadata.get("raw") if isinstance(metadata.get("raw"), dict) else metadata
    return Challenge(
        id=int(metadata.get("id") or raw.get("id")),
        name=str(metadata.get("name") or raw.get("name") or "challenge"),
        category=str(metadata.get("category") or raw.get("category") or ""),
        value=metadata.get("value") if isinstance(metadata.get("value"), int) else None,
        description=str(metadata.get("description") or raw.get("description") or ""),
        connection_info=metadata.get("connection_info") or raw.get("connection_info") or raw.get("connectionInfo"),
        files=[str(item) for item in metadata.get("files", [])],
        tags=[str(item) for item in metadata.get("tags", [])],
        hints=metadata.get("hints") or raw.get("hints") or [],
        raw=raw,
    )


def strip_html(value: str) -> str:
    value = re.sub(r"(?i)<br\s*/?>", "\n", value)
    value = re.sub(r"(?i)</p\s*>", "\n\n", value)
    value = re.sub(r"<[^>]+>", "", value)
    return html.unescape(value).strip()


def filename_from_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    name = Path(urllib.parse.unquote(parsed.path)).name
    return slugify(name) if name else "attachment.bin"


def filename_from_headers(headers: Any) -> str | None:
    disposition = headers.get("Content-Disposition") if headers else None
    if not disposition:
        return None
    match = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)"?', disposition)
    if not match:
        return None
    filename = urllib.parse.unquote(match.group(1)).strip()
    return slugify(filename) if filename else None
