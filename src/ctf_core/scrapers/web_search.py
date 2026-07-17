"""Web search with DuckDuckGo (free) and Google CSE (optional) — results cached in DB."""
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from ctf_core.utils.resilience import _SHUTDOWN, wait_for_internet, with_internet_retry

SEARCH_TYPES = ("general", "exploit", "cve", "tool_usage", "writeup")


def _cache_ttl() -> int:
    return int(os.environ.get("CTFTOOLKIT_SEARCH_CACHE_TTL", "3600"))


def _utcnow() -> datetime:
    """Naive UTC timestamp (non-deprecated utcnow replacement)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _get_cached(db, query: str, search_type: str) -> Optional[list[dict]]:
    """Return cached results if present and not expired."""
    try:
        row = db.fetchone(
            "SELECT results, expires_at FROM web_search_cache WHERE query=? AND search_type=?",
            (query, search_type),
        )
        if row is None:
            return None
        expires_at = datetime.fromisoformat(row["expires_at"])
        if _utcnow() > expires_at:
            return None
        return json.loads(row["results"])
    except Exception:
        return None


def _save_cache(db, query: str, search_type: str, results: list[dict]) -> None:
    expires_at = (_utcnow() + timedelta(seconds=_cache_ttl())).isoformat()
    try:
        db.execute(
            """INSERT INTO web_search_cache (query, search_type, results, cached_at, expires_at)
               VALUES (?, ?, ?, datetime('now'), ?)
               ON CONFLICT(query, search_type) DO UPDATE SET
                 results=excluded.results, cached_at=excluded.cached_at, expires_at=excluded.expires_at""",
            (query, search_type, json.dumps(results), expires_at),
        )
        db.commit()
    except Exception:
        pass


def _search_duckduckgo(query: str, limit: int) -> list[dict]:
    from duckduckgo_search import DDGS
    results = []
    with DDGS() as ddgs:
        for r in ddgs.text(query, max_results=limit):
            results.append({"title": r.get("title", ""), "url": r.get("href", ""), "snippet": r.get("body", "")})
    return results


def _search_google(query: str, limit: int) -> list[dict]:
    import urllib.request
    import urllib.parse

    api_key = os.environ.get("GOOGLE_API_KEY", "")
    cse_id = os.environ.get("GOOGLE_CSE_ID", "")
    if not api_key or not cse_id:
        return []

    params = urllib.parse.urlencode({"key": api_key, "cx": cse_id, "q": query, "num": min(limit, 10)})
    url = f"https://www.googleapis.com/customsearch/v1?{params}"

    with urllib.request.urlopen(url, timeout=10) as resp:
        data = json.loads(resp.read())

    return [
        {"title": item.get("title", ""), "url": item.get("link", ""), "snippet": item.get("snippet", "")}
        for item in data.get("items", [])
    ]


def search(
    query: str,
    search_type: str = "general",
    limit: int = 5,
    db=None,
) -> list[dict[str, Any]]:
    """Search the web using DuckDuckGo → Google CSE waterfall.

    Results are cached in web_search_cache for CTFTOOLKIT_SEARCH_CACHE_TTL seconds.
    Returns a list of {title, url, snippet} dicts.
    """
    if _SHUTDOWN.is_set():
        return []

    if search_type not in SEARCH_TYPES:
        search_type = "general"

    # Check cache first
    if db is not None:
        cached = _get_cached(db, query, search_type)
        if cached is not None:
            return cached[:limit]

    if not wait_for_internet():
        return []

    results: list[dict] = []

    # 1. Try DuckDuckGo (free, no key needed)
    if _SHUTDOWN.is_set():
        return []
    try:
        results = with_internet_retry(_search_duckduckgo, query, limit) or []
        print(f"[SEARCH] DuckDuckGo: {len(results)} results for '{query}'", flush=True)
        sys.stdout.flush()
    except Exception as e:
        print(f"[SEARCH] DuckDuckGo failed: {e}", flush=True)

    # 2. Fall back to Google CSE if DuckDuckGo returned nothing
    if not results and os.environ.get("GOOGLE_API_KEY"):
        if _SHUTDOWN.is_set():
            return []
        try:
            results = with_internet_retry(_search_google, query, limit) or []
            print(f"[SEARCH] Google CSE: {len(results)} results for '{query}'", flush=True)
            sys.stdout.flush()
        except Exception as e:
            print(f"[SEARCH] Google CSE failed: {e}", flush=True)

    # Cache results
    if db is not None and results:
        _save_cache(db, query, search_type, results)

    return results[:limit]
