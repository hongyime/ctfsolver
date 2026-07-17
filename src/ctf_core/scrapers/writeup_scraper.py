"""CTF writeup scraper — CTFtime.org, GitHub, DuckDuckGo waterfall."""
import json
import os
import random
import re
import sys
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional, Callable
from urllib.parse import urlparse

from ctf_core.utils.resilience import _SHUTDOWN, wait_for_internet, with_internet_retry


# ---------------------------------------------------------------------------
# AdaptiveRateLimiter (from searchtoolkit — per-domain, adaptive, thread-safe)
# ---------------------------------------------------------------------------

def _interruptible_sleep_local(seconds: float, check_interval: float = 0.2) -> None:
    if seconds <= 0:
        return
    end_time = time.time() + seconds
    while True:
        if _SHUTDOWN.is_set():
            return
        remaining = end_time - time.time()
        if remaining <= 0:
            return
        time.sleep(min(check_interval, remaining))


class _RateLimiter:
    def __init__(self, base_delay: float = 1.0, max_delay: float = 30.0, jitter: float = 0.5):
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.jitter = jitter
        self._domain_delays: dict[str, float] = {}
        self._domain_failures: dict[str, int] = {}
        self._lock = threading.RLock()

    def wait(self, url: str) -> None:
        domain = urlparse(url).netloc
        with self._lock:
            now = time.time()
            last = self._domain_delays.get(domain, 0)
            elapsed = now - last
            if elapsed < self.base_delay:
                wait_time = self.base_delay - elapsed + random.uniform(0, self.jitter)
                _interruptible_sleep_local(wait_time)
            self._domain_delays[domain] = time.time()

    def record_success(self, url: str) -> None:
        domain = urlparse(url).netloc
        with self._lock:
            failures = self._domain_failures.get(domain, 0)
            if failures > 0:
                self._domain_failures[domain] = max(0, failures - 1)

    def record_failure(self, url: str, status_code: int = 0) -> None:
        domain = urlparse(url).netloc
        with self._lock:
            self._domain_failures[domain] = self._domain_failures.get(domain, 0) + 1
            failures = self._domain_failures[domain]
            backoff = min(2 ** failures, self.max_delay)
            self._domain_delays[domain] = time.time() + backoff


class AdaptiveRateLimiter(_RateLimiter):
    def __init__(self, base_delay: float = 1.0, max_delay: float = 30.0,
                 min_delay: float = 0.5, jitter: float = 0.5, adjustment_factor: float = 0.1):
        super().__init__(base_delay, max_delay, jitter)
        self.min_delay = min_delay
        self.adjustment_factor = adjustment_factor
        self._domain_streaks: dict[str, int] = {}

    def record_success(self, url: str) -> None:
        domain = urlparse(url).netloc
        with self._lock:
            self._domain_streaks[domain] = self._domain_streaks.get(domain, 0) + 1
            if self._domain_streaks[domain] >= 5:
                self.base_delay = max(self.min_delay, self.base_delay * (1 - self.adjustment_factor))
                self._domain_streaks[domain] = 0
            super().record_success(url)

    def record_failure(self, url: str, status_code: int = 0) -> None:
        domain = urlparse(url).netloc
        with self._lock:
            self._domain_streaks[domain] = 0
            if status_code in (429, 503):
                self.base_delay = min(self.max_delay, self.base_delay * (1 + self.adjustment_factor))
            super().record_failure(url, status_code)


# ---------------------------------------------------------------------------
# Scrape targets
# ---------------------------------------------------------------------------

_rate_limiter = AdaptiveRateLimiter(base_delay=1.0, max_delay=10.0, min_delay=0.5)


def _downloads_dir() -> Path:
    base = Path(os.environ.get("CTFTOOLKIT_DOWNLOADS", "downloads"))
    return base / "writeups"


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(content, encoding="utf-8")
    os.replace(tmp, path)


def _is_safe_url(url: str) -> bool:
    """P1-008: block SSRF to private/loopback/link-local/reserved addresses."""
    import ipaddress
    import socket
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return False
        for info in socket.getaddrinfo(parsed.hostname, None):
            ip = ipaddress.ip_address(info[4][0])
            if (ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
                return False
        return True
    except Exception:
        return False


def _fetch_url(url: str, timeout: int = 10) -> Optional[str]:
    """Fetch a URL and return raw HTML/text, or None on error."""
    try:
        if not _is_safe_url(url):
            print(f"[SCRAPER] Blocked disallowed/SSRF URL: {url}", flush=True)
            return None
        req = urllib.request.Request(url, headers={"User-Agent": "CTFToolkit/1.0 (educational)"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception:
        return None


def _scrape_ctftime(challenge_name: str, limit: int) -> list[dict]:
    """Search CTFtime.org writeups."""
    query = urllib.parse.quote(challenge_name)
    url = f"https://ctftime.org/writeups?search={query}"

    if _SHUTDOWN.is_set():
        return []

    _rate_limiter.wait(url)
    html = with_internet_retry(_fetch_url, url)
    if not html:
        _rate_limiter.record_failure(url)
        return []

    _rate_limiter.record_success(url)

    # Parse writeup links from CTFtime search results
    results = []
    pattern = re.compile(r'<a href="(/writeup/\d+)"[^>]*>([^<]+)</a>')
    for m in pattern.finditer(html):
        path, title = m.group(1), m.group(2).strip()
        results.append({
            "title": title,
            "url": f"https://ctftime.org{path}",
            "source": "ctftime",
        })
        if len(results) >= limit:
            break
    return results


def _scrape_github(challenge_name: str, limit: int) -> list[dict]:
    """Search GitHub for CTF writeups via the public search API."""
    query = urllib.parse.quote(f"CTF writeup {challenge_name}")
    url = f"https://api.github.com/search/code?q={query}"

    if _SHUTDOWN.is_set():
        return []

    _rate_limiter.wait(url)
    try:
        headers = {
            "User-Agent": "CTFToolkit/1.0",
            "Accept": "application/vnd.github+json",
        }
        # P4-012: authenticated requests lift GitHub's 10 req/min unauth limit to ~5000/hr
        _gh_token = os.environ.get("GITHUB_TOKEN")
        if _gh_token:
            headers["Authorization"] = f"Bearer {_gh_token}"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        _rate_limiter.record_success(url)
    except Exception as e:
        _rate_limiter.record_failure(url)
        print(f"[SCRAPER] GitHub search failed: {e}", flush=True)
        return []

    results = []
    for item in data.get("items", [])[:limit]:
        results.append({
            "title": item.get("name", ""),
            "url": item.get("html_url", ""),
            "source": "github",
        })
    return results


def _scrape_duckduckgo(challenge_name: str, category: str, limit: int) -> list[dict]:
    """Search DuckDuckGo for CTF writeups."""
    try:
        from duckduckgo_search import DDGS
    except ImportError:
        return []

    query = f"CTF writeup {challenge_name} {category}".strip()

    if _SHUTDOWN.is_set():
        return []

    try:
        with DDGS() as ddgs:
            raw = list(ddgs.text(query, max_results=limit))
        return [{"title": r.get("title", ""), "url": r.get("href", ""), "source": "duckduckgo"} for r in raw]
    except Exception as e:
        print(f"[SCRAPER] DuckDuckGo search failed: {e}", flush=True)
        return []


def _fetch_and_store_writeup(entry: dict, challenge_name: str) -> Optional[dict]:
    """Fetch full writeup content, write to disk atomically, return metadata."""
    url = entry["url"]
    source = entry.get("source", "web")
    title = entry.get("title", url)

    if _SHUTDOWN.is_set():
        return None

    if not wait_for_internet():
        return None

    _rate_limiter.wait(url)
    html = with_internet_retry(_fetch_url, url)
    if not html:
        _rate_limiter.record_failure(url)
        return None

    _rate_limiter.record_success(url)

    # Try to extract plain text via BeautifulSoup
    content = html
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "lxml")
        content = soup.get_text(separator="\n")
    except Exception:
        pass

    # Write to disk: downloads/writeups/{challenge_name}/{source}_{slug}.md
    safe_name = re.sub(r"[^\w\-]", "_", challenge_name)[:50]
    safe_url = re.sub(r"[^\w]", "_", url)[-30:]
    file_name = f"{source}_{safe_url}.md"
    dest = _downloads_dir() / safe_name / file_name

    _atomic_write(dest, f"# {title}\n\nSource: {url}\n\n---\n\n{content}")
    print(f"[WRITEUP] Saved: {dest}", flush=True)
    sys.stdout.flush()

    summary = content[:300].replace("\n", " ").strip()
    return {
        "challenge_name": challenge_name,
        "source_url": url,
        "title": title,
        "content_summary": summary,
        "full_content_path": str(dest),
        "relevance_score": None,
    }


def search_writeups(
    challenge_name: str,
    category: str = "",
    limit: int = 10,
    db=None,
) -> list[dict]:
    """Search and scrape CTF writeups for the given challenge.

    Scrape waterfall: CTFtime → GitHub → DuckDuckGo.
    Writes full content to disk. Returns list of writeup metadata dicts.
    Memory-safe: writes each writeup immediately, never buffers all results.
    """
    if not wait_for_internet():
        return []

    candidates: list[dict] = []

    scrapers: list[tuple[Callable[..., list[dict]], tuple]] = [
        (_scrape_ctftime, (challenge_name, limit)),
        (_scrape_github, (challenge_name, limit)),
        (_scrape_duckduckgo, (challenge_name, category, limit)),
    ]
    for scrape_fn, args in scrapers:
        if _SHUTDOWN.is_set():
            break
        try:
            results = scrape_fn(*args)
            candidates.extend(results)
            if len(candidates) >= limit:
                break
        except Exception as e:
            print(f"[SCRAPER] {getattr(scrape_fn, '__name__', 'scraper')} error: {e}", flush=True)
        sys.stdout.flush()

    writeups = []
    seen_urls: set[str] = set()

    for entry in candidates[:limit]:
        if _SHUTDOWN.is_set():
            break

        url = entry.get("url", "")
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)

        metadata = _fetch_and_store_writeup(entry, challenge_name)
        if metadata is None:
            continue

        # Persist to DB if available
        if db is not None:
            try:
                db.execute(
                    """INSERT OR IGNORE INTO writeups
                       (challenge_name, category, source_url, title, content_summary, full_content_path)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        challenge_name,
                        category or None,
                        metadata["source_url"],
                        metadata["title"],
                        metadata["content_summary"],
                        metadata["full_content_path"],
                    ),
                )
                db.commit()
            except Exception as e:
                print(f"[SCRAPER] DB insert failed: {e}", flush=True)

        writeups.append(metadata)

    return writeups
