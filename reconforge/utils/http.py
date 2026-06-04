"""
HTTP Utility Module
═══════════════════
Safe HTTP requests with timeout, rate limiting, and error handling.
"""

import json
import time
from typing import Optional
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)


def fetch_text(url: str, timeout: int = 10) -> Optional[str]:
    """Fetch a URL and return the text content."""
    try:
        req = Request(url, headers={"User-Agent": USER_AGENT})
        with urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except (HTTPError, URLError, OSError):
        return None


def fetch_json(url: str, timeout: int = 10) -> Optional[dict]:
    """Fetch a URL and parse JSON response."""
    text = fetch_text(url, timeout)
    if text:
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None
    return None


def check_url_status(url: str, timeout: int = 5) -> Optional[int]:
    """Check if a URL is reachable and return status code."""
    try:
        req = Request(url, method="HEAD", headers={"User-Agent": USER_AGENT})
        with urlopen(req, timeout=timeout) as resp:
            return resp.status
    except HTTPError as e:
        return e.code
    except (URLError, OSError):
        return None


class RateLimiter:
    """Simple rate limiter for API calls."""

    def __init__(self, calls_per_second: float = 1.0):
        self.min_interval = 1.0 / calls_per_second
        self.last_call = 0.0

    def wait(self):
        """Wait if needed to respect rate limit."""
        elapsed = time.time() - self.last_call
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self.last_call = time.time()
