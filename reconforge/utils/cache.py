"""
Cache Utility Module
════════════════════
Simple disk-based cache to avoid re-fetching data
and respect rate limits during reconnaissance.
"""

import os
import json
import time
import hashlib
from typing import Any, Optional

CACHE_DIR = os.path.join(os.path.expanduser("~"), ".cache", "reconforge")


def _ensure_cache_dir():
    """Create cache directory if it doesn't exist."""
    os.makedirs(CACHE_DIR, exist_ok=True)


def _key_to_path(key: str) -> str:
    """Convert a cache key to a file path."""
    hashed = hashlib.sha256(key.encode()).hexdigest()[:32]
    return os.path.join(CACHE_DIR, f"{hashed}.json")


def get(key: str, max_age_hours: int = 24) -> Optional[Any]:
    """Get a value from cache if it exists and is not expired."""
    path = _key_to_path(key)
    if not os.path.exists(path):
        return None

    try:
        with open(path, "r") as f:
            data = json.load(f)

        age_hours = (time.time() - data["cached_at"]) / 3600
        if age_hours > max_age_hours:
            os.remove(path)
            return None

        return data["value"]
    except (json.JSONDecodeError, KeyError, OSError):
        return None


def set(key: str, value: Any):
    """Store a value in cache."""
    _ensure_cache_dir()
    path = _key_to_path(key)
    data = {"cached_at": time.time(), "value": value}
    try:
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
    except OSError:
        pass


def clear():
    """Clear all cached data."""
    _ensure_cache_dir()
    for fname in os.listdir(CACHE_DIR):
        if fname.endswith(".json"):
            try:
                os.remove(os.path.join(CACHE_DIR, fname))
            except OSError:
                pass
