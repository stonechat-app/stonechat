"""Per-IP, in-process rate limiting.

Assumes a single uvicorn process (as deployed): counts live in process memory
and reset on restart. That's fine for the goal — breaking scripted loops —
which doesn't need precise metering.
"""

import threading
import time

from fastapi import HTTPException


class RateLimiter:
    """Sliding-window counter per key; 429 beyond `limit` hits per `window_s`.
    Locked: sync handlers run across FastAPI's threadpool."""

    def __init__(self, limit: int, window_s: float):
        self.limit = limit
        self.window_s = window_s
        self._buckets: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.setdefault(key, [])
            bucket[:] = [t for t in bucket if now - t < self.window_s]
            if len(bucket) >= self.limit:
                raise HTTPException(429, "too many requests")
            bucket.append(now)
            if len(self._buckets) > 10_000:  # bound memory under address churn
                self._buckets.clear()
