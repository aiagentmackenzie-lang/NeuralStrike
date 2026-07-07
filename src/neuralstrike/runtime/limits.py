"""Rate limiting and concurrency controls."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class RateLimiter:
    """Token-bucket rate limiter for LLM / target calls."""

    max_calls: int
    per_seconds: float
    _tokens: float = field(init=False)
    _last: float = field(init=False)
    _lock: asyncio.Lock = field(init=False)

    def __post_init__(self) -> None:
        self._tokens = float(self.max_calls)
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._last = now
            rate = self.max_calls / self.per_seconds
            self._tokens = min(float(self.max_calls), self._tokens + elapsed * rate)
            if self._tokens < 1:
                wait = (1 - self._tokens) * (self.per_seconds / self.max_calls)
                await asyncio.sleep(wait)
                self._tokens = 0.0
            else:
                self._tokens -= 1.0


@dataclass
class ConcurrencyLimiter:
    """Semaphore wrapper that records active / peak concurrency."""

    max_concurrent: int
    _semaphore: asyncio.Semaphore = field(init=False)
    _active: int = field(default=0, init=False)
    _peak: int = field(default=0, init=False)
    _lock: asyncio.Lock = field(init=False)

    def __post_init__(self) -> None:
        self._semaphore = asyncio.Semaphore(self.max_concurrent)
        self._lock = asyncio.Lock()

    async def __aenter__(self) -> ConcurrencyLimiter:
        await self._semaphore.acquire()
        async with self._lock:
            self._active += 1
            self._peak = max(self._peak, self._active)
        return self

    async def __aexit__(self, *exc: Any) -> None:
        async with self._lock:
            self._active -= 1
        self._semaphore.release()

    def summary(self) -> dict[str, int]:
        return {"max": self.max_concurrent, "active": self._active, "peak": self._peak}
