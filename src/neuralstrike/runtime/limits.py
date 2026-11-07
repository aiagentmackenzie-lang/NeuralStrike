"""Rate limiting and concurrency controls."""

from __future__ import annotations

import asyncio
import math
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
        if type(self.max_calls) is not int or self.max_calls < 1:
            raise ValueError("max_calls must be a positive integer")
        if not math.isfinite(self.per_seconds) or self.per_seconds <= 0:
            raise ValueError("per_seconds must be finite and positive")
        self._tokens = float(self.max_calls)
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self._last
                self._last = now
                rate = self.max_calls / self.per_seconds
                self._tokens = min(float(self.max_calls), self._tokens + elapsed * rate)
                if self._tokens >= 1:
                    self._tokens -= 1
                    return
                await asyncio.sleep((1 - self._tokens) / rate)


@dataclass
class ConcurrencyLimiter:
    """Semaphore wrapper that records active / peak concurrency."""

    max_concurrent: int
    _semaphore: asyncio.Semaphore = field(init=False)
    _active: int = field(default=0, init=False)
    _peak: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        if type(self.max_concurrent) is not int or self.max_concurrent < 1:
            raise ValueError("max_concurrent must be a positive integer")
        self._semaphore = asyncio.Semaphore(self.max_concurrent)

    async def __aenter__(self) -> ConcurrencyLimiter:
        await self._semaphore.acquire()
        self._active += 1
        self._peak = max(self._peak, self._active)
        return self

    async def __aexit__(self, *exc: Any) -> None:
        self._active -= 1
        self._semaphore.release()

    def summary(self) -> dict[str, int]:
        return {"max": self.max_concurrent, "active": self._active, "peak": self._peak}
