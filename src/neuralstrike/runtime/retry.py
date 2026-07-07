"""Timeout + exponential-backoff retry helpers."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import TypeVar

from neuralstrike.core.exceptions import NeuralStrikeError

T = TypeVar("T")


class TimeoutError(NeuralStrikeError):
    """Raised when a coroutine exceeds its deadline."""


async def with_timeout(
    coro: Awaitable[T],
    seconds: float | None,
    *,
    label: str = "operation",
) -> T:
    """Run a coroutine with a hard timeout; fail closed on expiry."""
    if seconds is None:
        return await coro
    try:
        return await asyncio.wait_for(coro, timeout=seconds)
    except asyncio.TimeoutError as exc:
        raise TimeoutError(f"{label} timed out after {seconds}s") from exc


async def with_retry(
    fn: Callable[[], Awaitable[T]],
    *,
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    exceptions: tuple[type[Exception], ...] = (Exception,),
    label: str = "call",
) -> T:
    """Retry an async callable with exponential backoff and jitter.

    The last exception is re-raised so it is never silently swallowed.
    """
    last_exc: Exception | None = None
    for attempt in range(max_retries + 1):
        try:
            return await fn()
        except exceptions as exc:
            last_exc = exc
            if attempt == max_retries:
                break
            delay = min(base_delay * (2**attempt), max_delay)
            await asyncio.sleep(delay)
    raise NeuralStrikeError(f"{label} failed after {max_retries + 1} attempts: {last_exc}") from last_exc
