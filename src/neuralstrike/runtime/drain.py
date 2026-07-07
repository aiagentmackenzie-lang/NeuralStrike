"""Graceful task drain for shutdown / cancellation."""

from __future__ import annotations

import asyncio
from typing import Any


class GracefulDrain:
    """Hold references to in-flight tasks and cancel them gracefully."""

    def __init__(self) -> None:
        self._tasks: set[asyncio.Task[Any]] = set()

    def track(self, task: asyncio.Task[Any]) -> asyncio.Task[Any]:
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    async def drain(self, *, timeout: float | None = 5.0) -> None:
        """Cancel all tracked tasks and wait for them to finish."""
        if not self._tasks:
            return
        for t in list(self._tasks):
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        # Any tasks still running after the gather are waited on with a deadline.
        pending = {t for t in self._tasks if not t.done()}
        if pending and timeout is not None:
            await asyncio.wait_for(
                asyncio.gather(*pending, return_exceptions=True),
                timeout=timeout,
            )
