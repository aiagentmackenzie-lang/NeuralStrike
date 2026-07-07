"""Tests for runtime hardening helpers."""

from __future__ import annotations

import asyncio

import pytest

from neuralstrike.runtime import (
    Budget,
    BudgetExceeded,
    ConcurrencyLimiter,
    GracefulDrain,
    RateLimiter,
    with_retry,
    with_timeout,
)
from neuralstrike.runtime.retry import TimeoutError


class TestBudget:
    def test_tracks_usage(self) -> None:
        b = Budget(max_cost_usd=1.0, max_tokens=100)
        b.add_usage(cost_usd=0.5, tokens=50)
        assert b.spent_usd == 0.5
        assert b.tokens_used == 50

    def test_cost_exceeded_fails_closed(self) -> None:
        b = Budget(max_cost_usd=1.0)
        with pytest.raises(BudgetExceeded, match="cost budget exceeded"):
            b.add_usage(cost_usd=2.0)

    def test_token_exceeded_fails_closed(self) -> None:
        b = Budget(max_tokens=10)
        with pytest.raises(BudgetExceeded, match="token budget exceeded"):
            b.add_usage(tokens=11)


class TestTimeout:
    async def test_timeout_raises_fails_closed(self) -> None:
        with pytest.raises(TimeoutError, match=r"timed out after 0\.01s"):
            await with_timeout(asyncio.sleep(1), 0.01, label="sleep")

    async def test_no_timeout_passes(self) -> None:
        result = await with_timeout(asyncio.sleep(0), None)
        assert result is None


class TestRetry:
    async def test_retry_succeeds_eventually(self) -> None:
        state = {"attempts": 0}

        async def flaky() -> str:
            state["attempts"] += 1
            if state["attempts"] < 3:
                raise ConnectionError("boom")
            return "ok"

        result = await with_retry(flaky, max_retries=3, base_delay=0.01, exceptions=(ConnectionError,))
        assert result == "ok"
        assert state["attempts"] == 3

    async def test_retry_exhausted_raises(self) -> None:
        async def always_fails() -> str:
            raise RuntimeError("nope")

        with pytest.raises(Exception, match="failed after 3 attempts"):
            await with_retry(always_fails, max_retries=2, base_delay=0.01)


class TestRateLimiter:
    async def test_rate_limiter_throttles(self) -> None:
        rl = RateLimiter(max_calls=2, per_seconds=1.0)
        start = asyncio.get_event_loop().time()
        await rl.acquire()
        await rl.acquire()
        await rl.acquire()
        elapsed = asyncio.get_event_loop().time() - start
        assert elapsed >= 0.4  # third call had to wait for a token


class TestConcurrencyLimiter:
    async def test_concurrency_peak(self) -> None:
        limiter = ConcurrencyLimiter(max_concurrent=2)
        async with limiter, limiter:
            assert limiter.summary()["peak"] == 2


class TestGracefulDrain:
    async def test_drain_cancels_tasks(self) -> None:
        drain = GracefulDrain()

        async def sleeper() -> None:
            await asyncio.sleep(60)

        task = drain.track(asyncio.create_task(sleeper()))
        await drain.drain(timeout=0.1)
        assert task.cancelled()
