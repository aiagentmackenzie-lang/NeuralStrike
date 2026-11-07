"""Shared outbound admission and post-response token accounting.

Request admission limits dispatches. Token usage is provider-reported or an
explicit heuristic; an already dispatched billable request cannot be undone.
No automatic retries or absolute token/spend ceilings are promised.
"""

from __future__ import annotations

import json
import math
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from neuralstrike.runtime.budget import Budget, BudgetExceeded
from neuralstrike.runtime.limits import ConcurrencyLimiter, RateLimiter


class RequestLimitExceeded(BudgetExceeded):
    """Another outbound request cannot be admitted."""


class OutboundPolicy:
    """One policy shared by all adapters in an assessment/event loop."""

    def __init__(
        self,
        *,
        max_requests: int | None = None,
        max_total_tokens: int | None = None,
        max_concurrent_requests: int = 1,
        requests_per_minute: float | None = None,
    ) -> None:
        for name, value in (("max_requests", max_requests), ("max_total_tokens", max_total_tokens)):
            if value is not None and (type(value) is not int or value < 1):
                raise ValueError(f"{name} must be a positive integer")
        if requests_per_minute is not None and (
            not math.isfinite(requests_per_minute) or requests_per_minute <= 0
        ):
            raise ValueError("requests_per_minute must be finite and positive")
        self.max_requests = max_requests
        self.requests_per_minute = requests_per_minute
        self.concurrency = ConcurrencyLimiter(max_concurrent_requests)
        self.rate = RateLimiter(1, 60 / requests_per_minute) if requests_per_minute is not None else None
        self.budget = Budget(max_tokens=max_total_tokens)
        self.dispatched = 0
        self.unmeasured = 0
        self._accounted: set[int] = set()
        self._sources: set[str] = set()

    def _ensure_available(self) -> None:
        if self.max_requests is not None and self.dispatched >= self.max_requests:
            raise RequestLimitExceeded(f"outbound request limit exhausted ({self.max_requests})")
        if self.budget.max_tokens is not None:
            if self.unmeasured:
                raise RequestLimitExceeded("token budget cannot continue after an unmeasured request")
            if self.budget.tokens_used >= self.budget.max_tokens:
                raise RequestLimitExceeded("outbound token threshold exhausted")

    @asynccontextmanager
    async def request(self) -> AsyncIterator[dict[str, Any]]:
        receipt: dict[str, Any] | None = None
        try:
            self._ensure_available()
            async with self.concurrency:
                self._ensure_available()
                if self.rate is not None:
                    await self.rate.acquire()
                # Recheck after awaited admission gates; reserve without yielding.
                self._ensure_available()
                self.dispatched += 1
                number = self.dispatched
                receipt = {
                    "request_number": number,
                    "tokens": None,
                    "token_usage_source": "unavailable",
                    "cost_usd": None,
                    "cost_status": "unavailable",
                    "limit_semantics": "post-response token threshold; no absolute token or spend ceiling",
                }
                try:
                    yield receipt
                finally:
                    if number not in self._accounted:
                        self.unmeasured += 1
        finally:
            if receipt is not None:
                receipt["policy"] = self.summary()

    def account(self, receipt: dict[str, Any], payload: dict[str, Any], response: dict[str, Any]) -> None:
        """Account once before processing any returned tool actions."""
        usage = response.get("usage")
        tokens = usage.get("total_tokens") if isinstance(usage, dict) else None
        if type(tokens) is int and tokens >= 0:
            source = "provider-reported"
        else:
            size = len(json.dumps(payload, ensure_ascii=False).encode())
            size += len(json.dumps(response, ensure_ascii=False).encode())
            tokens = max(1, math.ceil(size / 4))
            source = "estimated"
        number = receipt["request_number"]
        if number in self._accounted:
            raise ValueError("outbound request already accounted")
        self._accounted.add(number)
        self._sources.add(source)
        receipt.update(tokens=tokens, token_usage_source=source)
        self.budget.add_usage(tokens=tokens)

    def configuration(self) -> dict[str, Any]:
        return {
            "max_requests": self.max_requests,
            "max_total_tokens": self.budget.max_tokens,
            "requests_per_minute": self.requests_per_minute,
            "max_concurrent_requests": self.concurrency.max_concurrent,
            "token_limit_semantics": "post-response reported/estimated threshold; may overshoot",
            "cost_status": "unavailable; no absolute spend ceiling",
        }

    def summary(self) -> dict[str, Any]:
        return {
            "max_requests": self.max_requests,
            "requests_reserved": self.dispatched,
            "requests_per_minute": self.requests_per_minute,
            "concurrency": self.concurrency.summary(),
            "max_total_tokens": self.budget.max_tokens,
            "total_tokens": self.budget.tokens_used,
            "token_usage_sources": sorted(self._sources),
            "unmeasured_requests": self.unmeasured,
            "cost_usd": None,
            "cost_status": "unavailable",
            "estimated_tokens_method": "ceil(request and response JSON UTF-8 bytes / 4); heuristic",
        }
