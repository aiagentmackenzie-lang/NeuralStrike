"""Cost / token budget tracking for NeuralStrike runs."""

from __future__ import annotations

from dataclasses import dataclass, field

from neuralstrike.core.exceptions import NeuralStrikeError


class BudgetExceeded(NeuralStrikeError):
    """Raised when a run exceeds its configured cost or token budget."""


@dataclass
class Budget:
    """A simple spend/token budget for a run.

    Token counts are estimates when the LLM response does not surface real
    usage metadata. The budget fails closed: spending past the cap aborts.
    """

    max_cost_usd: float | None = None
    max_tokens: int | None = None
    spent_usd: float = field(default=0.0, init=False)
    tokens_used: int = field(default=0, init=False)
    calls: int = field(default=0, init=False)

    def add_usage(self, *, cost_usd: float = 0.0, tokens: int = 0) -> None:
        """Record a single LLM call's usage."""
        self.calls += 1
        self.spent_usd += cost_usd
        self.tokens_used += tokens
        if self.max_cost_usd is not None and self.spent_usd > self.max_cost_usd:
            raise BudgetExceeded(
                f"cost budget exceeded: ${self.spent_usd:.4f} > ${self.max_cost_usd:.4f}"
            )
        if self.max_tokens is not None and self.tokens_used > self.max_tokens:
            raise BudgetExceeded(
                f"token budget exceeded: {self.tokens_used} > {self.max_tokens}"
            )

    def summary(self) -> dict[str, float | int | None]:
        return {
            "max_cost_usd": self.max_cost_usd,
            "max_tokens": self.max_tokens,
            "spent_usd": self.spent_usd,
            "tokens_used": self.tokens_used,
            "calls": self.calls,
        }
