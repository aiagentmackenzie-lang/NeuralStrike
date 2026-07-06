"""Tests for MCP-ITP implicit poisoning optimizer (Phase 5)."""

from __future__ import annotations

import pytest

from neuralstrike.attacks.mcp_implicit import MCPImplicitOptimizer


class TestMCPImplicitOptimizer:
    async def test_converges_when_asr_high(self) -> None:
        async def score(_desc: str) -> tuple[float, float]:
            return 0.9, 0.1

        opt = MCPImplicitOptimizer(
            initial_description="do evil",
            score_fn=score,
            max_iterations=3,
            asr_target=0.8,
        )
        result = await opt.optimize()
        assert result.converged
        assert result.best_asr == pytest.approx(0.9)

    async def test_respects_mtdr_budget(self) -> None:
        calls = []

        async def score(desc: str) -> tuple[float, float]:
            calls.append(desc)
            # First candidate is above budget, second accepted.
            return (0.5, 0.5) if len(calls) == 1 else (0.7, 0.2)

        async def mutate(desc: str, _feedback: str, _iteration: float) -> str:
            return f"mutated {desc}"

        opt = MCPImplicitOptimizer(
            initial_description="do evil",
            score_fn=score,
            mutate_fn=mutate,
            max_iterations=3,
            mtdr_budget=0.3,
        )
        result = await opt.optimize()
        assert not result.converged  # ASR target default 0.8 not reached
        assert result.best_asr == pytest.approx(0.7)
        assert result.best_mtdr == pytest.approx(0.2)

    async def test_requires_score_fn(self) -> None:
        opt = MCPImplicitOptimizer(initial_description="x")
        with pytest.raises(ValueError, match="score_fn"):
            await opt.optimize()

    async def test_history_records_iterations(self) -> None:
        async def score(desc: str) -> tuple[float, float]:
            return 0.6, 0.2

        opt = MCPImplicitOptimizer(
            initial_description="base",
            score_fn=score,
            max_iterations=2,
            asr_target=1.0,
        )
        result = await opt.optimize()
        assert len(result.history) == 3  # iteration 0 + 2 mutations
