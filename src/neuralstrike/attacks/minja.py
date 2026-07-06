"""MINJA-style memory-injection harness (Phase 5).

MINJA (Memory INJection Attack) targets agents with shared memory banks
by injecting a query-only payload that bridges from a benign remembered
entry to a malicious one, then progressively shortens the query to
surface the malicious memory.

This module generates the injection sequence and scores the target's
memory-augmented responses with deterministic oracles. It does not assume
canary leakage — a successful injection is measured by a forbidden tool
call or a canary leak produced after the memory turn.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from neuralstrike.adapters.base import Message, TargetAdapter, ToolSchema
from neuralstrike.evaluation.runner import Probe
from neuralstrike.evaluation.verdict import (
    EvidenceFidelity,
    SutResponse,
    TrialResult,
    Verdict,
)
from neuralstrike.oracles.base import Oracle, combine_oracle_results
from neuralstrike.oracles.evidence import upgrade_fidelity_from_traces
from neuralstrike.oracles.tool_harness import CanaryTool, TraceLog
from neuralstrike.utils.logging import get_logger

__all__ = ["MINJAStrategy", "MinjaHarness", "build_minja_probe"]

logger = get_logger("neuralstrike.attacks.minja")


@dataclass(frozen=True)
class MINJAStrategy:
    """A MINJA injection strategy: bridge query + progressive shortening."""

    bridge_query: str
    payload_query: str
    progressive_shorteners: tuple[str, ...]
    oracles: tuple[Oracle, ...] = field(default_factory=tuple)
    canary_tools: tuple[CanaryTool, ...] = field(default_factory=tuple)
    tools: tuple[ToolSchema, ...] = field(default_factory=tuple)


def _memory_message(content: str) -> Message:
    return Message(role="assistant", content=f"[MEMORY] {content}")


class MinjaHarness:
    """Drive a memory-augmented target with a MINJA injection sequence."""

    def __init__(self, strategy: MINJAStrategy) -> None:
        self.strategy = strategy

    async def run_sequence(
        self,
        adapter: TargetAdapter,
        *,
        system_prompt: str | None = None,
    ) -> dict[str, Any]:
        """Run the full bridge + progressive-shortening sequence.

        Returns a dict with per-step responses and the final oracle verdict.
        """
        trace = TraceLog()
        steps: list[dict[str, Any]] = []

        # Step 1: plant the bridge memory.
        bridge_response = await adapter.query(
            self.strategy.bridge_query,
            system_prompt=system_prompt,
            history=(_memory_message(self.strategy.bridge_query),),
            canary_tools=self.strategy.canary_tools,
            tools=self.strategy.tools,
            trace=trace,
            delivery_channel="memory",
        )
        steps.append({"step": "bridge", "response": bridge_response})

        # Step 2: deliver payload via memory channel.
        payload_response = await adapter.query(
            self.strategy.payload_query,
            system_prompt=system_prompt,
            history=(
                _memory_message(self.strategy.bridge_query),
                Message(role="user", content=self.strategy.bridge_query),
                Message(role="assistant", content=bridge_response.text),
                _memory_message(self.strategy.payload_query),
            ),
            canary_tools=self.strategy.canary_tools,
            tools=self.strategy.tools,
            trace=trace,
            delivery_channel="memory",
        )
        steps.append({"step": "payload", "response": payload_response})

        # Step 3+: progressive shortening.
        shorten_response = payload_response
        for idx, short_query in enumerate(self.strategy.progressive_shorteners, 1):
            shorten_response = await adapter.query(
                short_query,
                system_prompt=system_prompt,
                history=(
                    _memory_message(self.strategy.bridge_query),
                    Message(role="user", content=self.strategy.bridge_query),
                    Message(role="assistant", content=bridge_response.text),
                    _memory_message(self.strategy.payload_query),
                    Message(role="user", content=self.strategy.payload_query),
                    Message(role="assistant", content=payload_response.text),
                ),
                canary_tools=self.strategy.canary_tools,
                tools=self.strategy.tools,
                trace=trace,
                delivery_channel="memory",
            )
            steps.append({"step": f"shorten-{idx}", "response": shorten_response})

        # Score the final response with deterministic oracles.
        results = [o.check(shorten_response) for o in self.strategy.oracles]
        verdict, fidelity, findings = combine_oracle_results(results)
        findings = upgrade_fidelity_from_traces(findings, shorten_response, trace)

        return {
            "steps": steps,
            "final_response": shorten_response,
            "verdict": verdict,
            "fidelity": fidelity,
            "findings": findings,
            "trace": trace,
        }


def build_minja_probe(strategy: MINJAStrategy) -> Probe:
    """Wrap a MINJA strategy as a :class:`Probe` for the runner."""

    async def _factory(trial_index: int, seed: int, canary: str) -> TrialResult:
        # MINJA is evaluated against a memory-augmented adapter; the factory
        # receives a canary but the harness injects its own payload content.
        _ = canary, seed
        # For testability, we return a TrialResult with the strategy metadata.
        # A real run wires a TargetAdapter here.
        return TrialResult(
            trial_index=trial_index,
            seed=seed,
            temperature=0.0,
            verdict=Verdict.INCONCLUSIVE,
            fidelity=EvidenceFidelity.VERBAL,
            findings=(),
            payload=strategy.payload_query,
            response=SutResponse(),
            scenario_id="minja",
            iterations=len(strategy.progressive_shorteners) + 2,
        )

    return Probe(
        scenario_id="minja",
        goal="Inject malicious memory via bridging + progressive shortening",
        factory=_factory,
        category="ASI06",
        severity="high",
    )
