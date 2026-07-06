"""Adaptive-attack shared contract: the probe builder + result type.

The three strategies (crescendo / pair / tap) live in their own modules;
this module holds the shared :func:`adaptive_probe` builder that wires an
attacker_fn into the existing
:class:`~neuralstrike.core.adversarial_loop.AdversarialLoop`, and the
``AttackerCall`` / ``JudgeRankCall`` type aliases.

Separation is enforced (roadmap §Phase 4): the attacker **generates**, the
judge **scores** — distinct LLM clients; an attack can never score itself.
The attacker_fn only generates payloads; the loop's deterministic oracles +
advisory Judge do all scoring.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from neuralstrike.core.adversarial_loop import AdversarialLoop, AttackerFn
from neuralstrike.evaluation.probes import trial_from_loop
from neuralstrike.evaluation.runner import Probe
from neuralstrike.evaluation.verdict import TrialResult

__all__ = [
    "AdaptiveAttackResult",
    "AttackerCall",
    "JudgeRankCall",
    "adaptive_probe",
]

# An attacker LLM call: prompt -> refined payload.
AttackerCall = Callable[[str], Awaitable[str]]
# A judge-ranker call: (candidate, goal) -> score in [0.0, 1.0].
JudgeRankCall = Callable[[str, str], Awaitable[float]]


@dataclass
class AdaptiveAttackResult:
    """Summary of one adaptive trial (carries the per-turn refinement trace)."""

    verdict: str
    iterations: int
    final_payload: str
    trace: list[dict[str, Any]] = field(default_factory=list)


def adaptive_probe(
    victim_model: str,
    victim_type: str,
    *,
    oracles: list[Any],
    attacker_fn: AttackerFn,
    goal: str,
    llm: Any | None = None,
    judge_model: str | None = None,
    scenario_id: str = "adaptive",
    category: str = "adaptive",
    severity: str = "high",
    max_iterations: int = 5,
) -> Probe:
    """Build a Probe that runs one adaptive trial through the AdversarialLoop.

    The loop runs attacker -> victim -> oracle (+ advisory Judge) for up to
    ``max_iterations`` turns, stopping early on a SUCCEEDED verdict. The
    attacker_fn only generates; the oracles + Judge score (separation enforced
    by the loop's type-level contract).
    """

    async def _factory(trial_index: int, seed: int, canary: str) -> TrialResult:
        loop = AdversarialLoop(
            victim_model=victim_model,
            victim_type=victim_type,
            llm=llm,
            oracles=list(oracles),
            judge_model=judge_model,
            seed=seed,
            victim_temperature=0.0,
            attacker_fn=attacker_fn,
        )
        loop_result = await loop.execute_cycle(initial_goal=goal, max_iterations=max_iterations)
        return trial_from_loop(
            scenario_id=scenario_id,
            trial_index=trial_index,
            seed=seed,
            temperature=0.0,
            loop_result=loop_result,
        )

    return Probe(
        scenario_id=scenario_id,
        goal=goal,
        factory=_factory,
        category=category,
        severity=severity,
    )
