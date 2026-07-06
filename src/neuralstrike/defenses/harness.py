"""The defense-delta harness — measure ASR with vs without a defense.

Phase-4 exit gate, bullet 3: "a spotlighting defense reduces ASR on the
same corpus by a measured delta (the harness reports both, not just the
attack)." This module runs each scenario's payload against a victim
**with** and **without** the defense applied and returns both ASRs + the
delta, so a reviewer sees the defensive effect, not only the attack.

The harness is transport-agnostic: it takes an async ``victim_fn(payload)
-> str`` (the SUT under test) and the loaded corpus scenarios. For each
scenario it mints a per-run canary, builds the payload, scores the
baseline and defended responses with the scenario's deterministic
oracles, and aggregates conclusive-only ASR for both arms.
"""

from __future__ import annotations

import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from neuralstrike.corpus.loader import Scenario
from neuralstrike.defenses.base import Defense
from neuralstrike.evaluation.verdict import SutResponse, Verdict
from neuralstrike.oracles.base import combine_oracle_results
from neuralstrike.oracles.canary import mint_canary

__all__ = ["DefenseDelta", "ScenarioArmResult", "measure_defense_delta"]

VictimFn = Callable[[str], Awaitable[str]]


@dataclass(frozen=True)
class ScenarioArmResult:
    """One scenario's verdict in one arm (baseline or defended)."""

    scenario_id: str
    baseline_verdict: Verdict
    defended_verdict: Verdict


@dataclass(frozen=True)
class DefenseDelta:
    """The measured ASR with vs without a defense, plus the per-scenario detail."""

    defense: str
    baseline_asr: float
    defended_asr: float
    delta: float
    """``baseline_asr - defended_asr``; positive means the defense reduced ASR."""

    baseline_succeeded: int
    baseline_conclusive: int
    defended_succeeded: int
    defended_conclusive: int
    scenarios: tuple[ScenarioArmResult, ...] = field(default_factory=tuple)

    @property
    def headline(self) -> str:
        return (
            f"{self.defense}: baseline ASR={self.baseline_asr:.1%} -> "
            f"defended ASR={self.defended_asr:.1%} (delta={self.delta:+.1%}, "
            f"{self.baseline_succeeded}/{self.baseline_conclusive} -> "
            f"{self.defended_succeeded}/{self.defended_conclusive})"
        )


async def measure_defense_delta(
    defense: Defense,
    victim_fn: VictimFn,
    scenarios: list[Scenario],
    *,
    seed: int = 0,
    rng: secrets.SystemRandom | None = None,
) -> DefenseDelta:
    """Run each scenario with and without ``defense``; return both ASRs + delta.

    The same canary, victim, and oracles are used in both arms — the ONLY
    difference is whether the defense wraps the payload. So the delta is
    honestly attributable to the defense.
    """
    r = rng or secrets.SystemRandom()
    arms: list[ScenarioArmResult] = []
    bl_succ = bl_concl = df_succ = df_concl = 0

    for scenario in scenarios:
        canary = mint_canary(rng=r)
        payload = scenario.payload_for(canary)
        oracles = scenario.build_oracles(canary)

        # Baseline arm: raw payload.
        base_text = await victim_fn(payload)
        base_resp = SutResponse.from_text(base_text)
        bv, _, _ = combine_oracle_results([o.check(base_resp) for o in oracles])

        # Defended arm: defense-wrapped payload (same canary, same oracles).
        defended_payload = defense.apply(payload)
        def_text = await victim_fn(defended_payload)
        def_resp = SutResponse.from_text(def_text)
        dv, _, _ = combine_oracle_results([o.check(def_resp) for o in oracles])

        arms.append(ScenarioArmResult(scenario.id, bv, dv))
        if bv is Verdict.SUCCEEDED:
            bl_succ += 1
        if bv.is_conclusive:
            bl_concl += 1
        if dv is Verdict.SUCCEEDED:
            df_succ += 1
        if dv.is_conclusive:
            df_concl += 1

    baseline_asr = (bl_succ / bl_concl) if bl_concl else 0.0
    defended_asr = (df_succ / df_concl) if df_concl else 0.0
    return DefenseDelta(
        defense=defense.name,
        baseline_asr=baseline_asr,
        defended_asr=defended_asr,
        delta=baseline_asr - defended_asr,
        baseline_succeeded=bl_succ,
        baseline_conclusive=bl_concl,
        defended_succeeded=df_succ,
        defended_conclusive=df_concl,
        scenarios=tuple(arms),
    )
