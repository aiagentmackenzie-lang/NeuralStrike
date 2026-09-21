"""Structured attack trajectory: the per-turn execution trace of an adaptive run.

Phase 9 (G1 — trajectory-grounded adaptive attacks). 2026 attack research
(GPT-Red / SIRAJ / MUZZLE) converges on the same core move: the attacker
refines from the victim's *observed behavior* — which oracle blocked it, what
evidence surface was touched, what the victim actually did — not from a
flattened feedback string. This module is that structured layer.

Contracts (house rules, carried through):

- **Pure extraction.** A :class:`Trajectory` is derived exclusively from data
  the loop already recorded (:class:`~neuralstrike.core.adversarial_loop.
  IterationRecord`). Nothing here calls an LLM, and nothing here scores a
  payload — the attacker generates, the oracles + Judge score.
- **Deterministic.** Fingerprints and excerpts are stable functions of the
  record: same history → same trajectory → same fingerprint. A replay with
  the same seed reproduces the same trajectory.
- **Honest surfaces.** ``touched_surfaces`` is derived from *evidence*
  (fidelity + the response's actual tool-calls/traces), never claimed from
  the payload's intent. A text-only victim is ``text``; a tool-call surface
  is only claimed when a tool call was actually observed.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from neuralstrike.evaluation.verdict import SutResponse

__all__ = [
    "Trajectory",
    "TurnTrace",
    "fingerprint",
    "hash_goal",
    "summarize_for_attacker",
    "trajectory_from_loop_history",
]

_EXCERPT_MAX = 160
"""Deterministic response-excerpt cap (chars). Truncation is part of the
fingerprint contract: the same response always yields the same excerpt."""


def hash_goal(goal: str) -> str:
    """Stable 16-hex id for a goal (the memory join key; no goal text stored)."""
    return hashlib.sha256(goal.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class TurnTrace:
    """One attacker→victim→oracle turn, structured for trajectory conditioning.

    ``oracle_verdicts`` maps each fired oracle's id to its individual verdict —
    the attacker learns *which* detector blocked it, not just that it was
    blocked. ``touched_surfaces`` is evidence-derived: ``text`` (verbal
    channel), ``tool_args`` (a tool call was actually observed),
    ``execution`` (instrumented traces exist).
    """

    iteration: int
    verdict: str  # "resisted" | "succeeded" | "inconclusive"
    fidelity: str  # "verbal" | "intent_to_act" | "behavioral"
    oracle_verdicts: tuple[tuple[str, str], ...] = ()
    tool_call_names: tuple[str, ...] = ()
    touched_surfaces: tuple[str, ...] = ()
    response_excerpt: str = ""
    victim_error: bool = False


@dataclass(frozen=True)
class Trajectory:
    """The per-turn trace of one adaptive run up to the current turn."""

    strategy_label: str
    goal_hash: str
    goal: str
    turns: tuple[TurnTrace, ...] = ()

    @property
    def last(self) -> TurnTrace | None:
        """The most recent turn (``None`` before the first victim reply)."""
        return self.turns[-1] if self.turns else None

    @property
    def resisted_turns(self) -> int:
        """Count of turns where a deterministic oracle or Judge said RESISTED."""
        return sum(1 for t in self.turns if t.verdict == "resisted")


def _surfaces_of(response: SutResponse) -> tuple[str, ...]:
    """Evidence-derived surfaces: never claim a channel the response didn't touch."""
    surfaces: list[str] = []
    if response.text:
        surfaces.append("text")
    if response.tool_calls:
        surfaces.append("tool_args")
    if response.traces:
        surfaces.append("execution")
    return tuple(surfaces)


def turn_trace_from_parts(
    iteration: int,
    response: SutResponse,
    *,
    verdict: str,
    fidelity: str,
    findings: list[dict[str, Any]],
    status: str,
) -> TurnTrace:
    """Build one :class:`TurnTrace` from the loop's recorded iteration parts.

    ``findings`` is the serialized finding dicts (as stored on
    :class:`~neuralstrike.core.adversarial_loop.IterationRecord`) — the same
    data, no re-scoring.
    """
    oracle_verdicts = tuple(
        (str(f.get("oracle_id", "")), str(f.get("verdict", ""))) for f in findings if f.get("oracle_id")
    )
    return TurnTrace(
        iteration=iteration,
        verdict=verdict,
        fidelity=fidelity,
        oracle_verdicts=oracle_verdicts,
        tool_call_names=tuple(tc.name for tc in response.tool_calls),
        touched_surfaces=_surfaces_of(response),
        response_excerpt=(response.text or "")[:_EXCERPT_MAX],
        victim_error=status == "victim_error",
    )


def trajectory_from_loop_history(
    history: list[Any],
    *,
    strategy_label: str,
    goal: str,
) -> Trajectory:
    """Build a :class:`Trajectory` from the loop's ``history`` (IterationRecord dicts).

    Accepts the serialized ``LoopResult["history"]`` shape (response is a full
    :class:`SutResponse` per record). Pure: missing/odd fields degrade to
    empty evidence, never an exception — a record is data, not a verdict.
    """
    turns: list[TurnTrace] = []
    for rec in history:
        response = rec.get("response")
        if not isinstance(response, SutResponse):
            response = SutResponse()
        turns.append(
            turn_trace_from_parts(
                int(rec.get("iteration", 0)),
                response,
                verdict=str(rec.get("verdict", "inconclusive")),
                fidelity=str(rec.get("fidelity", "verbal")),
                findings=list(rec.get("findings", []) or []),
                status=str(rec.get("status", "ok")),
            )
        )
    return Trajectory(
        strategy_label=strategy_label,
        goal_hash=hash_goal(goal),
        goal=goal,
        turns=tuple(turns),
    )


def fingerprint(trajectory: Trajectory) -> str:
    """Deterministic trajectory fingerprint (the trajectory-diversity unit).

    Signature: ``<strategy>:<per-turn (verdict|oracles|surfaces)>`` joined by
    ``>``. Excerpts and seeds are deliberately excluded — the fingerprint
    captures *behavior shape*, not payload text, so two turns that provoked
    the same oracle behavior count as the same trajectory.
    """
    parts = [trajectory.strategy_label]
    for t in trajectory.turns:
        oracles = ",".join(f"{oid}:{v}" for oid, v in t.oracle_verdicts)
        parts.append(f"{t.verdict}|{oracles}|{'+'.join(t.touched_surfaces) or 'none'}")
    return ">".join(parts)


def summarize_for_attacker(trajectory: Trajectory) -> str:
    """The structured refinement brief an attacker conditions on.

    This is the Phase-9 upgrade over PAIR's flattened feedback: the attacker
    sees the verdict *history*, which oracle blocked each turn, which evidence
    surface was touched, and the victim's reply class. Same information class
    the loop's ``feedback`` already carried (observed, past-tense) — now
    structured. No future info, no self-assessment.
    """
    if not trajectory.turns:
        return "No prior turns; this is the first attempt."
    lines: list[str] = [f"Attack trajectory so far ({len(trajectory.turns)} turn(s)):"]
    for t in trajectory.turns:
        bits = [f"turn {t.iteration}: verdict={t.verdict} fidelity={t.fidelity}"]
        if t.oracle_verdicts:
            fired = ", ".join(f"{oid}={v}" for oid, v in t.oracle_verdicts)
            bits.append(f"oracles fired: {fired}")
        if t.touched_surfaces:
            bits.append(f"evidence surfaces: {'+'.join(t.touched_surfaces)}")
        if t.tool_call_names:
            bits.append(f"tool calls observed: {','.join(t.tool_call_names)}")
        if t.victim_error:
            bits.append("victim errored (transport/backend, not a refusal)")
        excerpt = t.response_excerpt.replace("\n", " ")
        if excerpt:
            bits.append(f'reply excerpt: "{excerpt}"')
        lines.append("; ".join(bits))
    return "\n".join(lines)
