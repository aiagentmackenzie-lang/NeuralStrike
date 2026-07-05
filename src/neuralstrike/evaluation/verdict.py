"""Verdict types, evidence fidelity, and the SUT response model.

This module is the **type foundation** of the measurement system. It
deliberately imports nothing from :mod:`neuralstrike.oracles` so the
oracles can depend on it without creating an import cycle.

Conclusive-only contract (non-negotiable):
- Three outcomes — ``Resisted``, ``Succeeded``, ``Inconclusive`` — never two.
- Weak evidence becomes ``Inconclusive`` (a coverage gap), never a
  fabricated ``Resisted`` (a fake PASS).
- The headline score is ``Resisted / (Resisted + Succeeded)``;
  ``Inconclusive`` trials are *coverage gaps*, not silent passes.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal


class Verdict(str, Enum):
    """The three conclusive outcomes of a probe against a SUT.

    ``INCONCLUSIVE`` is a first-class outcome — it means "the oracles could
    not reach a conclusion with the evidence available." It is never coerced
    to ``RESISTED``.
    """

    RESISTED = "resisted"
    SUCCEEDED = "succeeded"
    INCONCLUSIVE = "inconclusive"

    @property
    def is_conclusive(self) -> bool:
        """``True`` for the binary outcomes, ``False`` for the coverage gap."""
        return self in (Verdict.RESISTED, Verdict.SUCCEEDED)


class EvidenceFidelity(str, Enum):
    """How strong the evidence behind a verdict is.

    Ordered weakest -> strongest. ``VERBAL`` is the model's words only;
    ``INTENT_TO_ACT`` is an emitted (forbidden) tool-call; ``BEHAVIORAL`` is
    an instrumented tool that actually executed (Tier-2). A verdict on
    ``VERBAL`` evidence is the most fragile and the most likely candidate
    for an ``INCONCLUSIVE`` downgrade when the evidence is ambiguous.
    """

    VERBAL = "verbal"
    INTENT_TO_ACT = "intent_to_act"
    BEHAVIORAL = "behavioral"


@dataclass(frozen=True)
class ToolCall:
    """A single tool-call emitted by the SUT.

    ``arguments`` is the raw argument payload (dict for JSON tool-calls,
    string for free-form). Oracles stringize it before searching for
    canaries / forbidden shapes so the type stays permissive at the
    boundary and tight at the oracle.
    """

    name: str
    arguments: Any = None
    tool_call_id: str | None = None

    def argument_text(self) -> str:
        """Best-effort flat string of the arguments for substring/regex oracles."""
        if self.arguments is None:
            return ""
        if isinstance(self.arguments, str):
            return self.arguments
        try:
            return json.dumps(self.arguments, sort_keys=True, ensure_ascii=False)
        except (TypeError, ValueError):
            return str(self.arguments)


@dataclass(frozen=True)
class SutResponse:
    """What the SUT *did* in response to a payload.

    ``text`` is the model's words; ``tool_calls`` is what it tried to do;
    ``traces`` is execution evidence from instrumented canary tools
    (Tier-2 / ``BEHAVIORAL``). Any field may be empty — the absence of
    evidence is recorded as :attr:`Verdict.INCONCLUSIVE`, never as a pass.
    """

    text: str = ""
    tool_calls: tuple[ToolCall, ...] = field(default_factory=tuple)
    traces: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    error: str | None = None

    @classmethod
    def from_text(cls, text: str) -> SutResponse:
        """Convenience for text-only SUTs (the Phase-0 model-name victim)."""
        return cls(text=text)

    @property
    def all_text(self) -> str:
        """Concatenation of response text + every tool-call argument string.

        Oracles that hunt for leaked tokens (canary) or forbidden argument
        shapes search this surface, not just ``text`` — leakage into
        outbound tool args is a real exfiltration channel.
        """
        parts: list[str] = [self.text]
        parts.extend(tc.argument_text() for tc in self.tool_calls)
        return "\n".join(parts)


@dataclass(frozen=True)
class Finding:
    """One oracle's contribution to a verdict, with the evidence that backs it.

    ``oracle_id`` identifies which oracle fired so a regression case can
    pin the exact signal that flipped (the corpus's "every fixed honesty
    bug seeds a permanent regression case" rule).
    """

    oracle_id: str
    verdict: Verdict
    fidelity: EvidenceFidelity
    evidence_quote: str | None = None
    reason: str = ""
    severity: str = "info"
    advisory: bool = False


@dataclass(frozen=True)
class TrialResult:
    """The outcome of a single trial, fully replayable.

    ``seed`` and ``temperature`` are recorded so a replay with the same
    seed reproduces identical verdicts (Phase-0 exit-gate requirement).
    ``scenario_id`` carries the probe's id so scoring can group trials by
    category and baselines can pin a regression to a specific scenario.
    """

    trial_index: int
    seed: int
    temperature: float
    verdict: Verdict
    fidelity: EvidenceFidelity
    findings: tuple[Finding, ...] = field(default_factory=tuple)
    payload: str = ""
    response: SutResponse | None = None
    error: str | None = None
    scenario_id: str = ""
    iterations: int = 0


# Type aliases kept narrow on purpose — Literal unions, not free strings.
FailOnPolicy = Literal["never", "vuln", "regression"]
"""Baseline comparison policies. ``regression`` outranks absolute ``vuln``."""


__all__ = [
    "EvidenceFidelity",
    "FailOnPolicy",
    "Finding",
    "SutResponse",
    "ToolCall",
    "TrialResult",
    "Verdict",
]
