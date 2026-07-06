"""Static pre-deployment checkers — flag an unsafe deployment before shipping.

These do NOT transform a payload; they assess a deployment configuration
and return a :class:`~neuralstrike.defenses.base.RiskAssessment`. They are
the "should we even run this against a live target?" gate.

- :class:`LethalTrifectaChecker` — the lethal trifecta: a deployment that
  combines (1) access to private data, (2) ingestion of untrusted content,
  AND (3) an external-communications channel. Any two are manageable; all
  three together is the pre-deployment red flag.
- :class:`RuleOfTwoChecker` — Meta's Rule of Two: a privileged operation
  must not combine an untrusted input with a privileged action. The Noma
  critique (that the rule alone is insufficient against indirect
  injection) is recorded: the checker flags the deployment but does not
  claim it is safe — it returns the residual risk honestly.
"""

from __future__ import annotations

from dataclasses import dataclass

from neuralstrike.defenses.base import (
    Checker,
    DefenseContext,
    RiskAssessment,
    register_checker,
)

__all__ = ["LethalTrifectaChecker", "RuleOfTwoChecker", "RuleOfTwoFlags", "TrifectaFlags"]


@dataclass(frozen=True)
class TrifectaFlags:
    """The three lethal-trifecta conditions, each independently inspectable."""

    has_private_data: bool
    has_untrusted_content: bool
    has_external_comms: bool

    @property
    def is_lethal(self) -> bool:
        """``True`` iff all three conditions are present (the lethal trifecta)."""
        return self.has_private_data and self.has_untrusted_content and self.has_external_comms


@register_checker
class LethalTrifectaChecker(Checker):
    """Pre-deployment check for the lethal trifecta."""

    name = "lethal_trifecta"
    description = "Flag a deployment combining private data + untrusted content + external comms."

    def assess(self, context: DefenseContext) -> RiskAssessment:
        # The caller packs the three booleans into context.tools as a 3-tuple in
        # the documented order (private_data, untrusted_content, external_comms).
        flags = self._flags(context)
        reasons: list[str] = []
        if flags.has_private_data:
            reasons.append("private-data access present")
        if flags.has_untrusted_content:
            reasons.append("ingests untrusted content")
        if flags.has_external_comms:
            reasons.append("has external-communications channel")
        if flags.is_lethal:
            reasons.append("LETHAL TRIFECTA: all three conditions present — do not ship without mitigations")
        else:
            reasons.append("no lethal trifecta (fewer than three conditions)")
        return RiskAssessment(
            checker=self.name,
            safe=not flags.is_lethal,
            reasons=tuple(reasons),
            evidence=tuple(reasons),
        )

    def _flags(self, context: DefenseContext) -> TrifectaFlags:
        if len(context.tools) >= 3:
            priv, untrusted, comms = bool(context.tools[0]), bool(context.tools[1]), bool(context.tools[2])
        else:
            priv = untrusted = comms = False
        return TrifectaFlags(priv, untrusted, comms)


@dataclass(frozen=True)
class RuleOfTwoFlags:
    """Meta Rule of Two: an untrusted input combined with a privileged action."""

    has_untrusted_input: bool
    has_privileged_action: bool

    @property
    def violates(self) -> bool:
        return self.has_untrusted_input and self.has_privileged_action


@register_checker
class RuleOfTwoChecker(Checker):
    """Meta Rule of Two pre-deployment check (with the Noma-critique caveat).

    The Rule of Two says a privileged operation must not combine an untrusted
    input with a privileged action. Noma et al. critiqued this: the rule alone
    is insufficient against *indirect* prompt injection, because "untrusted
    input" is not always obvious (retrieved documents, tool results). This
    checker flags the violation AND records the residual risk honestly — it
    never claims a passing deployment is safe against indirect injection.
    """

    name = "rule_of_two"
    description = "Meta Rule of Two: untrusted input + privileged action = violation (Noma caveat recorded)."

    def assess(self, context: DefenseContext) -> RiskAssessment:
        if len(context.tools) >= 2:
            untrusted, privileged = bool(context.tools[0]), bool(context.tools[1])
        else:
            untrusted = privileged = False
        flags = RuleOfTwoFlags(untrusted, privileged)
        reasons: list[str] = []
        if flags.violates:
            reasons.append("Rule of Two VIOLATION: untrusted input combined with a privileged action")
            # Noma critique: even a non-violating deployment is not proven safe
            # against indirect injection — record the residual risk honestly.
            reasons.append("Noma caveat: passing this check does NOT prove safety against indirect injection")
        else:
            reasons.append("no Rule of Two violation")
            reasons.append("Noma caveat: this check alone does not prove safety against indirect injection")
        return RiskAssessment(
            checker=self.name,
            safe=not flags.violates,
            reasons=tuple(reasons),
            evidence=tuple(reasons),
        )
