"""Operator safety: action classification, TTL scaling, and HITL gating.

The HITL gate follows the Rapid7 pattern: irreversible / destructive actions
require explicit operator approval before they run. Reversible actions get
shorter TTLs; irreversible actions get longer TTLs (or are blocked pending
approval).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from neuralstrike.core.exceptions import ValidationError


class ActionClass(Enum):
    """Classification of an attack action's blast radius."""

    REVERSIBLE = "reversible"
    COMPENSABLE = "compensable"
    IRREVERSIBLE = "irreversible"


class SafetyError(ValidationError):
    """Raised when a safety / HITL gate blocks an action."""


# Keywords that move an action up the blast-radius scale.
_IRREVERSIBLE_HINTS = frozenset(
    {"delete", "destroy", "drop", "wipe", "revoke", "terminate", "exfil", "transfer", "pay", "purchase"}
)
_COMPENSABLE_HINTS = frozenset(
    {"modify", "update", "write", "create", "grant", "admin", "enable", "disable", "send"}
)


def classify_intent(intent: str | None) -> ActionClass:
    """Classify an attack intent by keyword matching.

    The mapping is conservative: if any irreversible keyword is present, the
    action is treated as irreversible. Case-insensitive.
    """
    if not intent:
        return ActionClass.REVERSIBLE
    lowered = intent.lower()
    words = frozenset(lowered.replace("-", " ").replace("_", " ").split())
    if words & _IRREVERSIBLE_HINTS:
        return ActionClass.IRREVERSIBLE
    if words & _COMPENSABLE_HINTS:
        return ActionClass.COMPENSABLE
    return ActionClass.REVERSIBLE


def ttl_for(action_class: ActionClass) -> int:
    """Suggested operator-approval TTL in seconds per action class."""
    return {
        ActionClass.REVERSIBLE: 60,
        ActionClass.COMPENSABLE: 300,
        ActionClass.IRREVERSIBLE: 0,  # never auto-approved
    }[action_class]


@dataclass(frozen=True)
class HITLGate:
    """Human-in-the-loop approval gate."""

    action_class: ActionClass
    intent: str | None = None
    approved: bool = False

    def assert_approved(self) -> None:
        """Fail closed if an irreversible action lacks explicit approval."""
        if self.action_class != ActionClass.IRREVERSIBLE:
            return
        if self.approved:
            return
        intent_label = self.intent or "(unspecified)"
        raise SafetyError(
            f"irreversible action {intent_label!r} requires --require-approval; "
            "refusing to run without explicit operator consent (fail-closed)"
        )

    def summary(self) -> dict[str, Any]:
        return {
            "intent": self.intent,
            "action_class": self.action_class.value,
            "approved": self.approved,
            "ttl_seconds": ttl_for(self.action_class),
        }
