"""Defensive-pattern testing — the defensive half of Phase 4.

NeuralStrike is a red-team tool, but Phase 4 ships the *defensive* half too:
test the published defenses the field actually ships, not just attack past
them. A :class:`Defense` is a payload transform that wraps/sanitizes the
adversarial payload the way a defended SUT would, so a run can measure the
ASR delta with vs without the defense (the harness reports both, not just
the attack — roadmap §Phase 4 exit gate, bullet 3).

Two families:

- **Payload-transform defenses** (instruction-hierarchy, spotlighting,
  StruQ, CaMeL, AgentDojo delimiters / sandwiching / detector / tool-filter)
  implement :meth:`Defense.apply` and are measured by
  :func:`measure_defense_delta`.
- **Static checkers** (lethal-trifecta, Meta Rule of Two) implement
  :meth:`Checker.assess` and return a :class:`RiskAssessment` for
  pre-deployment review (they don't transform a payload; they flag a
  deployment that is unsafe to ship).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "CHECKERS",
    "DEFENSES",
    "Checker",
    "Defense",
    "RiskAssessment",
    "apply_defense",
    "get_checker",
    "get_defense",
    "list_checkers",
    "list_defenses",
]


@dataclass(frozen=True)
class DefenseContext:
    """The context a defense may need to apply itself.

    ``system_prompt`` is the SUT's base system prompt (some defenses prepend
    an instruction-hierarchy directive to it); ``tools`` is the tool surface
    (a tool-filter defense may restrict it). Both optional.
    """

    system_prompt: str | None = None
    tools: tuple[Any, ...] = ()


class Defense(ABC):
    """A payload-transform defense (wraps/sanitizes the adversarial payload)."""

    name: str = ""
    description: str = ""

    @abstractmethod
    def apply(self, payload: str, *, context: DefenseContext | None = None) -> str:
        """Return the defended form of ``payload`` the SUT would see."""
        raise NotImplementedError


class Checker(ABC):
    """A static pre-deployment checker (flags an unsafe deployment)."""

    name: str = ""
    description: str = ""

    @abstractmethod
    def assess(self, context: DefenseContext) -> RiskAssessment:
        """Return a risk assessment for the deployment described by ``context``."""
        raise NotImplementedError


@dataclass(frozen=True)
class RiskAssessment:
    """The result of a static checker (lethal trifecta, Rule of Two)."""

    checker: str
    safe: bool
    reasons: tuple[str, ...] = ()
    evidence: tuple[str, ...] = field(default_factory=tuple)

    @property
    def summary(self) -> str:
        flag = "PASS" if self.safe else "FAIL"
        return f"[{self.checker}] {flag}: " + ("; ".join(self.reasons) or "no reasons")


_DEFENSES: dict[str, Defense] = {}
_CHECKERS: dict[str, Checker] = {}


def register_defense(cls: type[Defense]) -> type[Defense]:
    inst = cls()
    if not inst.name:
        raise RuntimeError(f"Defense subclass {cls.__name__} has no 'name'")
    _DEFENSES[inst.name] = inst
    return cls


def register_checker(cls: type[Checker]) -> type[Checker]:
    inst = cls()
    if not inst.name:
        raise RuntimeError(f"Checker subclass {cls.__name__} has no 'name'")
    _CHECKERS[inst.name] = inst
    return cls


def list_defenses() -> list[str]:
    return sorted(_DEFENSES)


def list_checkers() -> list[str]:
    return sorted(_CHECKERS)


def get_defense(name: str) -> Defense:
    try:
        return _DEFENSES[name]
    except KeyError as exc:
        raise KeyError(f"unknown defense {name!r}; registered: {list_defenses()}") from exc


def get_checker(name: str) -> Checker:
    try:
        return _CHECKERS[name]
    except KeyError as exc:
        raise KeyError(f"unknown checker {name!r}; registered: {list_checkers()}") from exc


def apply_defense(name: str, payload: str, *, context: DefenseContext | None = None) -> str:
    return get_defense(name).apply(payload, context=context)


# Public read-only views (registration via @register_defense / @register_checker only).
from types import MappingProxyType  # noqa: E402

DEFENSES = MappingProxyType(_DEFENSES)
CHECKERS = MappingProxyType(_CHECKERS)
