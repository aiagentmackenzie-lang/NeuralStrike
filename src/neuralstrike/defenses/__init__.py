"""Defensive-pattern testing — the defensive half of Phase 4.

Two families:

- **Payload-transform defenses** (instruction_hierarchy, spotlighting, struq,
  camel, delimiter, sandwiching, injection_detector, tool_filter) wrap the
  adversarial payload the way a defended SUT would. Measure the ASR delta
  with :func:`measure_defense_delta`.
- **Static checkers** (lethal_trifecta, rule_of_two) flag an unsafe
  deployment pre-launch; they return a :class:`RiskAssessment`, not a
  payload transform.
"""

from __future__ import annotations

from neuralstrike.defenses.base import (
    CHECKERS,
    DEFENSES,
    Checker,
    Defense,
    DefenseContext,
    RiskAssessment,
    apply_defense,
    get_checker,
    get_defense,
    list_checkers,
    list_defenses,
)
from neuralstrike.defenses.checkers import (
    LethalTrifectaChecker,
    RuleOfTwoChecker,
    RuleOfTwoFlags,
    TrifectaFlags,
)
from neuralstrike.defenses.defenses import (  # noqa: F401 (registers via decorator)
    CaMeLDefense,
    DelimiterDefense,
    InjectionDetectorDefense,
    InstructionHierarchyDefense,
    SandwichingDefense,
    SpotlightingDefense,
    StruQDefense,
    ToolFilterDefense,
)
from neuralstrike.defenses.harness import DefenseDelta, measure_defense_delta

__all__ = [
    "CHECKERS",
    "DEFENSES",
    "Checker",
    "Defense",
    "DefenseContext",
    "DefenseDelta",
    "LethalTrifectaChecker",
    "RiskAssessment",
    "RuleOfTwoChecker",
    "RuleOfTwoFlags",
    "SpotlightingDefense",
    "TrifectaFlags",
    "apply_defense",
    "get_checker",
    "get_defense",
    "list_checkers",
    "list_defenses",
    "measure_defense_delta",
]
