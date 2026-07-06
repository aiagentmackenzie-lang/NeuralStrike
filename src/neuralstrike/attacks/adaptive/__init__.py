"""Adaptive attacks — Crescendo, PAIR, TAP.

An *adaptive* attack refines its payload across turns from the target's
replies, where a *static* attack sends one fixed payload. The field's
hardest class (Nasr/Carlini: static ASR ~0% vs adaptive >90%) lives here.

Separation is enforced (roadmap §Phase 4): the attacker **generates**, the
judge **scores** — distinct LLM clients; an attack can never score itself.
These modules produce *attacker_fn* factories (the refinement strategy)
plus :func:`adaptive_probe` that wires them into the existing
:class:`~neuralstrike.core.adversarial_loop.AdversarialLoop`.

- :mod:`crescendo` — linear multi-turn escalation; scripted ladder fallback.
- :mod:`pair` — Chao et al. 2023; refine one jailbreak per turn. Requires
  an attacker LLM.
- :mod:`tap` — Mehrotra et al. 2023; branch K candidates, judge-rank, keep
  the best (simplified beam=1). Requires an attacker LLM + judge-ranker.
"""

from __future__ import annotations

from neuralstrike.attacks.adaptive.base import (
    AdaptiveAttackResult,
    AttackerCall,
    JudgeRankCall,
    adaptive_probe,
)
from neuralstrike.attacks.adaptive.crescendo import crescendo_attacker_fn
from neuralstrike.attacks.adaptive.pair import pair_attacker_fn
from neuralstrike.attacks.adaptive.tap import tap_attacker_fn

__all__ = [
    "AdaptiveAttackResult",
    "AttackerCall",
    "JudgeRankCall",
    "adaptive_probe",
    "crescendo_attacker_fn",
    "pair_attacker_fn",
    "tap_attacker_fn",
]
