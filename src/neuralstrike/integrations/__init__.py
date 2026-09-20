"""Cross-project integrations (Phase 7).

The NeuralGuard pairing — NeuralStrike generates attacks, NeuralGuard
screens them. The offensive half meets the defensive half.

* :mod:`neuralstrike.integrations.neuralguard` — firewall screens
  (HTTP client, bundled fixture, optional in-process NeuralGuard).
* :mod:`neuralstrike.integrations.attack_chain` — the canonical
  recon -> weaponize -> exploit -> post-ex attack-chain delta runner.
"""

from neuralstrike.integrations.attack_chain import (
    AttackChainDelta,
    AttackChainPayload,
    AttackPhase,
    PhaseResult,
    canonical_attack_chain,
    run_attack_chain_delta,
)
from neuralstrike.integrations.neuralguard import (
    CAUGHT_VERDICTS,
    BundledNeuralGuardFixture,
    NeuralGuardHTTPScreen,
    NeuralGuardScreen,
    ScreenResult,
    in_process_screen,
    neuralguard_available,
)
from neuralstrike.integrations.scarletai import (
    SCARLETAI_SOURCE,
    ExerciseTelemetry,
    post_events,
)

__all__ = [
    "CAUGHT_VERDICTS",
    "SCARLETAI_SOURCE",
    "AttackChainDelta",
    "AttackChainPayload",
    "AttackPhase",
    "BundledNeuralGuardFixture",
    "ExerciseTelemetry",
    "NeuralGuardHTTPScreen",
    "NeuralGuardScreen",
    "PhaseResult",
    "ScreenResult",
    "canonical_attack_chain",
    "in_process_screen",
    "neuralguard_available",
    "post_events",
    "run_attack_chain_delta",
]
