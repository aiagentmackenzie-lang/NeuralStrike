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

__all__ = [
    "CAUGHT_VERDICTS",
    "AttackChainDelta",
    "AttackChainPayload",
    "AttackPhase",
    "BundledNeuralGuardFixture",
    "NeuralGuardHTTPScreen",
    "NeuralGuardScreen",
    "PhaseResult",
    "ScreenResult",
    "canonical_attack_chain",
    "in_process_screen",
    "neuralguard_available",
    "run_attack_chain_delta",
]
