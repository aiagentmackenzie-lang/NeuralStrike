"""Benchmark pack imports + the pack-probe factory.

This package wires external benchmark datasets (HarmBench,
JailbreakBench, CyberSecEval) and local operator-supplied datasets into
NeuralStrike's runner. The honesty contract (Phase-3 exit gate, bullet 3):

- Pack probes ship **no expected-token oracle** -> verdicts come from the
  advisory Judge (DECIDE role) or, with no Judge, every probe is honestly
  **Inconclusive**. Never a fabricated Resisted/Succeeded.
- **No data is bundled.** Network packs fetch on demand behind
  ``--accept-license``; a local pack (``--import-probes``) skips the gate.

:func:`pack_probe_factory` builds the :class:`~neuralstrike.evaluation.runner.Probe`
that runs one pack probe through the Attacker-Victim-Judge loop with an
empty deterministic-oracle list. The loop's contract guarantees the
no-judge path is Inconclusive (``combine_oracle_results([]) ->
INCONCLUSIVE`` and no Judge to decide), and the with-judge path is a real
Judge verdict.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from neuralstrike.evaluation.probes import trial_from_loop
from neuralstrike.evaluation.runner import Probe
from neuralstrike.evaluation.verdict import TrialResult

if TYPE_CHECKING:
    from neuralstrike.core.llm_manager import LLMManager
    from neuralstrike.oracles.judge import JudgeOracle

__all__ = [
    "PACKS",
    "CyberSecEvalPack",
    "HarmBenchPack",
    "JailbreakBenchPack",
    "LocalPack",
    "Pack",
    "PackProbe",
    "get_pack",
    "list_packs",
    "pack_probe_factory",
]


def pack_probe_factory(
    probe: PackProbe,
    victim_model: str,
    victim_type: str,
    *,
    llm: LLMManager | None = None,
    judge_model: str | None = None,
    judge: JudgeOracle | None = None,
    max_iterations: int = 1,
) -> Probe:
    """Build a :class:`Probe` that scores a pack probe via the Judge (or Inconclusive).

    No deterministic oracle is configured (packs ship none). When
    ``judge_model`` is set, the loop's DECIDE branch runs the advisory
    Judge and its typed verdict is the trial's verdict. When
    ``judge_model`` is ``None``, the loop has no oracle and no Judge ->
    every trial is honestly :attr:`Verdict.INCONCLUSIVE` (a coverage gap),
    never a fabricated pass.
    """
    # Local imports avoid any import-order coupling at package init time.
    from neuralstrike.core.adversarial_loop import AdversarialLoop

    goal = probe.goal

    async def _factory(trial_index: int, seed: int, canary: str) -> TrialResult:
        _ = canary  # pack probes carry no canary; the arg satisfies the TrialFactory contract.
        loop = AdversarialLoop(
            victim_model=victim_model,
            victim_type=victim_type,
            llm=llm,
            oracles=[],  # no deterministic oracle: packs ship no expected-token oracle
            judge_model=judge_model,
            judge=judge,
            seed=seed,
            victim_temperature=0.0,
        )
        # The attacker "payload" for a pack probe is the probe's own prompt;
        # there is no canary to weave in. A static attacker returns it as-is.
        async def _static(_i: int, _g: str, _c: str, _f: str) -> str:
            return probe.prompt

        loop._attacker_fn = _static
        loop_result = await loop.execute_cycle(initial_goal=goal, max_iterations=max_iterations)
        return trial_from_loop(
            scenario_id=probe.id,
            trial_index=trial_index,
            seed=seed,
            temperature=0.0,
            loop_result=loop_result,
        )

    return Probe(
        scenario_id=probe.id,
        goal=goal,
        factory=_factory,
        category=probe.category,
        severity=probe.severity,
    )


# Import the pack implementations so their @register_pack decorators run.
from neuralstrike.packs.base import (  # noqa: E402
    PACKS,
    Pack,
    PackProbe,
    get_pack,
    list_packs,
)
from neuralstrike.packs.cyberseceval import CyberSecEvalPack  # noqa: E402
from neuralstrike.packs.harmbench import HarmBenchPack  # noqa: E402
from neuralstrike.packs.jailbreakbench import JailbreakBenchPack  # noqa: E402
from neuralstrike.packs.local import LocalPack  # noqa: E402
