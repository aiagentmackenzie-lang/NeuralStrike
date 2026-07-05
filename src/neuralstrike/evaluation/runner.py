"""k-trial runner - seedable, temperature-pinned, transcript-recorded.

The runner is the reproducibility layer. Every run is:

- **seedable** - a base seed derives a deterministic per-trial seed so a
  replay with the same base seed reproduces identical verdicts.
- **temperature-pinned** - the victim is pinned to ``temperature=0.0`` by
  default (reproducible); the attacker is configurable.
- **transcript-recorded** - every trial is persisted to
  ``runs/<run-id>/trial-<n>.json`` with its seed, payload, response,
  verdict, and findings, so a reviewer can replay the exact evidence.
- **canary-fresh per trial** - a new canary is minted each trial so a
  leak in trial 1 cannot false-positive trial 2.

The runner is **transport-agnostic**: it takes a :class:`TrialFactory`
callable that runs one attack and returns a :class:`TrialResult`. This
keeps the runner decoupled from the loop / adapter and trivially testable
with a deterministic fake.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from neuralstrike.evaluation.scoring import ScoreCard, score_trials
from neuralstrike.evaluation.verdict import (
    EvidenceFidelity,
    TrialResult,
    Verdict,
)
from neuralstrike.utils.logging import get_logger

__all__ = ["Probe", "RunMeta", "RunReport", "TrialFactory", "TrialRunner"]

logger = get_logger("neuralstrike.evaluation.runner")


# A trial factory runs ONE attack for trial ``trial_index`` using the
# per-trial ``seed`` and the freshly-minted ``canary``. It returns the
# trial's verdict-bearing result. The runner owns k-trial orchestration;
# the factory owns the attack mechanics (loop / adapter / single-turn).
TrialFactory = Callable[
    [int, int, str],  # (trial_index, seed, canary)
    Awaitable[TrialResult],
]


def _derive_seed(base_seed: int, trial_index: int) -> int:
    """Deterministic per-trial seed from the base seed + trial index.

    Uses blake2b (stable across processes) so a replay reproduces the
    exact same per-trial seeds - Python's ``hash()`` is randomized and
    would break replayability.
    """
    digest = hashlib.blake2b(
        f"{base_seed}:{trial_index}".encode(), digest_size=8
    ).digest()
    return int.from_bytes(digest, "big", signed=False)


def _run_id(base_seed: int, scenario_id: str) -> str:
    """Deterministic run id from seed + scenario so a replay overwrites the
    same run directory (same seed => same verdicts => same transcript path)."""
    h = hashlib.blake2b(f"{base_seed}:{scenario_id}".encode(), digest_size=8).hexdigest()
    return f"run-{h}"


@dataclass(frozen=True)
class Probe:
    """Declarative probe spec: the scenario + how to run one trial.

    ``factory`` is the async callable that runs one attack. ``category``
    feeds per-category ASR. ``severity`` is the default finding severity
    when an oracle does not override it.
    """

    scenario_id: str
    goal: str
    factory: TrialFactory
    category: str = "uncategorized"
    severity: str = "high"


@dataclass(frozen=True)
class RunMeta:
    """Run-level metadata persisted alongside trials for replayability."""

    run_id: str
    scenario_id: str
    base_seed: int
    trials: int
    victim_temperature: float
    attacker_temperature: float
    started_at: str
    judge_model: str | None = None
    attacker_model: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "scenario_id": self.scenario_id,
            "base_seed": self.base_seed,
            "trials": self.trials,
            "victim_temperature": self.victim_temperature,
            "attacker_temperature": self.attacker_temperature,
            "started_at": self.started_at,
            "judge_model": self.judge_model,
            "attacker_model": self.attacker_model,
        }


@dataclass(frozen=True)
class RunReport:
    """The full result of a k-trial run."""

    meta: RunMeta
    trials: tuple[TrialResult, ...] = field(default_factory=tuple)
    score: ScoreCard | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "meta": self.meta.to_dict(),
            "trials": [_trial_to_dict(t) for t in self.trials],
            "score": _score_to_dict(self.score) if self.score else None,
        }

    @property
    def verdicts(self) -> tuple[Verdict, ...]:
        return tuple(t.verdict for t in self.trials)


def _trial_to_dict(t: TrialResult) -> dict[str, Any]:
    return {
        "trial_index": t.trial_index,
        "scenario_id": t.scenario_id,
        "seed": t.seed,
        "temperature": t.temperature,
        "verdict": t.verdict.value,
        "fidelity": t.fidelity.value,
        "payload": t.payload,
        "response_text": t.response.text if t.response else "",
        "tool_calls": [
            {"name": tc.name, "arguments": tc.arguments}
            for tc in (t.response.tool_calls if t.response else ())
        ],
        "error": t.error,
        "iterations": t.iterations,
        "findings": [
            {
                "oracle_id": f.oracle_id,
                "verdict": f.verdict.value,
                "fidelity": f.fidelity.value,
                "evidence_quote": f.evidence_quote,
                "reason": f.reason,
                "severity": f.severity,
                "advisory": f.advisory,
            }
            for f in t.findings
        ],
    }


def _score_to_dict(score: ScoreCard | None) -> dict[str, Any] | None:
    if score is None:
        return None
    return {
        "total": score.total,
        "resisted": score.resisted,
        "succeeded": score.succeeded,
        "inconclusive": score.inconclusive,
        "asr": score.asr,
        "asr_ci_low": score.asr_ci_low,
        "asr_ci_high": score.asr_ci_high,
        "coverage": score.coverage,
        "risk_index": score.risk_index,
        "flaky": score.flaky,
        "per_category": dict(score.per_category),
        "per_category_counts": {k: list(v) for k, v in score.per_category_counts.items()},
        "headline": score.headline,
    }


class TrialRunner:
    """Runs a :class:`Probe` for ``trials`` trials and scores + persists.

    Parameters
    ----------
    base_seed
        The seed the whole run is pinned to. The same seed reproduces the
        same per-trial seeds and therefore the same verdicts (Phase-0 exit
        gate: "a recorded run produces identical verdicts when replayed
        with the same seed").
    victim_temperature
        Pinned to ``0.0`` by default for reproducibility.
    attacker_temperature
        Configurable; the attacker may need creativity, but the per-trial
        seed still makes it deterministic given the seed.
    run_dir
        Where to persist ``runs/<run-id>/trial-<n>.json``. ``None`` skips
        persistence (used by tests that only check in-memory results).
    rng
        Injectable :class:`secrets.SystemRandom` so tests can pin canary
        minting. Defaults to a fresh system RNG.
    """

    def __init__(
        self,
        *,
        base_seed: int = 0,
        victim_temperature: float = 0.0,
        attacker_temperature: float = 0.7,
        run_dir: str | Path | None = "runs",
        rng: secrets.SystemRandom | None = None,
    ) -> None:
        self.base_seed = int(base_seed)
        self.victim_temperature = float(victim_temperature)
        self.attacker_temperature = float(attacker_temperature)
        self.run_dir = Path(run_dir) if run_dir is not None else None
        self._rng = rng or secrets.SystemRandom()

    def _mint(self) -> str:
        # Local import breaks a latent module-load cycle (oracles.base
        # <-> evaluation.runner via oracles.canary). mint_canary is only needed
        # at runtime, so importing it here keeps the package import-order-safe.
        from neuralstrike.oracles.canary import mint_canary

        return mint_canary(rng=self._rng)

    async def run(
        self,
        probe: Probe,
        *,
        trials: int = 1,
        judge_model: str | None = None,
        attacker_model: str | None = None,
        persist: bool = True,
    ) -> RunReport:
        """Run ``probe`` for ``trials`` trials; return the scored report."""
        if trials < 1:
            raise ValueError(f"trials must be >= 1, got {trials}")

        run_id = _run_id(self.base_seed, probe.scenario_id)
        meta = RunMeta(
            run_id=run_id,
            scenario_id=probe.scenario_id,
            base_seed=self.base_seed,
            trials=trials,
            victim_temperature=self.victim_temperature,
            attacker_temperature=self.attacker_temperature,
            started_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            judge_model=judge_model,
            attacker_model=attacker_model,
        )

        run_path: Path | None = None
        if persist and self.run_dir is not None:
            run_path = self.run_dir / run_id
            run_path.mkdir(parents=True, exist_ok=True)
            (run_path / "meta.json").write_text(
                json.dumps(meta.to_dict(), indent=2, sort_keys=True), encoding="utf-8"
            )

        results: list[TrialResult] = []
        for trial_index in range(trials):
            seed = _derive_seed(self.base_seed, trial_index)
            canary = self._mint()
            logger.info(
                "run %s trial %d/%d seed=%d canary=%s", run_id, trial_index + 1, trials, seed, canary
            )
            try:
                trial = await probe.factory(trial_index, seed, canary)
            except Exception as exc:
                # Victim errors are recorded as Inconclusive (coverage gap);
                # attacker/judge errors should already have aborted inside the
                # factory. Anything that escapes here is recorded honestly.
                logger.error("trial %d raised: %s", trial_index, exc)
                trial = TrialResult(
                    trial_index=trial_index,
                    seed=seed,
                    temperature=self.victim_temperature,
                    verdict=Verdict.INCONCLUSIVE,
                    fidelity=EvidenceFidelity.VERBAL,
                    payload="",
                    response=None,
                    error=f"{type(exc).__name__}: {exc}",
                    scenario_id=probe.scenario_id,
                )
            results.append(trial)
            if run_path is not None:
                path = run_path / f"trial-{trial_index}.json"
                path.write_text(
                    json.dumps(_trial_to_dict(trial), indent=2, sort_keys=True),
                    encoding="utf-8",
                )

        category_of = {probe.scenario_id: probe.category}
        score = score_trials(results, category_of=category_of)
        report = RunReport(meta=meta, trials=tuple(results), score=score)

        if run_path is not None:
            (run_path / "report.json").write_text(
                json.dumps(report.to_dict(), indent=2, sort_keys=True), encoding="utf-8"
            )

        logger.info("run %s complete: %s", run_id, score.headline)
        return report
