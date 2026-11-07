"""k-trial runner - seedable, temperature-pinned, transcript-recorded.

The runner is the reproducibility layer. Every run is:

- **seedable** - a base seed derives deterministic per-trial seed metadata.
  Live providers and fresh canaries can still produce different observations.
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

import asyncio
import hashlib
import json
import os
import secrets
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from neuralstrike.evaluation.checkpoint import TrialCheckpoint, trial_checkpoint
from neuralstrike.evaluation.controls import SEED_DERIVATION, trial_controls
from neuralstrike.evaluation.scoring import ScoreCard, score_trials
from neuralstrike.evaluation.verdict import (
    EvidenceFidelity,
    TrialResult,
    Verdict,
    normalize_trial,
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
    digest = hashlib.blake2b(f"{base_seed}:{trial_index}".encode(), digest_size=8).digest()
    # Provider JSON bindings commonly accept signed 64-bit integers. Keep the
    # low 63 bits so every recorded seed is also a valid nonnegative wire seed.
    return int.from_bytes(digest, "big", signed=False) & ((1 << 63) - 1)


def _run_id(base_seed: int, scenario_id: str) -> str:
    """Unique execution identity; seeds are comparison metadata, not file names."""
    return f"run-{uuid.uuid4().hex}"


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    """Commit a private JSON file by atomic rename, without partial final files."""
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(payload, indent=2, sort_keys=True))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _manifest(path: Path, meta: RunMeta, *, complete: bool) -> None:
    files = {
        item.name: hashlib.sha256(item.read_bytes()).hexdigest()
        for item in sorted(path.glob("*.json"))
        if item.name != "manifest.json"
    }
    _atomic_json(
        path / "manifest.json",
        {
            "schema_version": 2,
            "run_id": meta.run_id,
            "state": "complete" if complete else "running",
            "comparison_key": hashlib.sha256(
                json.dumps(
                    {
                        "seed": meta.base_seed,
                        "scenario": meta.scenario_id,
                        "intensity": meta.intensity,
                        "identity": meta.comparison_identity,
                    },
                    sort_keys=True,
                ).encode()
            ).hexdigest(),
            "comparison_key_scope": "configured assessment inputs; remote application build unverified",
            "expected_trials": meta.trials,
            "files": files,
            "evidence_policy": "private raw evidence; not a sanitized sharing bundle",
        },
    )


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
    comparison_identity: dict[str, Any] = field(default_factory=dict)


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
    intensity: str = "standard"
    """A label pinning the probe profile (e.g. 'standard', 'adaptive', 'k3-instrumented').

    The baseline gate refuses to compare runs whose ``intensity`` differs —
    a baseline pinned at one probe profile is not comparable to a run at a
    different profile (the ASR means different things). Backward compatible:
    a baseline with no recorded intensity skips the check."""

    comparison_identity: dict[str, Any] = field(default_factory=dict)
    seed_derivation: str | None = None
    category: str = "uncategorized"
    severity: str = "high"
    provenance: dict[str, Any] = field(default_factory=dict)
    completed_at: str | None = None

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
            "intensity": self.intensity,
            "comparison_identity": self.comparison_identity,
            "seed_derivation": self.seed_derivation,
            "category": self.category,
            "severity": self.severity,
            "provenance": self.provenance,
            "completed_at": self.completed_at,
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
    document: dict[str, Any] = {
        "trial_index": t.trial_index,
        "scenario_id": t.scenario_id,
        "seed": t.seed,
        "temperature": float(t.temperature),
        "verdict": t.verdict.value,
        "fidelity": t.fidelity.value,
        "payload": t.payload,
        "inputs": t.inputs,
        "oracle_policy": t.oracle_policy,
        "exchanges": list(t.response.exchanges) if t.response else [],
        "response_present": t.response is not None,
        "response_text": t.response.text if t.response else "",
        "tool_calls": [
            {"name": tc.name, "arguments": tc.arguments, "tool_call_id": tc.tool_call_id}
            for tc in (t.response.tool_calls if t.response else ())
        ],
        "traces": list(t.response.traces) if t.response else [],
        "response_error": t.response.error if t.response else None,
        "error": t.error,
        "iterations": t.iterations,
        "trajectory_fingerprint": t.trajectory_fingerprint,
        "findings": [
            {
                "oracle_id": f.oracle_id,
                "verdict": f.verdict.value,
                "fidelity": f.fidelity.value,
                "evidence_quote": f.evidence_quote,
                "reason": f.reason,
                "severity": f.severity,
                "advisory": f.advisory,
                "tool_name": f.tool_name,
                "tool_call_id": f.tool_call_id,
                "arguments_digest": f.arguments_digest,
                "receipt_id": f.receipt_id,
                "evidence_origin": f.evidence_origin,
            }
            for f in t.findings
        ],
    }

    document = json.loads(json.dumps(document, allow_nan=False))
    observation = {
        key: value
        for key, value in document.items()
        if key not in {"verdict", "fidelity", "findings", "oracle_policy"}
    }
    document["evidence_id"] = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(observation, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        ).hexdigest()
    )
    return document


def _score_to_dict(score: ScoreCard | None) -> dict[str, Any] | None:
    if score is None:
        return None
    return {
        "total": score.total,
        "resisted": score.resisted,
        "succeeded": score.succeeded,
        "inconclusive": score.inconclusive,
        "asr": score.measured_asr,
        "asr_ci_low": score.asr_ci_low if score.measured_asr is not None else None,
        "asr_ci_high": score.asr_ci_high if score.measured_asr is not None else None,
        "coverage": score.coverage,
        "risk_index": score.risk_index if score.measured_asr is not None else None,
        "flaky": score.flaky,
        "per_category": dict(score.per_category),
        "per_category_counts": {k: list(v) for k, v in score.per_category_counts.items()},
        "headline": score.headline,
    }


def persist_report(report: RunReport, root: str | Path) -> Path:
    """Persist a new private execution/derivation without reusing a directory."""
    directory = Path(root) / report.meta.run_id
    directory.parent.mkdir(parents=True, exist_ok=True)
    directory.mkdir(mode=0o700, exist_ok=False)
    _atomic_json(directory / "meta.json", report.meta.to_dict())
    _manifest(directory, report.meta, complete=False)
    for trial in report.trials:
        _atomic_json(directory / f"trial-{trial.trial_index}.json", _trial_to_dict(trial))
    _atomic_json(directory / "report.json", report.to_dict())
    _manifest(directory, report.meta, complete=True)
    return directory


class TrialRunner:
    """Runs a :class:`Probe` for ``trials`` trials and scores + persists.

    Parameters
    ----------
    base_seed
        Derives stable per-trial seed metadata. This does not guarantee identical
        live observations or verdicts; offline evidence replay is separate.
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
        inter_trial_delay: float = 0.0,
        trial_timeout: float | None = None,
    ) -> None:
        self.base_seed = int(base_seed)
        self.victim_temperature = float(victim_temperature)
        self.attacker_temperature = float(attacker_temperature)
        self.run_dir = Path(run_dir) if run_dir is not None else None
        self._rng = rng or secrets.SystemRandom()
        # Operator-safety knobs (Phase 3). --delay spaces trials so a live
        # target's WAF/rate-limiter does not ban the run (gap G6). --timeout
        # bounds a single trial so one hung LLM call cannot stall the whole
        # run (gap G5); a timed-out trial is recorded Inconclusive (a
        # coverage gap), never a fabricated pass.
        self.inter_trial_delay = float(inter_trial_delay)
        self.trial_timeout = float(trial_timeout) if trial_timeout is not None else None

    def _mint(self) -> str:
        # Local import breaks a latent module-load cycle (oracles.base
        # <-> evaluation.runner via oracles.canary). mint_canary is only needed
        # at runtime, so importing it here keeps the package import-order-safe.
        from neuralstrike.oracles.canary import mint_canary

        return mint_canary(rng=self._rng)

    async def _execute(
        self, probe: Probe, trial_index: int, seed: int, canary: str, checkpoint: TrialCheckpoint
    ) -> TrialResult:
        with trial_checkpoint(checkpoint), trial_controls(seed, self.victim_temperature):
            if self.trial_timeout is not None:
                return await asyncio.wait_for(
                    probe.factory(trial_index, seed, canary), timeout=self.trial_timeout
                )
            return await probe.factory(trial_index, seed, canary)

    async def run(
        self,
        probe: Probe,
        *,
        trials: int = 1,
        judge_model: str | None = None,
        attacker_model: str | None = None,
        persist: bool = True,
        intensity: str = "standard",
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
            intensity=intensity,
            comparison_identity=probe.comparison_identity,
            seed_derivation=SEED_DERIVATION,
            category=probe.category,
            severity=probe.severity,
        )

        run_path: Path | None = None
        if persist and self.run_dir is not None:
            run_path = self.run_dir / run_id
            self.run_dir.mkdir(parents=True, exist_ok=True)
            run_path.mkdir(mode=0o700, exist_ok=False)
            _atomic_json(run_path / "meta.json", meta.to_dict())
            _manifest(run_path, meta, complete=False)

        results: list[TrialResult] = []
        for trial_index in range(trials):
            if trial_index > 0 and self.inter_trial_delay > 0:
                await asyncio.sleep(self.inter_trial_delay)
            seed = _derive_seed(self.base_seed, trial_index)
            canary = self._mint()
            logger.info("run %s trial %d/%d seed=%d canary=%s", run_id, trial_index + 1, trials, seed, canary)
            checkpoint = TrialCheckpoint()
            try:
                trial = await self._execute(probe, trial_index, seed, canary, checkpoint)
            except asyncio.CancelledError:
                partial = checkpoint.interrupted("trial cancelled before completion")
                if partial is not None and run_path is not None:
                    _atomic_json(
                        run_path / f"trial-{trial_index}.json", _trial_to_dict(normalize_trial(partial))
                    )
                    _manifest(run_path, meta, complete=False)
                raise
            except asyncio.TimeoutError:
                # A hung trial is a coverage gap, not a fabricated pass. The
                # run continues (other trials may conclude); the timeout is
                # recorded honestly on this trial.
                logger.warning("trial %d timed out after %ss", trial_index, self.trial_timeout)
                trial = TrialResult(
                    trial_index=trial_index,
                    seed=seed,
                    temperature=self.victim_temperature,
                    verdict=Verdict.INCONCLUSIVE,
                    fidelity=EvidenceFidelity.VERBAL,
                    payload="",
                    response=None,
                    error=f"trial timed out after {self.trial_timeout}s",
                    scenario_id=probe.scenario_id,
                )
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
            if trial.error:
                trial = checkpoint.interrupted(trial.error) or trial
            trial = normalize_trial(trial)
            results.append(trial)
            if run_path is not None:
                _atomic_json(run_path / f"trial-{trial_index}.json", _trial_to_dict(trial))
                _manifest(run_path, meta, complete=False)

        category_of = {probe.scenario_id: probe.category}
        score = score_trials(results, category_of=category_of)
        meta = replace(meta, completed_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        report = RunReport(meta=meta, trials=tuple(results), score=score)

        if run_path is not None:
            _atomic_json(run_path / "meta.json", meta.to_dict())
            _atomic_json(run_path / "report.json", report.to_dict())
            _manifest(run_path, meta, complete=True)

        logger.info("run %s complete: %s", run_id, score.headline)
        return report
