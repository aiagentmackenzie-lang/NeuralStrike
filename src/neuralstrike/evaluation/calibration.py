"""Cohort-relative z-score calibration — informational, never gates.

A raw ASR is an *absolute* number. A z-score against a reference cohort
is a *relative* number: "is this SUT more exploitable than the cohort's
median member?" garak-style relative scoring. This module computes it.

The non-negotiable rule (Decision, recorded): **ship no built-in
cohort.** A fabricated cohort (mean/std pulled from thin air) makes
every z-score a lie — the number would look precise and mean nothing.
The operator supplies their own cohort file (``--calibration cohort.json``);
NeuralStrike never invents one. An absent cohort means "no z-score",
never "z-score vs a fake baseline".

The z-score is **informational only**. It never changes an exit code. A
run that is far above the cohort average is still exit 0 if it has no
Succeeded findings; a run far below is still exit 1/4 if it has a
regression. The gate is the gate; the z-score is context.

Cohort file schema (JSON)::

    {
      "name": "defenders-cohort-2026",
      "description": "20 defender SUTs scored with the same corpus",
      "asr": {"mean": 0.45, "std": 0.12, "n": 20},
      "per_category": {
        "asi01-prompt-injection": {"mean": 0.60, "std": 0.10, "n": 20}
      }
    }

Only ``name`` and ``asr`` (with ``mean`` and ``std``) are required.
``per_category`` is optional and produces a per-category z-score map.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from neuralstrike.evaluation.statistics import ScoreCard, z_score

__all__ = [
    "CalibrationError",
    "CalibrationResult",
    "Cohort",
    "CohortStats",
    "calibrate",
    "load_cohort",
]


class CalibrationError(Exception):
    """Raised when a cohort file is missing, malformed, or incomplete."""


@dataclass(frozen=True)
class CohortStats:
    """One statistic (mean / std / n) for a cohort or a cohort category."""

    mean: float
    std: float
    n: int = 0

    def validate(self, *, where: str = "asr") -> None:
        if not isinstance(self.mean, (int, float)) or not isinstance(self.std, (int, float)):
            raise CalibrationError(f"cohort {where} mean/std must be numbers")
        if self.mean < 0 or self.mean > 1:
            raise CalibrationError(f"cohort {where} mean must be in [0, 1], got {self.mean}")
        if self.std < 0:
            raise CalibrationError(f"cohort {where} std must be >= 0, got {self.std}")


@dataclass(frozen=True)
class Cohort:
    """A user-supplied reference cohort. NeuralStrike ships none."""

    name: str
    asr: CohortStats
    description: str = ""
    per_category: Mapping[str, CohortStats] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "asr": {"mean": self.asr.mean, "std": self.asr.std, "n": self.asr.n},
            "per_category": {
                k: {"mean": v.mean, "std": v.std, "n": v.n}
                for k, v in self.per_category.items()
            },
        }


def _cohort_stats_from_dict(d: Any, *, where: str) -> CohortStats:
    if not isinstance(d, dict):
        raise CalibrationError(f"cohort {where} must be an object with mean/std")
    if "mean" not in d or "std" not in d:
        raise CalibrationError(f"cohort {where} requires 'mean' and 'std'")
    stats = CohortStats(mean=float(d["mean"]), std=float(d["std"]), n=int(d.get("n", 0)))
    stats.validate(where=where)
    return stats


def load_cohort(path: str | Path) -> Cohort:
    """Load a user-supplied cohort from a JSON file.

    Raises :class:`CalibrationError` on missing file, invalid JSON, or a
    cohort missing the required ``name`` / ``asr.mean`` / ``asr.std``
    fields. NeuralStrike never falls back to a built-in cohort — a
    missing/incomplete cohort means "no z-score", not "z vs a fake one".
    """
    p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise CalibrationError(f"cohort file not found: {p}") from exc
    except json.JSONDecodeError as exc:
        raise CalibrationError(f"cohort {p} is not valid JSON: {exc.msg}") from exc
    if not isinstance(data, dict):
        raise CalibrationError(f"cohort {p} must be a JSON object")
    name = data.get("name")
    if not isinstance(name, str) or not name.strip():
        raise CalibrationError(f"cohort {p} missing required string 'name'")
    asr = _cohort_stats_from_dict(data.get("asr"), where="asr")

    per_cat: dict[str, CohortStats] = {}
    raw_cats = data.get("per_category") or {}
    if isinstance(raw_cats, dict):
        for cat, stats in raw_cats.items():
            per_cat[str(cat)] = _cohort_stats_from_dict(stats, where=f"per_category.{cat}")

    return Cohort(
        name=name,
        asr=asr,
        description=str(data.get("description", "")),
        per_category=per_cat,
    )


@dataclass(frozen=True)
class CalibrationResult:
    """The z-score of an observed run against a reference cohort.

    ``z`` is the population z-score of the run's ASR against the cohort's
    mean/std. ``per_category`` maps each category present in *both* the
    run and the cohort to its z-score. ``interpretation`` is a short
    human-readable label. **None of this changes an exit code.**
    """

    cohort: str
    observed_asr: float
    cohort_mean: float
    cohort_std: float
    z: float
    per_category: Mapping[str, float] = field(default_factory=dict)

    @property
    def interpretation(self) -> str:
        if self.cohort_std <= 0:
            return "degenerate cohort (std=0); no comparative signal"
        if self.z >= 2.0:
            return "far above cohort average (>+2 sigma)"
        if self.z >= 1.0:
            return "above cohort average (+1 to +2 sigma)"
        if self.z <= -2.0:
            return "far below cohort average (<-2 sigma)"
        if self.z <= -1.0:
            return "below cohort average (-2 to -1 sigma)"
        return "consistent with cohort average (within +/-1 sigma)"

    def to_dict(self) -> dict[str, Any]:
        return {
            "cohort": self.cohort,
            "observed_asr": self.observed_asr,
            "cohort_mean": self.cohort_mean,
            "cohort_std": self.cohort_std,
            "z": self.z,
            "interpretation": self.interpretation,
            "per_category": dict(self.per_category),
        }


def calibrate(score: ScoreCard, cohort: Cohort) -> CalibrationResult:
    """Compute the cohort-relative z-score of ``score.asr`` (informational only).

    Per-category z-scores are computed for categories present in *both*
    the run's ``per_category`` and the cohort's ``per_category``. A
    category in only one side is skipped (no fabrication).
    """
    z = z_score(score.asr, cohort.asr.mean, cohort.asr.std)
    per_cat: dict[str, float] = {}
    for cat, run_asr in score.per_category.items():
        cstats = cohort.per_category.get(cat)
        if cstats is None:
            continue
        per_cat[cat] = z_score(run_asr, cstats.mean, cstats.std)
    return CalibrationResult(
        cohort=cohort.name,
        observed_asr=score.asr,
        cohort_mean=cohort.asr.mean,
        cohort_std=cohort.asr.std,
        z=z,
        per_category=per_cat,
    )
