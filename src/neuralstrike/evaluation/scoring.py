"""Backward-compat re-export shim.

The statistical primitives (Wilson CIs, conclusive-only scoring, the
:class:`ScoreCard`, severity-weighted risk index, coverage, flaky
detection) have a single canonical home in
:mod:`neuralstrike.evaluation.statistics`. This module re-exports them so
every existing import — ``from neuralstrike.evaluation.scoring import
score_trials`` — keeps working unchanged.

Nothing new lives here. Add new measurement primitives to
``statistics.py``.
"""

from __future__ import annotations

from neuralstrike.evaluation.statistics import (
    SEVERITY_WEIGHTS,
    ScoreCard,
    score_trials,
    wilson_ci,
)

__all__ = ["SEVERITY_WEIGHTS", "ScoreCard", "score_trials", "wilson_ci"]
