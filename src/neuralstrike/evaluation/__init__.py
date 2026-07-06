"""NeuralStrike measurement - conclusive-only scoring, k-trial runs, baselines.

The evaluation layer turns oracle verdicts into trustworthy numbers:

- :mod:`verdict`      - the three-outcome type system (Resisted / Succeeded /
  Inconclusive) + evidence fidelity.
- :mod:`statistics`   - the canonical measurement module: Wilson CIs,
  conclusive-only ASR, per-category ASR, severity-weighted 0-100 risk
  index, coverage, k-trial aggregation, corpus aggregation, z-score.
- :mod:`scoring`      - backward-compat re-export shim over ``statistics``.
- :mod:`runner`       - k-trial runner; per-trial canary minting;
  seed + temperature pinning; per-trial transcript persistence; flaky
  detection.
- :mod:`baseline`     - save / compare / gate with honest exit codes
  (0 pass · 1 vuln · 3 runtime error · 4 regression).
- :mod:`calibration`  - cohort-relative z-score (informational, never
  changes exit code; ships no built-in cohort).
"""

from neuralstrike.evaluation.baseline import BaselineError, compare_baseline, save_baseline
from neuralstrike.evaluation.runner import Probe, RunReport, TrialRunner
from neuralstrike.evaluation.scoring import ScoreCard, score_trials, wilson_ci
from neuralstrike.evaluation.statistics import (
    RunStatistics,
    aggregate_corpus_stats,
    k_trial_summary,
    z_score,
)
from neuralstrike.evaluation.verdict import (
    EvidenceFidelity,
    Finding,
    SutResponse,
    ToolCall,
    TrialResult,
    Verdict,
)

__all__ = [
    "BaselineError",
    "EvidenceFidelity",
    "Finding",
    "Probe",
    "RunReport",
    "RunStatistics",
    "ScoreCard",
    "SutResponse",
    "ToolCall",
    "TrialResult",
    "TrialRunner",
    "Verdict",
    "aggregate_corpus_stats",
    "compare_baseline",
    "k_trial_summary",
    "save_baseline",
    "score_trials",
    "wilson_ci",
    "z_score",
]
