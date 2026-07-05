"""Baseline save / compare / gate with honest exit codes.

A baseline is a pinned snapshot of which scenarios produced which
verdicts + severities on a reference run (typically ``main``). The
comparison is the CI gate.

Exit codes (non-negotiable):

- ``0`` — pass. No new findings and (under ``regression``) no regressions.
- ``1`` — vuln. ``--fail-on vuln`` and at least one Succeeded finding
  exists in the current run.
- ``3`` — runtime error. The baseline could not be loaded / parsed, or
  the runs are not comparable (truncation / intensity mismatch — the
  Phase-3 gate's refusal; here a stub that returns a clear error).
- ``4`` — regression. ``--fail-on regression`` and a scenario that was
  ``Resisted`` or ``Inconclusive`` in the baseline is now ``Succeeded``.
  **Regression outranks absolute vuln**: if both a pre-existing vuln and
  a regression exist, the exit code is ``4`` (regression), not ``1``.

``--fail-on never`` records the comparison but always exits ``0`` (the
"informational baseline" mode used while a corpus is still maturing).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from neuralstrike.evaluation.runner import RunReport
from neuralstrike.evaluation.verdict import Verdict

__all__ = [
    "BaselineError",
    "CompareDecision",
    "CompareResult",
    "baseline_path",
    "compare_baseline",
    "save_baseline",
]


class BaselineError(Exception):
    """Raised when a baseline cannot be loaded or runs are not comparable."""


class CompareDecision(str, Enum):
    """The decision a baseline comparison reaches."""

    PASS = "pass"
    VULN = "vuln"
    REGRESSION = "regression"
    NOT_COMPARABLE = "not_comparable"


@dataclass(frozen=True)
class CompareResult:
    """The outcome of a baseline comparison."""

    decision: CompareDecision
    exit_code: int
    summary: str
    new_succeeded: tuple[str, ...] = ()
    pre_existing_succeeded: tuple[str, ...] = ()
    regressions: tuple[str, ...] = ()
    fixed: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "exit_code": self.exit_code,
            "summary": self.summary,
            "new_succeeded": list(self.new_succeeded),
            "pre_existing_succeeded": list(self.pre_existing_succeeded),
            "regressions": list(self.regressions),
            "fixed": list(self.fixed),
        }


def baseline_path(directory: str | Path, scenario_id: str) -> Path:
    """Canonical baseline file path for a scenario."""
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in scenario_id) or "scenario"
    return Path(directory) / f"{safe}.baseline.json"


def _scenario_signatures(report: RunReport) -> dict[str, str]:
    """Map ``scenario_id -> verdict`` for the trials in ``report``.

    A scenario that appears multiple times (multi-trial run) is reduced
    to its *worst* conclusive verdict (Succeeded > Inconclusive >
    Resisted) — a single successful trial means the scenario is
    exploitable.
    """
    worst: dict[str, Verdict] = {}
    for t in report.trials:
        sid = t.scenario_id
        if not sid:
            continue
        prev = worst.get(sid)
        if prev is None or _verdict_rank(t.verdict) > _verdict_rank(prev):
            worst[sid] = t.verdict
    return {sid: v.value for sid, v in worst.items()}


def _verdict_rank(v: Verdict) -> int:
    return {Verdict.RESISTED: 0, Verdict.INCONCLUSIVE: 1, Verdict.SUCCEEDED: 2}[v]


def save_baseline(directory: str | Path, report: RunReport) -> Path:
    """Persist ``report`` as the baseline for its scenario.

    The baseline stores, per scenario, the verdict signature and the
    severities of the Succeeded findings. This is the pinned reference
    that ``compare_baseline`` diffs against.
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    sigs = _scenario_signatures(report)
    severities: dict[str, list[str]] = {}
    for t in report.trials:
        if t.verdict is not Verdict.SUCCEEDED or not t.scenario_id:
            continue
        severities.setdefault(t.scenario_id, [])
        for f in t.findings:
            if f.verdict is Verdict.SUCCEEDED:
                severities[t.scenario_id].append(f.severity)

    payload = {
        "scenario_id": report.meta.scenario_id,
        "base_seed": report.meta.base_seed,
        "trials": report.meta.trials,
        "verdicts": sigs,
        "succeeded_severities": severities,
        "score": {
            "asr": report.score.asr if report.score else None,
            "coverage": report.score.coverage if report.score else None,
            "risk_index": report.score.risk_index if report.score else None,
        },
    }
    path = baseline_path(directory, report.meta.scenario_id)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path


def _load_baseline(path: Path) -> Mapping[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise BaselineError(f"baseline not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise BaselineError(f"baseline {path} is not valid JSON: {exc.msg}") from exc
    if not isinstance(data, dict) or "verdicts" not in data:
        raise BaselineError(f"baseline {path} missing 'verdicts' map")
    return data


def compare_baseline(
    directory: str | Path,
    report: RunReport,
    *,
    fail_on: str = "regression",
) -> CompareResult:
    """Compare ``report`` against the saved baseline for its scenario.

    ``fail_on`` selects the gate policy (see module docstring).
    """
    if fail_on not in {"never", "vuln", "regression"}:
        raise BaselineError(f"invalid fail_on={fail_on!r}; expected never|vuln|regression")

    scenario = report.meta.scenario_id
    path = baseline_path(directory, scenario)
    baseline = _load_baseline(path)
    baseline_verdicts: Mapping[str, str] = baseline["verdicts"]
    current = _scenario_signatures(report)

    # Truncation / intensity mismatch refusal: a baseline pinned at
    # ``trials=N`` cannot be compared to a run with fewer trials (the
    # run was truncated, so its ASR is not comparable to the baseline).
    baseline_trials = baseline.get("trials")
    if isinstance(baseline_trials, int) and baseline_trials > 0 and report.meta.trials < baseline_trials:
        return CompareResult(
            decision=CompareDecision.NOT_COMPARABLE,
            exit_code=3,
            summary=(
                f"current run has {report.meta.trials} trials but baseline pinned at "
                f"{baseline_trials}; refusing to compare a truncated scan"
            ),
        )

    new_succ: list[str] = []
    pre_existing: list[str] = []
    regressions: list[str] = []
    fixed: list[str] = []

    for sid, v in current.items():
        if v == Verdict.SUCCEEDED.value:
            prev = baseline_verdicts.get(sid)
            if prev is None:
                new_succ.append(sid)
            elif prev == Verdict.SUCCEEDED.value:
                pre_existing.append(sid)
            else:  # was Resisted/Inconclusive -> now Succeeded
                regressions.append(sid)
        else:
            prev = baseline_verdicts.get(sid)
            if prev == Verdict.SUCCEEDED.value and v != Verdict.SUCCEEDED.value:
                fixed.append(sid)

    # Decision: regression outranks vuln; vuln requires fail_on in {vuln, regression}.
    if regressions and fail_on == "regression":
        return CompareResult(
            decision=CompareDecision.REGRESSION,
            exit_code=4,
            summary=f"{len(regressions)} regression(s): {regressions}",
            new_succeeded=tuple(new_succ),
            pre_existing_succeeded=tuple(pre_existing),
            regressions=tuple(regressions),
            fixed=tuple(fixed),
        )

    current_vuln = bool(new_succ or pre_existing)
    if current_vuln and fail_on in {"vuln", "regression"}:
        return CompareResult(
            decision=CompareDecision.VULN,
            exit_code=1,
            summary=(
                f"{len(new_succ) + len(pre_existing)} Succeeded finding(s) "
                f"(new={len(new_succ)}, pre-existing={len(pre_existing)})"
            ),
            new_succeeded=tuple(new_succ),
            pre_existing_succeeded=tuple(pre_existing),
            regressions=tuple(regressions),
            fixed=tuple(fixed),
        )

    return CompareResult(
        decision=CompareDecision.PASS,
        exit_code=0,
        summary=(
            f"pass: {len(fixed)} fixed, {len(regressions)} regressions, "
            f"{len(new_succ)} new, {len(pre_existing)} pre-existing"
        ),
        new_succeeded=tuple(new_succ),
        pre_existing_succeeded=tuple(pre_existing),
        regressions=tuple(regressions),
        fixed=tuple(fixed),
    )
