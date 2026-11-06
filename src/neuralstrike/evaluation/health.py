"""Execution completeness and policy are separate from observed vulnerabilities."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import asdict, dataclass
from typing import Any

from neuralstrike.evaluation.runner import RunReport
from neuralstrike.evaluation.verdict import Verdict


@dataclass(frozen=True)
class AssessmentHealth:
    selected: int
    attempted: int
    conclusive: int
    errors: int
    succeeded: int
    complete: bool

    @property
    def status(self) -> str:
        return "complete" if self.complete else "incomplete"

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "status": self.status}

    def exit_code(self, fail_on: str) -> int:
        if fail_on not in {"vuln", "regression", "never"}:
            raise ValueError("fail_on must be never|vuln|regression")
        if fail_on == "never":
            return 0
        if not self.complete:
            return 3
        # Regression requires a baseline. Without one, retain legacy report-only
        # vulnerability semantics, while always enforcing execution completeness.
        return 1 if fail_on == "vuln" and self.succeeded else 0


def assessment_health(reports: Sequence[RunReport], *, selected: int | None = None) -> AssessmentHealth:
    expected = sum(r.meta.trials for r in reports) if selected is None else selected
    trials = [t for report in reports for t in report.trials]
    conclusive = sum(t.verdict is not Verdict.INCONCLUSIVE for t in trials)
    errors = sum(bool(t.error or (t.response and t.response.error)) for t in trials)
    valid_indices = all(
        len({(t.scenario_id, t.trial_index) for t in r.trials}) == len(r.trials)
        and len(r.trials) == r.meta.trials
        for r in reports
    )
    return AssessmentHealth(
        selected=expected,
        attempted=len(trials),
        conclusive=conclusive,
        errors=errors,
        succeeded=sum(t.verdict is Verdict.SUCCEEDED for t in trials),
        complete=bool(expected)
        and len(trials) == expected
        and conclusive == expected
        and not errors
        and valid_indices,
    )
