"""Offline comparison of two committed assessment bundles — the ``compare`` command.

Both sides are loaded through :func:`load_assessment`, so every recorded byte is
hash-checked before a verdict is read, and no target, model or oracle is called.
The question is narrow on purpose: *did the same declared plan produce a better or
worse result?* — not *is the target vulnerable now?*

Refusals are first class. A different adapter, target, seed, trial count or scenario
payload, and any incomplete current assessment, produce ``not_comparable`` with a
non-zero exit. A comparison that could not be made never becomes a pass, and a
scenario that went Succeeded → Inconclusive is never counted as a fix.

The decision itself is :func:`neuralstrike.evaluation.baseline.decide_comparison`,
the same function the live ``scan --baseline-dir`` gate uses, so the two surfaces
cannot drift apart about what a regression is.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from neuralstrike.evaluation.assessment import (
    VerifiedAssessment,
    is_assessment_bundle,
    load_assessment,
    target_label,
)
from neuralstrike.evaluation.baseline import (
    BaselineError,
    CompareDecision,
    CompareResult,
    decide_comparison,
)
from neuralstrike.evaluation.identity import configuration_digest
from neuralstrike.evaluation.verdict import Verdict

__all__ = ["ComparisonError", "compare_assessments", "compare_with_record"]

_SCHEMA_VERSION = 1


class ComparisonError(BaselineError):
    """Raised when two bundles cannot be compared at all."""


def _verdicts(bundle: VerifiedAssessment) -> dict[str, str]:
    """Scenario → worst recorded verdict, exactly as the bundle records it."""
    return {result.scenario.id: result.verdict.value for result in bundle.report.scenario_results}


def _scenario_digests(bundle: VerifiedAssessment) -> dict[str, str]:
    return {
        scenario.id: configuration_digest(scenario.model_dump(by_alias=True))
        for scenario in bundle.plan.scenarios
    }


def _compatibility(baseline: VerifiedAssessment, current: VerifiedAssessment) -> str | None:
    """Name the first difference that makes a comparison meaningless."""
    left, right = baseline.plan, current.plan
    left_digests, right_digests = _scenario_digests(baseline), _scenario_digests(current)
    only_left = sorted(set(left_digests) - set(right_digests))
    only_right = sorted(set(right_digests) - set(left_digests))
    changed = sorted(
        sid for sid, digest in left_digests.items() if sid in right_digests and right_digests[sid] != digest
    )

    checks: tuple[tuple[bool, str], ...] = (
        (
            left.adapter != right.adapter,
            f"adapter differs ({left.adapter!r} vs {right.adapter!r}); refusing to compare",
        ),
        (
            target_label(left.target) != target_label(right.target),
            "target differs; a fix verified on a different target is not a fix "
            f"({target_label(left.target)!r} vs {target_label(right.target)!r})",
        ),
        (
            left.base_seed != right.base_seed,
            f"seed differs ({left.base_seed} vs {right.base_seed}); refusing to compare trial controls",
        ),
        (
            left.trials != right.trials,
            f"trial count differs ({left.trials} vs {right.trials}); refusing a truncated comparison",
        ),
        (
            bool(only_left or only_right),
            "scenario selection differs "
            f"(only-baseline={only_left}, only-current={only_right}); refusing to compare",
        ),
        (
            bool(changed),
            f"scenario payload changed between bundles: {changed}; refusing to compare",
        ),
    )
    for failed, message in checks:
        if failed:
            return message
    return None


def _load_pair(baseline: str | Path, current: str | Path) -> tuple[VerifiedAssessment, VerifiedAssessment]:
    for label, path in (("baseline", baseline), ("current", current)):
        if not is_assessment_bundle(path):
            raise ComparisonError(
                f"{label} is not a committed assessment bundle; run `neuralstrike assess` first"
            )
    return load_assessment(baseline), load_assessment(current)


def _compare(reference: VerifiedAssessment, candidate: VerifiedAssessment, *, fail_on: str) -> CompareResult:
    issue = _compatibility(reference, candidate)
    if issue is not None:
        return CompareResult(CompareDecision.NOT_COMPARABLE, 0 if fail_on == "never" else 3, issue)

    current_verdicts = _verdicts(candidate)
    unresolved = sorted(
        scenario_id
        for scenario_id, verdict in current_verdicts.items()
        if verdict == Verdict.INCONCLUSIVE.value
    )
    health = candidate.report.health
    incomplete = bool(
        unresolved or candidate.report.execution_error is not None or health is None or not health.complete
    )
    return decide_comparison(
        _verdicts(reference),
        current_verdicts,
        fail_on=fail_on,
        incomplete=incomplete,
        unresolved=unresolved,
    )


def _record(
    reference: VerifiedAssessment, candidate: VerifiedAssessment, result: CompareResult
) -> dict[str, Any]:
    """Bind the decision to the two verified bundle identities it was made from."""
    return {
        "schema_version": _SCHEMA_VERSION,
        "operation": "offline-assessment-compare",
        "target_calls": False,
        "baseline_assessment_id": reference.assessment_id,
        "baseline_manifest_sha256": reference.manifest_sha256,
        "current_assessment_id": candidate.assessment_id,
        "current_manifest_sha256": candidate.manifest_sha256,
        "comparison": result.to_dict(),
    }


def compare_assessments(
    baseline: str | Path,
    current: str | Path,
    *,
    fail_on: str = "regression",
) -> CompareResult:
    """Compare two committed assessment bundles and apply the gate policy."""
    if fail_on not in {"never", "vuln", "regression"}:
        raise ComparisonError(f"invalid fail_on={fail_on!r}; expected never|vuln|regression")
    reference, candidate = _load_pair(baseline, current)
    return _compare(reference, candidate, fail_on=fail_on)


def compare_with_record(
    baseline: str | Path,
    current: str | Path,
    *,
    fail_on: str = "regression",
) -> tuple[CompareResult, dict[str, Any]]:
    """Compare once and return the decision plus the record binding both bundles."""
    if fail_on not in {"never", "vuln", "regression"}:
        raise ComparisonError(f"invalid fail_on={fail_on!r}; expected never|vuln|regression")
    reference, candidate = _load_pair(baseline, current)
    result = _compare(reference, candidate, fail_on=fail_on)
    return result, _record(reference, candidate, result)
