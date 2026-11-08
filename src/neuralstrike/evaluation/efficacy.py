"""Offline label/prediction comparison. Labels are assertions, never authenticated review.

A sidecar binds ground truth to exact assessment bytes and scenario content.
No target code, provider or oracle is executed. Export success is not a gate.
"""

from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field, model_validator

from neuralstrike.evaluation.assessment import load_assessment
from neuralstrike.evaluation.bundle import MAX_TRIALS, BundleError, _Document, _json, _read
from neuralstrike.evaluation.identity import configuration_digest
from neuralstrike.evaluation.statistics import wilson_ci
from neuralstrike.evaluation.verdict import Verdict, normalize_trial

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Text = Annotated[str, Field(min_length=1, max_length=4096)]


class ApplicationProvenance(_Document):
    source: Text
    revision: Text
    license: Text
    configuration_sha256: Digest
    capabilities: list[Text] = Field(min_length=1, max_length=128)
    exclusions: list[Text] = Field(max_length=128)


class GroundTruthCase(_Document):
    scenario_id: Text
    scenario_sha256: Digest
    boundary_class: Text
    expected_violation: bool
    ground_truth_source: Text
    ground_truth_sha256: Digest
    label_origin: Literal["self_authored", "upstream_assertion", "independent_review", "pilot_owner"]
    preconditions: Text
    benign_task: Literal["passed", "failed", "inconclusive", "not_measured"]
    benign_evidence_sha256: Digest | None

    @model_validator(mode="after")
    def evidence_required(self) -> GroundTruthCase:
        if self.benign_task != "not_measured" and self.benign_evidence_sha256 is None:
            raise ValueError("measured benign task requires a separate evidence digest")
        return self


class EfficacyLabels(_Document):
    schema_version: Literal[1]
    cohort_id: Text
    assessment_manifest_sha256: Digest
    application: ApplicationProvenance
    cases: list[GroundTruthCase] = Field(min_length=1, max_length=MAX_TRIALS)


def _rate(numerator: int, denominator: int) -> dict[str, Any]:
    return {
        "numerator": numerator,
        "denominator": denominator,
        "value": numerator / denominator if denominator else None,
        "wilson_95": list(wilson_ci(numerator, denominator)) if denominator else None,
    }


def _counts(rows: list[dict[str, Any]]) -> dict[str, Any]:
    counts = Counter(row["classification"] for row in rows)
    benign = Counter(row["benign_task"] for row in rows if row["trial_index"] == 0)
    return {
        **{key: counts[key] for key in ("tp", "fp", "tn", "fn", "inconclusive")},
        "planned": len(rows),
        "missing": sum(not row["recorded"] for row in rows),
        "errors": sum(row["execution_error"] for row in rows),
        "conclusive": sum(counts[key] for key in ("tp", "fp", "tn", "fn")),
        "precision": _rate(counts["tp"], counts["tp"] + counts["fp"]),
        "recall": _rate(counts["tp"], counts["tp"] + counts["fn"]),
        "specificity": _rate(counts["tn"], counts["tn"] + counts["fp"]),
        "benign_passed": benign["passed"],
        "benign_measured": benign["passed"] + benign["failed"],
        "benign_inconclusive": benign["inconclusive"],
        "benign_not_measured": benign["not_measured"],
        "benign_completion": _rate(benign["passed"], benign["passed"] + benign["failed"]),
    }


def evaluate_efficacy(bundle: str | Path, labels_path: str | Path) -> dict[str, Any]:
    """Compare all planned trials, including missing ones, against external labels.

    Binary truth describes this exact scenario/configuration boundary outcome,
    not hypothetical vulnerability reachability. Ratios exclude inconclusives;
    their counts and planned denominators remain explicit. Wilson intervals are
    descriptive binomial summaries, not independence or population guarantees.
    """
    assessment = load_assessment(bundle)
    raw = _read(Path(labels_path))
    labels = EfficacyLabels.model_validate(_json(raw))
    if labels.assessment_manifest_sha256 != assessment.manifest_sha256:
        raise BundleError("ground truth references a different assessment manifest")
    by_id = {case.scenario_id: case for case in labels.cases}
    selected = {scenario.id for scenario in assessment.plan.scenarios}
    if len(by_id) != len(labels.cases) or set(by_id) != selected:
        raise BundleError("labels must match the entire selected scenario plan exactly once")
    runs = {run.meta.scenario_id: run for run in assessment.runs}
    rows: list[dict[str, Any]] = []
    for scenario in assessment.plan.scenarios:
        case = by_id[scenario.id]
        if case.scenario_sha256 != configuration_digest(scenario.model_dump(by_alias=True)):
            raise BundleError("ground truth scenario content differs from the assessment plan")
        run = runs.get(scenario.id)
        trials = {trial.trial_index: normalize_trial(trial) for trial in run.trials} if run else {}
        for index in range(assessment.plan.trials):
            trial = trials.get(index)
            error = bool(trial and (trial.error or (trial.response and trial.response.error)))
            verdict = trial.verdict if trial else Verdict.INCONCLUSIVE
            # An assessment-wide failure has no trustworthy per-trial scope.
            # Preserve positive evidence; withhold all negative conclusions.
            if assessment.report.execution_error and verdict is Verdict.RESISTED:
                verdict = Verdict.INCONCLUSIVE
            classification = "inconclusive"
            if verdict is Verdict.SUCCEEDED:
                classification = "tp" if case.expected_violation else "fp"
            elif verdict is Verdict.RESISTED:
                classification = "fn" if case.expected_violation else "tn"
            origins = (
                sorted(
                    {
                        finding.evidence_origin
                        for finding in trial.findings
                        if finding.verdict is verdict and finding.evidence_origin
                    }
                )
                if trial
                else []
            )
            rows.append(
                {
                    "scenario_id": scenario.id,
                    "trial_index": index,
                    "run_id": run.meta.run_id if run else None,
                    "seed": trial.seed if trial else None,
                    "recorded": trial is not None,
                    "expected_violation": case.expected_violation,
                    "prediction": verdict.value,
                    "classification": classification,
                    "boundary_class": case.boundary_class,
                    "evidence_origin": origins or ["unattributed"],
                    "execution_error": error,
                    "assessment_execution_error": bool(assessment.report.execution_error),
                    "fidelity": trial.fidelity.value if trial else None,
                    # Benign evidence is case-level; count once, never multiply by k.
                    "benign_task": case.benign_task if index == 0 else "not_measured",
                }
            )
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[(row["boundary_class"], "+".join(row["evidence_origin"]))].append(row)
    return {
        "schema_version": 1,
        "kind": "neuralstrike-efficacy",
        "cohort_id": labels.cohort_id,
        "assessment_id": assessment.assessment_id,
        "assessment_manifest_sha256": assessment.manifest_sha256,
        "labels_sha256": hashlib.sha256(raw).hexdigest(),
        "labels": labels.model_dump(),
        "assessment_health": assessment.report.health.to_dict() if assessment.report.health else None,
        "independent_validation": "not_established",
        "limitations": [
            "Label origins and application provenance are supplied assertions, not authenticated review.",
            "No target/model/oracle calls; findings are recorded predictions, not independent ground truth.",
            "Conclusive-only ratios; missing and incomplete negatives remain inconclusive.",
            "Repeated trials may be dependent; Wilson intervals do not establish population efficacy.",
            "Benign task evidence is case-level and counted once; no remediation gate is inferred.",
        ],
        "overall": _counts(rows),
        "by_boundary_and_origin": [
            {"boundary_class": boundary, "evidence_origin": origin, **_counts(group)}
            for (boundary, origin), group in sorted(groups.items())
        ],
        "trials": rows,
    }
