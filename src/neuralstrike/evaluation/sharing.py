"""Allowlisted sharing summaries omit raw evidence and all freeform identifiers.

This is a deliberately non-replayable projection, not a scrubbed evidence bundle
or an anonymity guarantee. Hash references can link known observations.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from neuralstrike.evaluation.assessment import is_assessment_bundle, load_assessment
from neuralstrike.evaluation.bundle import BundleError, load_bundle
from neuralstrike.evaluation.health import assessment_health
from neuralstrike.evaluation.runner import _trial_to_dict
from neuralstrike.utils.artifacts import write_private_artifact

_ORIGINS = {"local-canary-fixture", "captured-provider-response", "unverified-observation"}


def _reference(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def _trial(document: dict[str, Any]) -> dict[str, Any]:
    origin = document.get("evidence_origin")
    return {
        "evidence_id": document["evidence_id"],
        "verdict": document["verdict"],
        "fidelity": document["fidelity"],
        "evidence_origin": origin if origin in _ORIGINS else "unverified-observation",
    }


def sharing_summary(source: str | Path) -> dict[str, Any]:
    """Validate the source and project only counts, enums and hash references."""
    scenarios = []
    if is_assessment_bundle(source):
        assessment = load_assessment(source)
        health = assessment.report.health
        if health is None:
            raise BundleError("assessment has no authoritative health")
        overall = assessment.report.overall()
        source_hash = assessment.manifest_sha256
        for result in assessment.report.scenario_results:
            scenarios.append(
                {
                    "scenario_ref": result.scenario.fingerprint,
                    "planned_trials": assessment.plan.trials,
                    "recorded_trials": result.total,
                    "verdict": result.verdict.value,
                    "counts": {
                        "succeeded": result.succeeded,
                        "resisted": result.resisted,
                        "inconclusive": result.inconclusive,
                    },
                    "trials": [
                        _trial(
                            {
                                "evidence_id": trial.evidence_id,
                                "verdict": trial.verdict.value,
                                "fidelity": trial.fidelity.value,
                                "evidence_origin": trial.evidence_origin,
                            }
                        )
                        for trial in result.trials
                    ],
                }
            )
    else:
        bundle = load_bundle(source)
        report = bundle.report
        health = assessment_health([report])
        source_hash = bundle.manifest_sha256
        score = report.score
        if score is None:
            raise BundleError("run has no authoritative score")
        overall = {
            "total": score.total,
            "succeeded": score.succeeded,
            "resisted": score.resisted,
            "inconclusive": score.inconclusive,
            "asr": score.measured_asr,
            "coverage": score.coverage,
        }
        scenarios.append(
            {
                "scenario_ref": _reference(report.meta.scenario_id),
                "planned_trials": report.meta.trials,
                "recorded_trials": len(report.trials),
                "counts": {
                    "succeeded": score.succeeded,
                    "resisted": score.resisted,
                    "inconclusive": score.inconclusive,
                },
                "trials": [_trial(_trial_to_dict(trial)) for trial in report.trials],
            }
        )
    return {
        "schema_version": 1,
        "kind": "neuralstrike-share-summary",
        "artifact_policy": {
            "classification": "share-summary",
            "sanitized": True,
            "replayable": False,
            "raw_evidence": False,
        },
        "source_manifest_sha256": source_hash,
        "verification": "source byte consistency; no author or target authenticity attestation",
        "health": health.to_dict(),
        "overall": overall,
        "scenarios": scenarios,
        "limitations": [
            "Summary omits inputs, outputs, policy text, target labels, identifiers and raw evidence.",
            "This summary cannot be replayed or establish remediation; retain the private source bundle.",
            "Hash references are linkable and are not an anonymity guarantee.",
            "Complete execution is not a security assurance; local receipts represent fixture effects.",
        ],
    }


def export_summary(source: str | Path, destination: str | Path) -> dict[str, Any]:
    original, output = Path(source).resolve(), Path(destination).resolve()
    if output == original or original in output.parents:
        raise BundleError("sharing output must be outside the source bundle")
    document = sharing_summary(original)
    write_private_artifact(output, json.dumps(document, indent=2, sort_keys=True))
    return document
