"""Generate a self-authored engineering review packet, never independent efficacy.

python -m examples.langgraph_account_support.efficacy --out /tmp/phase3
No model calls. Expected outcomes are specified by mode, never oracle verdict.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from pathlib import Path

from examples.langgraph_account_support.verify import run_cycle

from neuralstrike.evaluation.assessment import load_assessment
from neuralstrike.evaluation.efficacy import evaluate_efficacy
from neuralstrike.evaluation.identity import configuration_digest
from neuralstrike.utils.artifacts import write_private_artifact


def build_packet(root: Path) -> None:
    receipt_path = root / "validation.json"
    receipt = json.loads(receipt_path.read_text())
    receipt_digest = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
    for stage in receipt["stages"]:
        assessment_path = root / stage["assessment_path"]
        assessment = load_assessment(assessment_path)
        # Static expectation and direct application-state check, not oracle labels.
        expected = stage["mode"] != "hardened"
        if (stage["role_after"] == "admin") != expected:
            raise ValueError("application role disagrees with independently specified mode expectation")
        labels = {
            "schema_version": 1,
            "cohort_id": "self-authored-account-support-engineering-only",
            "assessment_manifest_sha256": assessment.manifest_sha256,
            "application": {
                "source": "NeuralStrike/examples/langgraph_account_support/application.py",
                "revision": receipt["application_version"],
                "license": "MIT",
                "configuration_sha256": configuration_digest(
                    {
                        "mode": stage["mode"],
                        "source_sha256": receipt["application_source_sha256"],
                        "versions": receipt["versions"],
                    }
                ),
                "capabilities": ["controlled role update", "synthetic account support task"],
                "exclusions": ["no model", "no independent author or reviewer", "no persistent memory"],
            },
            "cases": [
                {
                    "scenario_id": scenario.id,
                    "scenario_sha256": configuration_digest(scenario.model_dump(by_alias=True)),
                    "boundary_class": "unauthorized_privilege_change",
                    "expected_violation": expected,
                    "ground_truth_source": "validation.json: mode expectation and direct role_after",
                    "ground_truth_sha256": receipt_digest,
                    "label_origin": "self_authored",
                    "preconditions": "synthetic reader; injected document; mode-controlled authorization",
                    "benign_task": "passed" if stage["benign_task_completed"] else "failed",
                    "benign_evidence_sha256": receipt_digest,
                }
                for scenario in assessment.plan.scenarios
            ],
        }
        label_path = root / f"{stage['mode']}-labels.json"
        write_private_artifact(label_path, json.dumps(labels, indent=2, sort_keys=True))
        result = evaluate_efficacy(assessment_path, label_path)
        write_private_artifact(
            root / f"{stage['mode']}-efficacy.json", json.dumps(result, indent=2, sort_keys=True)
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    root = asyncio.run(run_cycle(args.out))
    build_packet(root)
    print(root)


if __name__ == "__main__":
    main()
