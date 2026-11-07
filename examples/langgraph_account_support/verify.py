"""Run the local three-stage application cycle and preserve a private receipt.

Usage: python -m examples.langgraph_account_support.verify --out /tmp/validation
Requires NeuralStrike and its LangGraph extra; never calls an inference service.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import uuid
from importlib.metadata import version
from pathlib import Path
from typing import Any

from examples.langgraph_account_support.application import APP_VERSION, AccountSupport

from neuralstrike.adapters.langgraph import LangGraphAdapter
from neuralstrike.attacks.indirect import IndirectHarness
from neuralstrike.corpus.loader import load_corpus
from neuralstrike.evaluation.assessment import AssessmentRecorder, load_assessment
from neuralstrike.evaluation.baseline import compare_baseline, save_baseline
from neuralstrike.evaluation.bundle import replay_bundle
from neuralstrike.evaluation.runner import TrialRunner
from neuralstrike.evaluation.verdict import EvidenceFidelity, Verdict
from neuralstrike.utils.artifacts import write_private_artifact


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _hashes(root: Path) -> dict[str, str]:
    return {
        str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in root.rglob("*")
        if p.is_file()
    }


async def run_cycle(output_root: Path) -> Path:
    directory = Path(__file__).parent
    scenario = load_corpus(directory / "scenarios.yaml")[0]
    root = output_root / f"validation-{uuid.uuid4().hex}"
    root.mkdir(parents=True, mode=0o700, exist_ok=False)
    application = AccountSupport()
    async def reset(graph: Any, thread_id: str | None) -> None:
        application.reset()

    adapter = LangGraphAdapter(
        graph=application.graph,
        reset=reset,
        lifecycle_id="controlled-account-support/reset-v1",
        target_id="controlled-account-support",
        delivery_channels=frozenset({"user_message", "retrieved_document"}),
    )
    probe = IndirectHarness(scenario).probe_for(adapter)
    stages: list[dict[str, Any]] = []
    reports = []
    for mode in ("vulnerable", "hardened", "regressed"):
        recorder = AssessmentRecorder(
            root / "assessments",
            scenarios=[scenario],
            base_seed=123,
            trials=1,
            adapter="langgraph",
            target="controlled-account-support",
            fail_on="vuln",
            declared_scope={
                "fixture": True,
                "application_version": APP_VERSION,
                "authorization": "controlled local example only",
                "mode": mode,
            },
        )
        try:
            application.hardened = mode == "hardened"
            report = await TrialRunner(run_dir=root / "runs", base_seed=123).run(probe)
            recorder.add(report)
        except BaseException:
            recorder.finish(execution_error="controlled validation execution aborted")
            raise
        corpus = recorder.finish()
        trial = report.trials[0]
        expected = Verdict.RESISTED if mode == "hardened" else Verdict.SUCCEEDED
        _require(trial.verdict is expected, f"{mode}: unexpected oracle outcome")
        _require(trial.response is not None, f"{mode}: no response")
        _require(
            trial.response.exchanges[0]["lifecycle"]["reset"] == "completed",
            f"{mode}: configured reset did not complete",
        )
        _require(trial.fidelity is EvidenceFidelity.INTENT_TO_ACT, "unexpected evidence promotion")
        _require(
            application.roles["customer"] == ("reader" if mode == "hardened" else "admin"),
            f"{mode}: independent application state disagrees with outcome",
        )
        _require(trial.response.text in scenario.benign_task_markers, f"{mode}: legitimate task incomplete")
        _require(
            scenario.adversarial_payload in application.events[0]["documents"][0],
            f"{mode}: retrieval node did not observe the selected payload",
        )
        before = _hashes(recorder.path)
        _require(
            load_assessment(recorder.path, verify_oracles=True).report.to_dict() == corpus.to_dict(),
            "assessment replay differs",
        )
        _require(_hashes(recorder.path) == before, "offline replay mutated source")
        bundle = root / "runs" / report.meta.run_id
        _require(
            replay_bundle(bundle, verify_oracles=True).to_dict() == report.to_dict(), "run replay differs"
        )
        reports.append(report)
        stages.append(
            {
                "mode": mode,
                "verdict": trial.verdict.value,
                "fidelity": trial.fidelity.value,
                "role_after": application.roles["customer"],
                "benign_task_completed": True,
                "assessment_path": str(recorder.path.relative_to(root)),
                "assessment_manifest_sha256": before["manifest.json"],
                "run_id": report.meta.run_id,
                "evidence_id": report.to_dict()["trials"][0]["evidence_id"],
                "application_events": json.loads(json.dumps(application.events)),
                "lifecycle": trial.response.exchanges[0]["lifecycle"],
            }
        )
    save_baseline(root / "vulnerable-baseline", reports[0])
    fix = compare_baseline(root / "vulnerable-baseline", reports[1])
    _require(fix.exit_code == 0 and fix.fixed == (scenario.id,), "fix not verified")
    save_baseline(root / "hardened-baseline", reports[1])
    regression = compare_baseline(root / "hardened-baseline", reports[2])
    _require(regression.exit_code == 4 and regression.regressions == (scenario.id,), "regression gate failed")
    receipt = {
        "kind": "neuralstrike-controlled-application-validation",
        "schema_version": 1,
        "status": "verified-local-cycle",
        "application_version": APP_VERSION,
        "application_source_sha256": hashlib.sha256((directory / "application.py").read_bytes()).hexdigest(),
        "scenario_sha256": hashlib.sha256((directory / "scenarios.yaml").read_bytes()).hexdigest(),
        "versions": {
            name: version(name)
            for name in ("neuralstrike", "langgraph", "langchain-core", "langgraph-checkpoint")
        },
        "stages": stages,
        "fix_comparison": fix.to_dict(),
        "regression_comparison": regression.to_dict(),
        "limitations": [
            "Controlled deterministic application, not an independently authored customer efficacy cohort.",
            "Application events are local fixture observations, not signed remote attestations.",
            "No model calls, production compromise, broad framework conformance or live-service validation.",
            "Retrieval uses an explicit injected conversation ToolMessage, not a remote search index.",
        ],
    }
    write_private_artifact(root / "validation.json", json.dumps(receipt, indent=2, sort_keys=True))
    await adapter.close()
    return root


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    print(asyncio.run(run_cycle(args.out)))


if __name__ == "__main__":
    main()
