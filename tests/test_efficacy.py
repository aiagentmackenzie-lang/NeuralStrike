"""Ground truth is supplied separately; replay never learns labels from verdicts."""

import hashlib
import json

import pytest
from typer.testing import CliRunner

from neuralstrike.corpus import load_corpus_dir
from neuralstrike.evaluation.assessment import AssessmentRecorder, load_assessment
from neuralstrike.evaluation.runner import Probe, TrialRunner
from neuralstrike.evaluation.verdict import EvidenceFidelity, SutResponse, TrialResult, Verdict
from neuralstrike.main import app


@pytest.fixture
async def cohort(tmp_path):
    scenarios = load_corpus_dir()[:3]
    recorder = AssessmentRecorder(
        tmp_path / "runs",
        scenarios=scenarios,
        base_seed=7,
        trials=2,
        adapter="fixture",
        target="synthetic",
        fail_on="vuln",
    )
    for number, scenario in enumerate(scenarios[:2]):

        async def factory(index, seed, canary, sid=scenario.id, n=number):
            return TrialResult(
                index,
                seed,
                0,
                Verdict.SUCCEEDED if n == 0 else Verdict.RESISTED,
                EvidenceFidelity.VERBAL,
                scenario_id=sid,
                response=SutResponse(text="synthetic", error="later failure" if index else None),
            )

        recorder.add(
            await TrialRunner(base_seed=7, run_dir=None).run(Probe(scenario.id, "fixture", factory), trials=2)
        )
    recorder.finish()
    verified = load_assessment(recorder.path)
    labels = {
        "schema_version": 1,
        "cohort_id": "engineering-only",
        "assessment_manifest_sha256": verified.manifest_sha256,
        "application": {
            "source": "https://example.invalid/self-authored",
            "revision": "a" * 40,
            "license": "MIT",
            "configuration_sha256": "b" * 64,
            "capabilities": ["text"],
            "exclusions": ["no independent app"],
        },
        "cases": [
            {
                "scenario_id": scenario.id,
                "scenario_sha256": hashlib.sha256(
                    json.dumps(
                        verified.plan.scenarios[n].model_dump(by_alias=True),
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode()
                ).hexdigest(),
                "boundary_class": "privilege_change",
                "expected_violation": n != 1,
                "ground_truth_source": "synthetic independently supplied test label",
                "ground_truth_sha256": "c" * 64,
                "label_origin": "self_authored",
                "preconditions": "synthetic only",
                "benign_task": "not_measured",
                "benign_evidence_sha256": None,
            }
            for n, scenario in enumerate(scenarios)
        ],
    }
    # Use the existing canonical digest implementation.
    from neuralstrike.evaluation.identity import configuration_digest

    for label, scenario in zip(labels["cases"], verified.plan.scenarios, strict=True):
        label["scenario_sha256"] = configuration_digest(scenario.model_dump(by_alias=True))
    path = tmp_path / "labels.json"
    path.write_text(json.dumps(labels))
    return recorder.path, path, labels


async def test_replay_counts_missing_and_partial_without_manufacturing_negatives(cohort):
    from neuralstrike.evaluation.efficacy import evaluate_efficacy

    bundle, labels, _ = cohort
    before = {p: p.read_bytes() for p in bundle.rglob("*") if p.is_file()}
    result = evaluate_efficacy(bundle, labels)
    counts = result["overall"]
    assert {
        k: counts[k] for k in ("tp", "fp", "tn", "fn", "inconclusive", "missing", "errors", "planned")
    } == {"tp": 2, "fp": 0, "tn": 1, "fn": 0, "inconclusive": 3, "missing": 2, "errors": 2, "planned": 6}
    assert counts["recall"]["denominator"] == 2
    assert counts["specificity"]["denominator"] == 1
    assert counts["benign_passed"] == 0
    assert counts["benign_measured"] == 0
    assert counts["benign_completion"]["value"] is None
    assert result["independent_validation"] == "not_established"
    assert len(result["trials"]) == 6
    assert len(result["by_boundary_and_origin"]) >= 1
    assert {p: p.read_bytes() for p in bundle.rglob("*") if p.is_file()} == before


@pytest.mark.parametrize("damage", ["hash", "omit", "duplicate", "scenario", "bool", "benign", "extra"])
async def test_rejects_misaligned_or_ambiguous_labels(cohort, damage):
    from neuralstrike.evaluation.efficacy import evaluate_efficacy

    bundle, path, labels = cohort
    if damage == "hash":
        labels["assessment_manifest_sha256"] = "0" * 64
    elif damage == "omit":
        labels["cases"].pop()
    elif damage == "duplicate":
        labels["cases"].append(labels["cases"][0])
    elif damage == "scenario":
        labels["cases"][0]["scenario_sha256"] = "sha256:" + "0" * 64
    elif damage == "bool":
        labels["cases"][0]["expected_violation"] = "false"
    elif damage == "benign":
        labels["cases"][0]["benign_task"] = "passed"
    else:
        labels["invented"] = True
    path.write_text(json.dumps(labels))
    with pytest.raises(ValueError):
        evaluate_efficacy(bundle, path)


async def test_cli_exports_private_report_and_refuses_source_overwrite(cohort, tmp_path):
    bundle, labels, _ = cohort
    output = tmp_path / "metrics.json"
    result = CliRunner().invoke(app, ["efficacy", str(bundle), "--labels", str(labels), "--out", str(output)])
    assert result.exit_code == 0, result.output
    assert json.loads(output.read_text())["overall"]["planned"] == 6
    assert output.stat().st_mode & 0o777 == 0o600
    assert "not a security gate" in result.output.lower()
    rejected = CliRunner().invoke(
        app, ["efficacy", str(bundle), "--labels", str(labels), "--out", str(labels)]
    )
    assert rejected.exit_code == 3


async def test_confirmed_errors_do_not_hide_false_positives(cohort):
    from neuralstrike.evaluation.efficacy import evaluate_efficacy

    bundle, path, labels = cohort
    labels["cases"][0]["expected_violation"] = False
    path.write_text(json.dumps(labels))
    result = evaluate_efficacy(bundle, path)
    assert result["overall"]["fp"] == 2
    assert result["overall"]["precision"]["value"] == 0


async def test_fn_tn_and_benign_denominators_are_explicit(cohort):
    from neuralstrike.evaluation.efficacy import evaluate_efficacy

    bundle, path, labels = cohort
    labels["cases"][1]["expected_violation"] = True
    labels["cases"][1]["benign_task"] = "passed"
    labels["cases"][1]["benign_evidence_sha256"] = "d" * 64
    path.write_text(json.dumps(labels))
    result = evaluate_efficacy(bundle, path)
    assert result["overall"]["fn"] == 1
    assert result["overall"]["tn"] == 0
    assert result["overall"]["recall"]["denominator"] == 3
    assert result["overall"]["benign_measured"] == 1
    assert result["overall"]["benign_not_measured"] == 2
    assert result["overall"]["specificity"]["wilson_95"] is None


async def test_assessment_wide_error_withholds_negatives_but_preserves_positives(cohort):
    from neuralstrike.evaluation.efficacy import evaluate_efficacy

    bundle, path, _ = cohort
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    report_path = bundle / "report.json"
    from neuralstrike.evaluation.assessment import _assemble

    verified = load_assessment(bundle)
    report = _assemble(verified.plan, list(verified.runs), "cleanup failed").to_dict()
    manifest["execution_error"] = "cleanup failed"
    report_path.write_text(json.dumps(report))
    manifest["files"]["report.json"] = hashlib.sha256(report_path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest))
    labels = json.loads(path.read_text())
    labels["assessment_manifest_sha256"] = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    path.write_text(json.dumps(labels))
    result = evaluate_efficacy(bundle, path)
    assert result["overall"]["tp"] == 2
    assert result["overall"]["tn"] == 0
    assert result["overall"]["inconclusive"] == 4


async def test_controlled_application_packet_keeps_truth_separate_from_prediction(tmp_path):
    from examples.langgraph_account_support.efficacy import build_packet
    from examples.langgraph_account_support.verify import run_cycle

    root = await run_cycle(tmp_path)
    build_packet(root)
    for mode, key in [("vulnerable", "tp"), ("hardened", "tn"), ("regressed", "tp")]:
        result = json.loads((root / f"{mode}-efficacy.json").read_text())
        assert result["overall"][key] == 1
        assert result["overall"]["benign_completion"]["value"] == 1
        assert result["independent_validation"] == "not_established"
