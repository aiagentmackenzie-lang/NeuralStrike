"""Phase 0: formats count canonical trials, retaining oracle annotations separately."""

import json
import xml.etree.ElementTree as ET

import pytest

from neuralstrike.corpus import load_corpus_dir
from neuralstrike.evaluation.runner import RunMeta, RunReport
from neuralstrike.evaluation.scoring import score_trials
from neuralstrike.evaluation.verdict import EvidenceFidelity, Finding, SutResponse, TrialResult, Verdict
from neuralstrike.reports import build_corpus_run, to_json, to_junit, to_markdown, to_sarif
from neuralstrike.reports.pdf import _lines_for_run


def make_run(trials):
    scenario = load_corpus_dir()[0]
    report = RunReport(
        RunMeta("fixture", scenario.id, 0, len(trials), 0, 0.7, "2026-11-06T00:00:00Z"), trials=tuple(trials)
    )
    return build_corpus_run(
        scenarios=[scenario],
        reports=[report],
        base_seed=0,
        trials_per_scenario=len(trials),
        adapter="fixture",
        target="local",
    )


def trial(index, verdict, findings=(), error=None):
    return TrialResult(
        index,
        index,
        0,
        verdict,
        EvidenceFidelity.VERBAL,
        findings=tuple(findings),
        scenario_id=load_corpus_dir()[0].id,
        response=SutResponse(text="fixture", error=error),
    )


def finding(oracle, verdict, reason, advisory=False):
    return Finding(
        oracle,
        verdict,
        EvidenceFidelity.VERBAL,
        evidence_quote=reason,
        reason=reason,
        severity="high",
        advisory=advisory,
    )


def test_mixed_oracles_are_annotations_not_extra_trials():
    run = make_run(
        [
            trial(
                0,
                Verdict.INCONCLUSIVE,
                [
                    finding("one", Verdict.RESISTED, "insufficient observation"),
                    finding("judge", Verdict.SUCCEEDED, "advisory", True),
                ],
            ),
            trial(
                1,
                Verdict.SUCCEEDED,
                [
                    finding("one", Verdict.RESISTED, "other condition"),
                    finding("two", Verdict.SUCCEEDED, "actual violation"),
                ],
                error="late outage",
            ),
            trial(2, Verdict.RESISTED, [finding("one", Verdict.RESISTED, "complete resistance")]),
        ]
    )
    data = json.loads(to_json(run))
    outcomes = data["scenario_results"][0]["trials"]
    assert len(outcomes) == data["overall"]["total"] == 3
    assert [t["verdict"] for t in outcomes] == ["inconclusive", "succeeded", "resisted"]
    assert len(outcomes[0]["findings"]) == 2
    assert outcomes[1]["evidence_quote"] == "actual violation"
    assert outcomes[1]["error"] == "late outage"
    sarif_run = json.loads(to_sarif(run))["runs"][0]
    assert len(sarif_run["results"]) == 3
    assert [r["level"] for r in sarif_run["results"]] == ["note", "error", "none"]
    assert sarif_run["invocations"][0]["executionSuccessful"] is False
    assert len(sarif_run["results"][0]["properties"]["findings"]) == 2
    root = ET.fromstring(to_junit(run))
    assert root.get("tests") == "3"
    assert root.get("failures") == "1"
    assert root.get("skipped") == "1"
    assert len(root.findall(".//testcase")) == 3
    assert to_markdown(run).count("| 1 |") == 1
    assert "late outage" in to_markdown(run)
    assert sum("trial 1 " in line for line in _lines_for_run(run, 100)) == 1


@pytest.mark.parametrize(
    "verdict,expected", [(Verdict.RESISTED, Verdict.INCONCLUSIVE), (Verdict.SUCCEEDED, Verdict.SUCCEEDED)]
)
def test_late_error_cannot_prove_resistance_or_erase_violation(verdict, expected):
    observation = trial(0, verdict, error="late outage")
    run = make_run([observation])
    assert run.scenario_results[0].trials[0].verdict is expected
    assert run.health.complete is False
    assert run.health.conclusive == (1 if expected is Verdict.SUCCEEDED else 0)
    assert score_trials([observation]).inconclusive == (1 if expected is Verdict.INCONCLUSIVE else 0)


def test_zero_conclusive_asr_is_unavailable_in_all_exports():
    observation = trial(0, Verdict.INCONCLUSIVE)
    run = make_run([observation])
    data = json.loads(to_json(run))
    assert data["overall"]["asr"] is None
    assert data["scenario_results"][0]["evidence"]["score"]["risk_index"] is None
    invocation = json.loads(to_sarif(run))["runs"][0]["invocations"][0]
    assert invocation["properties"]["overall_asr"] is None
    assert "unavailable" in to_markdown(run).lower()
    assert any("ASR" in line and "unavailable" in line for line in _lines_for_run(run, 100))
    assert "ASR=unavailable" in score_trials([observation]).headline


def test_reports_reject_mislabeled_scenario_coverage():
    from dataclasses import replace

    scenarios = load_corpus_dir()[:2]
    observation = replace(trial(0, Verdict.RESISTED), scenario_id=scenarios[1].id)
    wrong_report = RunReport(RunMeta("fixture", scenarios[1].id, 0, 1, 0, 0.7, "t"), trials=(observation,))
    with pytest.raises(ValueError, match="scenario"):
        build_corpus_run(
            scenarios=scenarios[:1],
            reports=[wrong_report],
            base_seed=0,
            trials_per_scenario=1,
            adapter="fixture",
            target="local",
        )


def test_junit_distinguishes_execution_errors_from_unobserved_coverage():
    run = make_run([trial(0, Verdict.RESISTED, error="HTTP 503")])
    root = ET.fromstring(to_junit(run))
    assert root.get("errors") == "1"
    assert root.get("tests") == "1"
    assert root.get("skipped") == "0"
    assert root.find(".//error") is not None
    properties = {p.get("name"): p.get("value") for p in root.findall(".//properties/property")}
    assert properties["assessment_health"] == "incomplete"
    assert properties["inconclusive"] == "1"


def test_report_start_comes_from_recorded_run_metadata():
    scenario = load_corpus_dir()[0]
    report = RunReport(
        RunMeta(
            "fixture", scenario.id, 0, 1, 0, 0.7, "2026-11-06T00:00:00Z", completed_at="2026-11-06T00:02:00Z"
        ),
        trials=(trial(0, Verdict.RESISTED),),
    )
    run = build_corpus_run(
        scenarios=[scenario],
        reports=[report],
        base_seed=0,
        trials_per_scenario=1,
        adapter="fixture",
        target="local",
    )
    assert run.started_at == "2026-11-06T00:00:00Z"
    assert run.completed_at == "2026-11-06T00:02:00Z"
    assert json.loads(to_json(run))["completed_at"] == run.completed_at
    invocation = json.loads(to_sarif(run))["runs"][0]["invocations"][0]
    assert invocation["endTimeUtc"] == run.completed_at
    assert run.completed_at in to_markdown(run)
    assert run.completed_at in to_junit(run)
    assert any(run.completed_at in line for line in _lines_for_run(run, 95))


def test_reports_never_label_raw_evidence_as_sanitized():
    run = make_run([trial(0, Verdict.INCONCLUSIVE)])
    assert json.loads(to_json(run))["artifact_policy"] == {
        "classification": "private-raw",
        "sanitized": False,
    }
    invocation = json.loads(to_sarif(run))["runs"][0]["invocations"][0]
    assert invocation["properties"]["artifact_policy"]["sanitized"] is False
    assert "private raw" in to_markdown(run).lower()
    assert any("private raw" in line.lower() for line in _lines_for_run(run, 100))
    assert "private-raw" in to_junit(run)
