"""NS-02: transport outages are incomplete assessments, never security passes."""

import json
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from neuralstrike.adapters.openai_endpoint import OpenAIEndpointAdapter
from neuralstrike.evaluation.verdict import SutResponse, ToolCall
from neuralstrike.main import app


@pytest.mark.parametrize("command", ["scan", "corpus"])
@pytest.mark.parametrize("policy,expected", [("vuln", 3), ("regression", 3), ("never", 0)])
def test_outage_exit_and_report_health(tmp_path, command, policy, expected):
    args = [
        command,
        "--adapter",
        "openai",
        "--url",
        "http://local.invalid",
        "--model",
        "fixture",
        "--fail-on",
        policy,
    ]
    if command == "scan":
        args += ["--run-dir", str(tmp_path / "runs")]
    else:
        args += ["--limit", "1", "--format", "sarif", "--out", str(tmp_path / "report")]
    with patch.object(OpenAIEndpointAdapter, "query", AsyncMock(return_value=SutResponse(error="HTTP 503"))):
        result = CliRunner().invoke(app, args)
    assert result.exit_code == expected, result.output
    assert "incomplete" in result.output.lower()
    assert "unavailable" in result.output.lower()
    if command == "corpus":
        sarif = json.loads((tmp_path / "report.sarif").read_text())
        assert sarif["runs"][0]["invocations"][0]["executionSuccessful"] is False


def test_scan_vuln_policy_without_baseline(tmp_path):
    response = SutResponse(
        tool_calls=(ToolCall(name="grant_admin_access", arguments={"user_id": "attacker"}),)
    )
    with patch.object(OpenAIEndpointAdapter, "query", AsyncMock(return_value=response)):
        result = CliRunner().invoke(
            app,
            [
                "scan",
                "--adapter",
                "openai",
                "--url",
                "http://local.invalid",
                "--model",
                "fixture",
                "--fail-on",
                "vuln",
                "--run-dir",
                str(tmp_path),
            ],
        )
    assert result.exit_code == 1, result.output


def test_mixed_trials_preserve_vulnerability_and_incomplete_health():
    from neuralstrike.evaluation.health import assessment_health
    from neuralstrike.evaluation.runner import RunMeta, RunReport
    from neuralstrike.evaluation.verdict import EvidenceFidelity, TrialResult, Verdict

    trials = tuple(
        TrialResult(i, i, 0, v, EvidenceFidelity.VERBAL, scenario_id="s")
        for i, v in enumerate([Verdict.SUCCEEDED, Verdict.INCONCLUSIVE])
    )
    report = RunReport(RunMeta("run", "s", 1, 2, 0, 0.7, "t"), trials=trials)
    health = assessment_health([report])
    assert health.succeeded == 1
    assert health.conclusive == 1
    assert health.status == "incomplete"
    assert health.exit_code("vuln") == 3


def test_report_health_is_independent_of_vulnerability():
    from neuralstrike.corpus import load_corpus_dir
    from neuralstrike.evaluation.runner import RunMeta, RunReport
    from neuralstrike.evaluation.verdict import EvidenceFidelity, TrialResult, Verdict
    from neuralstrike.reports import build_corpus_run, to_json, to_junit, to_markdown, to_sarif
    from neuralstrike.reports.pdf import _lines_for_run

    scenario = load_corpus_dir()[0]
    for verdict, status in [(Verdict.SUCCEEDED, "complete"), (Verdict.INCONCLUSIVE, "incomplete")]:
        trial = TrialResult(0, 0, 0, verdict, EvidenceFidelity.VERBAL, scenario_id=scenario.id)
        report = RunReport(RunMeta("run", scenario.id, 0, 1, 0, 0.7, "2026-11-06T00:00:00Z"), trials=(trial,))
        run = build_corpus_run(
            scenarios=[scenario],
            reports=[report],
            base_seed=0,
            trials_per_scenario=1,
            adapter="fixture",
            target="local",
        )
        assert json.loads(to_json(run))["health"]["status"] == status
        assert json.loads(to_sarif(run))["runs"][0]["invocations"][0]["executionSuccessful"] == (
            status == "complete"
        )
        assert f"Assessment health:** {status}" in to_markdown(run)
        assert f'"{status}"' in to_junit(run)
        assert any(f"Assessment health: {status}" in line for line in _lines_for_run(run, 100))


def test_wrong_trial_index_is_incomplete_without_baseline():
    from neuralstrike.evaluation.health import assessment_health
    from neuralstrike.evaluation.runner import RunMeta, RunReport
    from neuralstrike.evaluation.verdict import EvidenceFidelity, TrialResult, Verdict

    trial = TrialResult(99, 0, 0, Verdict.RESISTED, EvidenceFidelity.VERBAL, scenario_id="s")
    report = RunReport(RunMeta("r", "s", 0, 1, 0, 0.7, "t"), trials=(trial,))
    assert assessment_health([report]).exit_code("vuln") == 3


@pytest.mark.parametrize("policy", ["vuln", "regression", "never"])
def test_corrupt_baseline_is_runtime_exit_not_vulnerability(tmp_path, policy):
    from neuralstrike.evaluation.baseline import baseline_path

    baseline_path(tmp_path, "asi01-scan").write_text("{invalid JSON")
    with patch.object(OpenAIEndpointAdapter, "query", AsyncMock(return_value=SutResponse(text="fixture"))):
        result = CliRunner().invoke(
            app,
            [
                "scan",
                "--adapter",
                "openai",
                "--url",
                "http://fixture",
                "--model",
                "fixture",
                "--baseline-dir",
                str(tmp_path),
                "--fail-on",
                policy,
                "--run-dir",
                str(tmp_path / "runs"),
            ],
        )
    assert result.exit_code == 3, result.output
    assert "baseline" in result.output.lower()
    assert "valid json" in " ".join(result.output.lower().split())
