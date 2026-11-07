"""Every existing --fail-on surface enforces the same standalone health/policy."""

import json
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from neuralstrike.core.config import settings
from neuralstrike.evaluation.runner import RunMeta, RunReport
from neuralstrike.evaluation.scoring import score_trials
from neuralstrike.evaluation.verdict import EvidenceFidelity, SutResponse, TrialResult, Verdict
from neuralstrike.main import app


@pytest.mark.parametrize("command", ["evaluate", "pack"])
@pytest.mark.parametrize(
    "verdict,policy,expected",
    [
        (Verdict.SUCCEEDED, "vuln", 1),
        (Verdict.INCONCLUSIVE, "regression", 3),
        (Verdict.INCONCLUSIVE, "vuln", 3),
        (Verdict.INCONCLUSIVE, "never", 0),
        (Verdict.RESISTED, "vuln", 0),
    ],
)
def test_standalone_command_policy(tmp_path, monkeypatch, command, verdict, policy, expected):
    monkeypatch.setattr(settings, "skip_reachability_check", True)
    trial = TrialResult(
        0, 0, 0, verdict, EvidenceFidelity.VERBAL, scenario_id="s", response=SutResponse(text="fixture")
    )
    report = RunReport(
        RunMeta("fixture", "s", 0, 1, 0, 0.7, "2026-11-06T00:00:00Z"),
        trials=(trial,),
        score=score_trials([trial]),
    )
    args = [command, "--target", "fixture", "--fail-on", policy, "--run-dir", str(tmp_path / "runs")]
    if command == "pack":
        source = tmp_path / "probes.json"
        source.write_text(json.dumps([{"id": "p1", "prompt": "synthetic fixture"}]))
        args += ["--name", "local", "--import-probes", str(source)]
    with patch("neuralstrike.evaluation.runner.TrialRunner.run", AsyncMock(return_value=report)):
        result = CliRunner().invoke(app, args)
    assert result.exit_code == expected, result.output
    assert ("incomplete" if verdict is Verdict.INCONCLUSIVE else "complete") in result.output.lower()
