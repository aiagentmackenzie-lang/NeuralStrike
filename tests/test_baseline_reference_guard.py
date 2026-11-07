"""A candidate must not overwrite the reference it is about to gate against."""

import json
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from neuralstrike.core.config import settings
from neuralstrike.evaluation.runner import RunMeta, RunReport
from neuralstrike.evaluation.scoring import score_trials
from neuralstrike.evaluation.verdict import EvidenceFidelity, TrialResult, Verdict
from neuralstrike.main import app


@pytest.mark.parametrize("command", ["scan", "evaluate", "pack"])
@pytest.mark.parametrize("alias", [False, True])
def test_compare_and_save_same_reference_is_rejected_before_execution(tmp_path, monkeypatch, command, alias):
    monkeypatch.setattr(settings, "skip_reachability_check", True)
    reference = tmp_path / "reference"
    reference.mkdir()
    original = reference / "s.baseline.json"
    original.write_text("trusted reference sentinel")
    destination = tmp_path / "alias" if alias else reference
    if alias:
        destination.symlink_to(reference, target_is_directory=True)
    trial = TrialResult(0, 0, 0, Verdict.RESISTED, EvidenceFidelity.VERBAL, scenario_id="s")
    report = RunReport(
        RunMeta("candidate", "s", 0, 1, 0, 0.7, "t"), trials=(trial,), score=score_trials([trial])
    )
    args = [command, "--baseline-dir", str(reference), "--save-baseline-dir", str(destination)]
    if command == "scan":
        args += ["--adapter", "openai", "--url", "http://127.0.0.1:1", "--model", "synthetic"]
    else:
        args += ["--target", "synthetic"]
    if command == "pack":
        probes = tmp_path / "probes.json"
        probes.write_text(json.dumps([{"id": "s", "prompt": "synthetic"}]))
        args += ["--name", "local", "--import-probes", str(probes)]
    with patch("neuralstrike.evaluation.runner.TrialRunner.run", AsyncMock(return_value=report)) as run:
        result = CliRunner().invoke(app, args)
    assert result.exit_code == 3, result.output
    assert "reference" in result.output.lower()
    run.assert_not_called()
    assert original.read_text() == "trusted reference sentinel"
