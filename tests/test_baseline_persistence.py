"""Baseline snapshots must be private, attributable and atomically replaced."""

import json

import pytest

from neuralstrike.evaluation.baseline import BaselineError, compare_baseline, save_baseline
from neuralstrike.evaluation.runner import RunMeta, RunReport
from neuralstrike.evaluation.verdict import EvidenceFidelity, TrialResult, Verdict


def reference(verdict=Verdict.RESISTED):
    trial = TrialResult(0, 1, 0, verdict, EvidenceFidelity.VERBAL, scenario_id="s")
    return RunReport(
        RunMeta("reference-execution", "s", 1, 1, 0, 0.7, "2026-11-06T00:00:00Z"), trials=(trial,)
    )


def test_baseline_is_private_and_points_to_its_execution(tmp_path):
    path = save_baseline(tmp_path, reference())
    assert path.stat().st_mode & 0o777 == 0o600
    payload = json.loads(path.read_text())
    assert payload["run_id"] == "reference-execution"
    assert payload["schema_version"] == 1
    assert compare_baseline(tmp_path, reference()).exit_code == 0


def test_failed_replace_preserves_trusted_reference(tmp_path, monkeypatch):
    from neuralstrike.utils import artifacts

    path = save_baseline(tmp_path, reference())
    original = path.read_bytes()

    def fail_replace(*args):
        raise OSError("synthetic disk failure")

    monkeypatch.setattr(artifacts.os, "replace", fail_replace)
    with pytest.raises(OSError, match="synthetic disk failure"):
        save_baseline(tmp_path, reference(Verdict.SUCCEEDED))
    assert path.read_bytes() == original
    assert not list(tmp_path.glob("*.tmp"))


def test_unknown_baseline_schema_is_rejected(tmp_path):
    path = save_baseline(tmp_path, reference())
    payload = json.loads(path.read_text())
    payload["schema_version"] = 999
    path.write_text(json.dumps(payload))
    with pytest.raises(BaselineError, match="schema"):
        compare_baseline(tmp_path, reference())


@pytest.mark.parametrize("field", ["run_id", "trial_indices"])
def test_declared_schema_requires_its_execution_metadata(tmp_path, field):
    path = save_baseline(tmp_path, reference())
    payload = json.loads(path.read_text())
    payload.pop(field)
    path.write_text(json.dumps(payload))
    with pytest.raises(BaselineError, match="metadata"):
        compare_baseline(tmp_path, reference())
