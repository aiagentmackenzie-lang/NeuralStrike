"""Sharing is an allowlisted summary, never a purportedly sanitized raw replay."""

from dataclasses import asdict, replace

import pytest
from typer.testing import CliRunner

from neuralstrike.corpus import load_corpus_dir
from neuralstrike.evaluation.runner import Probe, TrialRunner
from neuralstrike.evaluation.verdict import (
    EvidenceFidelity,
    Finding,
    SutResponse,
    ToolCall,
    TrialResult,
    Verdict,
)
from neuralstrike.main import app

SECRET = "SYNTHETIC_PRIVATE_CONTENT_8e6d7a"


@pytest.fixture
async def private_assessment(tmp_path):
    from neuralstrike.evaluation.assessment import AssessmentRecorder

    scenario = replace(load_corpus_dir()[0], id=SECRET, legitimate_task=SECRET, source_path=SECRET)
    recorder = AssessmentRecorder(
        tmp_path,
        scenarios=[scenario],
        base_seed=7,
        trials=1,
        adapter="fixture",
        target=f"https://user:{SECRET}@fixture?key={SECRET}#{SECRET}",
        fail_on="vuln",
    )

    async def factory(index, seed, canary):
        return TrialResult(
            index,
            seed,
            0,
            Verdict.SUCCEEDED,
            EvidenceFidelity.VERBAL,
            scenario_id=scenario.id,
            inputs={"scenario": asdict(scenario), "secret": SECRET},
            payload=SECRET,
            response=SutResponse(
                text=SECRET, error=SECRET, tool_calls=(ToolCall(SECRET, {"password": SECRET}, SECRET),)
            ),
            findings=(
                Finding(
                    SECRET, Verdict.SUCCEEDED, EvidenceFidelity.VERBAL, evidence_quote=SECRET, reason=SECRET
                ),
            ),
        )

    result = await TrialRunner(base_seed=7, run_dir=None).run(Probe(scenario.id, "fixture", factory))
    recorder.add(result)
    recorder.finish(execution_error=SECRET)
    return recorder.path


async def test_summary_omits_all_freeform_content_and_is_not_replayable(private_assessment, tmp_path):
    from neuralstrike.evaluation.sharing import export_summary

    source = private_assessment
    before = {str(p.relative_to(source)): p.read_bytes() for p in source.rglob("*") if p.is_file()}
    destination = tmp_path / "summary.json"
    summary = export_summary(source, destination)
    encoded = destination.read_text()
    assert SECRET not in encoded
    assert summary["kind"] == "neuralstrike-share-summary"
    assert summary["artifact_policy"]["sanitized"] is True
    assert summary["artifact_policy"]["replayable"] is False
    assert summary["health"]["status"] == "incomplete"
    assert summary["overall"]["succeeded"] == 1
    assert summary["scenarios"][0]["scenario_ref"].startswith("sha256:")
    assert summary["scenarios"][0]["trials"][0]["evidence_id"].startswith("sha256:")
    assert destination.stat().st_mode & 0o777 == 0o600
    assert {str(p.relative_to(source)): p.read_bytes() for p in source.rglob("*") if p.is_file()} == before
    result = CliRunner().invoke(app, ["replay", str(destination), "--fail-on", "never"])
    assert result.exit_code == 3


async def test_summary_cli_preserves_health_and_rejects_source_overwrite(private_assessment, tmp_path):
    out = tmp_path / "summary.json"
    result = CliRunner().invoke(app, ["export-summary", str(private_assessment), "--out", str(out)])
    assert result.exit_code == 0, result.output  # Export success, not a security gate.
    assert "not a security gate" in result.output.lower()
    assert SECRET not in out.read_text()
    result = CliRunner().invoke(
        app, ["export-summary", str(private_assessment), "--out", str(private_assessment / "report.json")]
    )
    assert result.exit_code == 3, result.output


async def test_summary_export_validates_source_before_writing(private_assessment, tmp_path):
    from neuralstrike.evaluation.bundle import BundleError
    from neuralstrike.evaluation.sharing import export_summary

    child = next((private_assessment / "runs").iterdir())
    (child / "trial-0.json").write_text("corrupt")
    destination = tmp_path / "summary.json"
    with pytest.raises(BundleError):
        export_summary(private_assessment, destination)
    assert not destination.exists()
