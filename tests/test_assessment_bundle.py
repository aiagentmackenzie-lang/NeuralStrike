"""A portable assessment retains the complete selected plan, including omissions."""

import hashlib
import json
from dataclasses import replace
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from typer.testing import CliRunner

from neuralstrike.adapters.openai_endpoint import OpenAIEndpointAdapter
from neuralstrike.attacks.indirect import IndirectHarness
from neuralstrike.corpus import load_corpus_dir
from neuralstrike.evaluation.runner import Probe, TrialRunner
from neuralstrike.evaluation.verdict import EvidenceFidelity, TrialResult, Verdict
from neuralstrike.main import app


def files(path):
    return {str(p.relative_to(path)): p.read_bytes() for p in path.rglob("*") if p.is_file()}


@pytest.fixture
async def recorded(tmp_path):
    from neuralstrike.evaluation.assessment import AssessmentRecorder

    scenarios = load_corpus_dir()[:2]
    recorder = AssessmentRecorder(
        tmp_path / "assessments",
        scenarios=scenarios,
        base_seed=7,
        trials=1,
        adapter="openai",
        target="http://fixture",
        fail_on="vuln",
    )
    for scenario in scenarios:
        adapter = OpenAIEndpointAdapter(
            "http://fixture",
            model="synthetic",
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    200, json={"choices": [{"message": {"content": "synthetic fixture"}}]}
                )
            ),
        )
        try:
            report = await TrialRunner(base_seed=7, run_dir=tmp_path / "original-runs").run(
                IndirectHarness(scenario).probe_for(adapter)
            )
        finally:
            await adapter.close()
        recorder.add(report)
    result = recorder.finish()
    return recorder.path, result


async def test_portable_bundle_replays_complete_selection_offline(recorded, tmp_path):
    from neuralstrike.evaluation.assessment import load_assessment

    path, original = recorded
    before = files(path)
    moved = tmp_path / "portable-copy"
    path.rename(moved)
    with patch.object(httpx.AsyncClient, "send", AsyncMock(side_effect=AssertionError("no network"))):
        loaded = load_assessment(moved, verify_oracles=True)
    assert loaded.report.to_dict() == original.to_dict()
    assert loaded.report.health.selected == 2
    assert [s.scenario.id for s in loaded.report.scenario_results] == [s.id for s in load_corpus_dir()[:2]]
    assert files(moved) == before
    assert (moved / "manifest.json").stat().st_mode & 0o777 == 0o600


async def test_missing_selected_scenario_is_not_a_smaller_passing_assessment(tmp_path):
    from neuralstrike.evaluation.assessment import AssessmentRecorder, load_assessment

    scenarios = load_corpus_dir()[:2]
    recorder = AssessmentRecorder(
        tmp_path,
        scenarios=scenarios,
        base_seed=7,
        trials=1,
        adapter="fixture",
        target="synthetic",
        fail_on="vuln",
    )

    async def factory(index, seed, canary):
        return TrialResult(
            index, seed, 0, Verdict.RESISTED, EvidenceFidelity.VERBAL, scenario_id=scenarios[0].id
        )

    report = await TrialRunner(base_seed=7, run_dir=None).run(Probe(scenarios[0].id, "fixture", factory))
    recorder.add(report)
    recorder.finish()
    loaded = load_assessment(recorder.path)
    assert loaded.report.health.selected == 2
    assert loaded.report.health.attempted == 1
    assert loaded.report.health.complete is False
    missing = loaded.report.scenario_results[1]
    assert missing.total == 0  # No fabricated attempt or dummy trial.
    assert loaded.report.to_dict()["scenario_results"][1]["recording_status"] == "missing"
    assert missing.verdict is Verdict.INCONCLUSIVE
    assert loaded.report.health.exit_code("vuln") == 3
    result = CliRunner().invoke(app, ["replay", str(recorder.path)])
    assert result.exit_code == 3, result.output
    assert "incomplete" in result.output.lower()


@pytest.mark.parametrize(
    "damage",
    [
        "child_missing",
        "child_hash",
        "omit_link",
        "plan",
        "summary",
        "summary_array",
        "schema",
        "symlink",
        "running",
        "extra_child",
    ],
)
async def test_assessment_corruption_never_passes_even_report_only(recorded, damage, tmp_path):
    from neuralstrike.evaluation.assessment import load_assessment
    from neuralstrike.evaluation.bundle import BundleError

    path, _ = recorded
    manifest_path = path / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    children = list((path / "runs").iterdir())
    if damage == "child_missing":
        (children[0] / "trial-0.json").unlink()
    elif damage == "child_hash":
        (children[0] / "trial-0.json").write_text("{}")
    elif damage == "omit_link":
        manifest["runs"].pop()
    elif damage == "plan":
        plan = json.loads((path / "plan.json").read_text())
        plan["scenarios"].pop()
        (path / "plan.json").write_text(json.dumps(plan))
        manifest["files"]["plan.json"] = hashlib.sha256((path / "plan.json").read_bytes()).hexdigest()
    elif damage in {"summary", "summary_array"}:
        (path / "report.json").write_text("[]" if damage == "summary_array" else "{}")
        manifest["files"]["report.json"] = hashlib.sha256((path / "report.json").read_bytes()).hexdigest()
    elif damage == "schema":
        manifest["schema_version"] = 999
    elif damage == "symlink":
        original = children[0]
        relocated = tmp_path / "outside-child"
        original.rename(relocated)
        original.symlink_to(relocated, target_is_directory=True)
    elif damage == "running":
        manifest["state"] = "running"
    else:
        (path / "runs" / "unlisted").mkdir()
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(BundleError):
        load_assessment(path)
    result = CliRunner().invoke(app, ["replay", str(path), "--fail-on", "never"])
    assert result.exit_code == 3, result.output


async def test_recorder_plan_is_frozen_before_any_result_and_rejects_wrong_context(tmp_path):
    from neuralstrike.evaluation.assessment import AssessmentRecorder, load_assessment
    from neuralstrike.evaluation.bundle import BundleError

    scenarios = load_corpus_dir()[:1]
    recorder = AssessmentRecorder(
        tmp_path,
        scenarios=scenarios,
        base_seed=7,
        trials=1,
        adapter="fixture",
        target="synthetic",
        fail_on="vuln",
    )
    before = (recorder.path / "plan.json").read_bytes()
    assert json.loads((recorder.path / "manifest.json").read_text())["state"] == "running"
    with pytest.raises(BundleError):
        load_assessment(recorder.path)

    async def factory(index, seed, canary):
        return TrialResult(
            index, seed, 0, Verdict.RESISTED, EvidenceFidelity.VERBAL, scenario_id=scenarios[0].id
        )

    report = await TrialRunner(base_seed=99, run_dir=None).run(Probe(scenarios[0].id, "fixture", factory))
    with pytest.raises(BundleError, match="context"):
        recorder.add(report)
    assert (recorder.path / "plan.json").read_bytes() == before
    assert not list((recorder.path / "runs").iterdir())


def test_corpus_cli_records_assessment_before_adapter_failure(tmp_path):
    with patch(
        "neuralstrike.adapters.openai_endpoint.OpenAIEndpointAdapter",
        side_effect=RuntimeError("synthetic setup failure"),
    ):
        result = CliRunner().invoke(
            app,
            [
                "corpus",
                "--adapter",
                "openai",
                "--url",
                "http://fixture",
                "--model",
                "synthetic",
                "--limit",
                "2",
                "--run-dir",
                str(tmp_path / "runs"),
                "--out",
                str(tmp_path / "report"),
            ],
        )
    assert result.exit_code == 3, result.output
    paths = list((tmp_path / "runs").glob("assessment-*"))
    assert len(paths) == 1
    from neuralstrike.evaluation.assessment import load_assessment

    loaded = load_assessment(paths[0])
    assert loaded.report.health.selected == 2
    assert loaded.report.health.attempted == 0
    assert loaded.report.health.complete is False
    assert loaded.report.execution_error


async def test_child_with_changed_scenario_contents_cannot_claim_the_frozen_plan(tmp_path):
    from dataclasses import asdict

    from neuralstrike.evaluation.assessment import AssessmentRecorder
    from neuralstrike.evaluation.bundle import BundleError

    scenario = load_corpus_dir()[0]
    recorder = AssessmentRecorder(
        tmp_path,
        scenarios=[scenario],
        base_seed=7,
        trials=1,
        adapter="fixture",
        target="synthetic",
        fail_on="vuln",
    )
    changed = replace(scenario, legitimate_task="different selected task")

    async def factory(index, seed, canary):
        return TrialResult(
            index,
            seed,
            0,
            Verdict.RESISTED,
            EvidenceFidelity.VERBAL,
            scenario_id=scenario.id,
            inputs={"scenario": asdict(changed)},
        )

    report = await TrialRunner(base_seed=7, run_dir=None).run(Probe(scenario.id, "fixture", factory))
    with pytest.raises(BundleError, match="context"):
        recorder.add(report)


async def test_assessment_rescore_preserves_selection_and_original_bytes(recorded, tmp_path):
    from neuralstrike.evaluation.assessment import load_assessment, rescore_assessment
    from neuralstrike.oracles.forbidden_tool import ForbiddenToolOracle, ForbiddenToolSpec

    source, original = recorded
    before = files(source)
    oracle = ForbiddenToolOracle(ForbiddenToolSpec(forbidden_tools=("synthetic_tool",)))
    with patch.object(httpx.AsyncClient, "send", AsyncMock(side_effect=AssertionError("no network"))):
        derived = rescore_assessment(source, [oracle], output_root=tmp_path / "derived", oracle_version="v2")
    loaded = load_assessment(derived.path, verify_oracles=True)
    assert loaded.assessment_id != original.assessment_id
    assert [s.scenario.id for s in loaded.report.scenario_results] == [
        s.scenario.id for s in original.scenario_results
    ]
    assert loaded.report.health.selected == original.health.selected
    assert files(source) == before
    assert loaded.plan.declared_scope == json.loads(before["plan.json"])["declared_scope"]
    parent_manifest = json.loads((loaded.path / "manifest.json").read_text())
    assert parent_manifest["provenance"]["source_assessment_id"] == original.assessment_id
    assert (
        parent_manifest["provenance"]["source_manifest_sha256"]
        == hashlib.sha256(before["manifest.json"]).hexdigest()
    )
    for old, new in zip(original.scenario_results, loaded.report.scenario_results, strict=True):
        assert [trial.evidence_id for trial in old.trials] == [trial.evidence_id for trial in new.trials]


async def test_assessment_wide_error_cannot_pass_with_all_conclusive_children(tmp_path):
    from neuralstrike.evaluation.assessment import AssessmentRecorder, load_assessment

    scenario = load_corpus_dir()[0]
    recorder = AssessmentRecorder(
        tmp_path,
        scenarios=[scenario],
        base_seed=7,
        trials=1,
        adapter="fixture",
        target="synthetic",
        fail_on="vuln",
    )

    async def factory(index, seed, canary):
        return TrialResult(index, seed, 0, Verdict.RESISTED, EvidenceFidelity.VERBAL, scenario_id=scenario.id)

    result = await TrialRunner(base_seed=7, run_dir=None).run(Probe(scenario.id, "fixture", factory))
    recorder.add(result)
    recorder.finish(execution_error="synthetic cleanup failure")
    loaded = load_assessment(recorder.path)
    assert loaded.report.health.selected == loaded.report.health.conclusive == 1
    assert loaded.report.health.complete is False
    assert CliRunner().invoke(app, ["replay", str(recorder.path)]).exit_code == 3


async def test_assessment_rescore_keeps_missing_scenarios_and_rejects_source_output(tmp_path):
    from neuralstrike.evaluation.assessment import AssessmentRecorder, rescore_assessment
    from neuralstrike.evaluation.bundle import BundleError

    recorder = AssessmentRecorder(
        tmp_path,
        scenarios=load_corpus_dir()[:2],
        base_seed=7,
        trials=1,
        adapter="fixture",
        target="synthetic",
        fail_on="vuln",
    )
    recorder.finish()
    before = files(recorder.path)
    derived = rescore_assessment(
        recorder.path, [], output_root=tmp_path / "derived", oracle_version="empty-v1"
    )
    assert derived.report.health.selected == 2
    assert derived.report.health.attempted == 0
    assert derived.report.health.complete is False
    with pytest.raises(BundleError):
        rescore_assessment(recorder.path, [], output_root=recorder.path, oracle_version="empty-v1")
    assert files(recorder.path) == before


@pytest.mark.parametrize("format", ["json", "sarif", "junit", "markdown", "pdf"])
async def test_assessment_replay_renders_each_format_without_target_calls(recorded, tmp_path, format):
    source, original = recorded
    destination = tmp_path / f"export.{format}"
    with patch.object(httpx.AsyncClient, "send", AsyncMock(side_effect=AssertionError("no network"))):
        result = CliRunner().invoke(
            app,
            [
                "replay",
                str(source),
                "--verify-oracles",
                "--format",
                format,
                "--out",
                str(destination),
                "--fail-on",
                "never",
            ],
        )
    assert result.exit_code == 0, result.output
    assert destination.stat().st_mode & 0o777 == 0o600
    if format == "json":
        assert json.loads(destination.read_text()) == original.to_dict()
    elif format == "sarif":
        report = json.loads(destination.read_text())["runs"][0]
        assert report["invocations"][0]["properties"]["health"]["selected"] == 2
        assert len(report["results"]) == 2
    elif format == "junit":
        import xml.etree.ElementTree as ET

        assert ET.fromstring(destination.read_text()).get("tests") == "2"
    elif format == "markdown":
        assert "incomplete" in destination.read_text()
    else:
        from pypdf import PdfReader

        assert PdfReader(destination, strict=True).pages


@pytest.mark.parametrize("format", ["sarif", "junit", "markdown", "pdf"])
async def test_all_presentations_identify_the_parent_assessment(recorded, format):
    from io import BytesIO

    from pypdf import PdfReader

    from neuralstrike.reports import render_report

    _, report = recorded
    rendered = render_report(report, format)
    if isinstance(rendered, bytes):
        text = "\n".join(page.extract_text() for page in PdfReader(BytesIO(rendered), strict=True).pages)
    else:
        text = rendered
    assert report.assessment_id in text
    assert report.plan_digest in "".join(text.split())


async def test_recorded_producer_version_is_not_replaced_by_replay_software_version(recorded):
    from neuralstrike.evaluation.assessment import load_assessment

    path, original = recorded
    report = json.loads((path / "report.json").read_text())
    report["tool_version"] = "historical-compatible-producer"
    (path / "report.json").write_text(json.dumps(report))
    manifest = json.loads((path / "manifest.json").read_text())
    manifest["producer_version"] = report["tool_version"]
    manifest["files"]["report.json"] = hashlib.sha256((path / "report.json").read_bytes()).hexdigest()
    (path / "manifest.json").write_text(json.dumps(manifest))
    loaded = load_assessment(path)
    assert loaded.report.to_dict()["tool_version"] == "historical-compatible-producer"
    assert loaded.report.overall() == original.overall()
    assert loaded.report.health == original.health
