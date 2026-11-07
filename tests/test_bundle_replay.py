"""Offline replay verifies evidence and never calls a target or mutates its source."""

import hashlib
import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from neuralstrike.adapters.openai_endpoint import OpenAIEndpointAdapter
from neuralstrike.attacks.indirect import IndirectHarness
from neuralstrike.corpus import load_corpus_dir
from neuralstrike.evaluation.runner import Probe, TrialRunner
from neuralstrike.evaluation.verdict import EvidenceFidelity, TrialResult, Verdict
from neuralstrike.oracles.forbidden_tool import ForbiddenToolOracle, ForbiddenToolSpec


def snapshot(path):
    return {p.name: p.read_bytes() for p in path.iterdir()}


def rehash(path, name):
    manifest_path = path / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["files"][name] = hashlib.sha256((path / name).read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest))


@pytest.fixture
async def indirect_bundle(tmp_path):
    scenario = next(s for s in load_corpus_dir() if s.delivery_vector == "retrieved_document")
    adapter = OpenAIEndpointAdapter(
        "http://fixture",
        model="synthetic",
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json={"choices": [{"message": {"content": "fixture reply"}}]})
        ),
    )
    try:
        report = await TrialRunner(run_dir=tmp_path).run(IndirectHarness(scenario).probe_for(adapter))
    finally:
        await adapter.close()
    return tmp_path / report.meta.run_id, report


async def test_indirect_offline_replay_is_identical_and_read_only(indirect_bundle):
    from neuralstrike.evaluation.bundle import replay_bundle

    path, original = indirect_bundle
    before = snapshot(path)
    with patch.object(httpx.AsyncClient, "send", AsyncMock(side_effect=AssertionError("network forbidden"))):
        replay = replay_bundle(path)
    assert replay.to_dict() == original.to_dict()
    assert replay.trials[0].inputs["history"]
    assert any(m["role"] == "tool" for m in replay.trials[0].response.exchanges[0]["request"]["messages"])
    assert snapshot(path) == before
    assert json.loads(before["manifest.json"])["schema_version"] == 2
    assert replay.to_dict()["trials"][0]["evidence_id"].startswith("sha256:")


async def test_new_oracle_rescore_creates_derived_bundle_without_mutation(indirect_bundle, tmp_path):
    from neuralstrike.evaluation.bundle import load_bundle, rescore_bundle

    source, original = indirect_bundle
    before = snapshot(source)
    oracle = ForbiddenToolOracle(ForbiddenToolSpec(forbidden_tools=("synthetic_tool",)))
    with patch.object(httpx.AsyncClient, "send", AsyncMock(side_effect=AssertionError("network forbidden"))):
        result = rescore_bundle(
            source, [oracle], output_root=tmp_path / "derived", oracle_version="fixture-v2"
        )
    derived = tmp_path / "derived" / result.meta.run_id
    loaded = load_bundle(derived).report
    assert loaded.to_dict() == result.to_dict()
    assert result.meta.run_id != original.meta.run_id
    assert result.meta.provenance["source_run_id"] == original.meta.run_id
    assert (
        result.meta.provenance["source_manifest_sha256"]
        == hashlib.sha256(before["manifest.json"]).hexdigest()
    )
    assert result.meta.provenance["oracle_version"] == "fixture-v2"
    assert result.meta.provenance["oracle_digest"]
    assert result.to_dict()["trials"][0]["evidence_id"] == original.to_dict()["trials"][0]["evidence_id"]
    assert snapshot(source) == before
    assert (derived / "report.json").stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "damage",
    [
        "bytes",
        "missing",
        "unlisted",
        "traversal",
        "symlink",
        "schema",
        "running",
        "duplicate_key",
        "report_mismatch",
    ],
)
async def test_corrupt_or_incompatible_bundle_fails_explicitly(indirect_bundle, damage, tmp_path):
    from neuralstrike.evaluation.bundle import BundleError, replay_bundle

    path, _ = indirect_bundle
    trial = path / "trial-0.json"
    manifest_path = path / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if damage == "bytes":
        trial.write_text(trial.read_text() + " ")
    elif damage == "missing":
        trial.unlink()
    elif damage == "unlisted":
        (path / "trial-99.json").write_text("{}")
    elif damage == "traversal":
        manifest["files"]["../outside.json"] = "0" * 64
        manifest_path.write_text(json.dumps(manifest))
    elif damage == "symlink":
        outside = tmp_path / "outside.json"
        outside.write_bytes(trial.read_bytes())
        trial.unlink()
        trial.symlink_to(outside)
    elif damage == "schema":
        manifest["schema_version"] = 999
        manifest_path.write_text(json.dumps(manifest))
    elif damage == "running":
        manifest["state"] = "running"
        manifest_path.write_text(json.dumps(manifest))
    elif damage == "duplicate_key":
        manifest_path.write_text(
            manifest_path.read_text().replace(
                '"schema_version": 2', '"schema_version": 999, "schema_version": 2'
            )
        )
    else:
        document = json.loads(trial.read_text())
        document["verdict"] = "succeeded"
        trial.write_text(json.dumps(document))
        rehash(path, "trial-0.json")
    with pytest.raises(BundleError):
        replay_bundle(path)


async def test_errors_and_absent_responses_survive_replay_and_rescore(tmp_path):
    from neuralstrike.evaluation.bundle import replay_bundle, rescore_bundle

    async def factory(index, seed, canary):
        return TrialResult(
            index,
            seed,
            0,
            Verdict.INCONCLUSIVE,
            EvidenceFidelity.VERBAL,
            scenario_id="outage",
            error="synthetic outage",
        )

    report = await TrialRunner(run_dir=tmp_path).run(
        Probe("outage", "fixture", factory, category="availability")
    )
    source = tmp_path / report.meta.run_id
    assert replay_bundle(source).to_dict() == report.to_dict()
    result = rescore_bundle(source, [], output_root=tmp_path / "derived", oracle_version="empty-v1")
    assert result.trials[0].response is None
    assert result.trials[0].error == "synthetic outage"
    assert result.trials[0].verdict is Verdict.INCONCLUSIVE
    assert result.score.measured_asr is None


async def test_legacy_manifest_is_readable_with_explicit_limits(indirect_bundle):
    from neuralstrike.evaluation.bundle import load_bundle

    path, _ = indirect_bundle
    manifest = json.loads((path / "manifest.json").read_text())
    manifest["schema_version"] = 1
    (path / "manifest.json").write_text(json.dumps(manifest))
    loaded = load_bundle(path)
    assert loaded.schema_version == 1
    assert loaded.limitations


async def test_semantic_tampering_rejected_even_when_hashes_recomputed(indirect_bundle):
    from neuralstrike.evaluation.bundle import BundleError, replay_bundle

    path, _ = indirect_bundle
    report_path = path / "report.json"
    report = json.loads(report_path.read_text())
    report["score"]["succeeded"] = 999
    report_path.write_text(json.dumps(report))
    rehash(path, "report.json")
    with pytest.raises(BundleError, match="score"):
        replay_bundle(path)


async def test_replay_cli_reports_health_and_rejects_corruption_even_with_never(indirect_bundle, tmp_path):
    from typer.testing import CliRunner

    from neuralstrike.main import app

    path, original = indirect_bundle
    output = tmp_path / "offline.json"
    result = CliRunner().invoke(app, ["replay", str(path), "--out", str(output), "--fail-on", "never"])
    assert result.exit_code == 0, result.output
    assert "recorded outcomes" in result.output.lower()
    assert "incomplete" in result.output.lower()
    assert json.loads(output.read_text()) == original.to_dict()
    assert output.stat().st_mode & 0o777 == 0o600
    (path / "trial-0.json").write_text("corrupt")
    result = CliRunner().invoke(app, ["replay", str(path), "--fail-on", "never"])
    assert result.exit_code == 3, result.output
    assert "bundle" in result.output.lower()


async def test_rescore_cli_uses_explicit_local_policy_and_preserves_source(indirect_bundle, tmp_path):
    from typer.testing import CliRunner

    from neuralstrike.main import app

    source, _ = indirect_bundle
    before = snapshot(source)
    root = tmp_path / "derived-cli"
    result = CliRunner().invoke(
        app,
        [
            "rescore",
            str(source),
            "--out-dir",
            str(root),
            "--forbid-tool",
            "synthetic_tool",
            "--oracle-version",
            "fixture-v2",
            "--fail-on",
            "never",
        ],
    )
    assert result.exit_code == 0, result.output
    assert snapshot(source) == before
    derived = json.loads(next(root.glob("*/report.json")).read_text())
    assert derived["meta"]["provenance"]["oracle_version"] == "fixture-v2"


@pytest.mark.parametrize("operation", ["replay", "rescore"])
async def test_cli_cannot_write_inside_source_bundle(indirect_bundle, operation):
    from typer.testing import CliRunner

    from neuralstrike.main import app

    source, _ = indirect_bundle
    before = snapshot(source)
    args = [operation, str(source), "--fail-on", "never"]
    if operation == "replay":
        args += ["--out", str(source / "report.json")]
    else:
        args += ["--out-dir", str(source), "--forbid-tool", "synthetic", "--oracle-version", "v2"]
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 3, result.output
    assert snapshot(source) == before


async def test_bound_behavioral_receipt_survives_replay_and_same_policy_rescore(tmp_path):
    from neuralstrike.evaluation.bundle import replay_bundle, rescore_bundle
    from neuralstrike.evaluation.probes import adapter_scan_probe
    from neuralstrike.oracles.tool_harness import make_canary_tools

    calls = []

    def handler(request):
        calls.append(json.loads(request.content))
        message = (
            {"content": "fixture complete"}
            if len(calls) > 1
            else {
                "content": "",
                "tool_calls": [
                    {
                        "id": "call-bound",
                        "type": "function",
                        "function": {"name": "grant_admin_access", "arguments": '{"user_id":"synthetic"}'},
                    }
                ],
            }
        )
        return httpx.Response(200, json={"choices": [{"message": message}]})

    adapter = OpenAIEndpointAdapter(
        "http://fixture", model="synthetic", tier="instrumented", transport=httpx.MockTransport(handler)
    )
    oracle = ForbiddenToolOracle(ForbiddenToolSpec(forbidden_tools=("grant_admin_access",)))
    try:
        report = await TrialRunner(run_dir=tmp_path).run(
            adapter_scan_probe(
                adapter,
                payload="synthetic",
                scenario_id="bound",
                oracles=[oracle],
                canary_tools=make_canary_tools(),
            )
        )
    finally:
        await adapter.close()
    path = tmp_path / report.meta.run_id
    assert report.trials[0].fidelity is EvidenceFidelity.BEHAVIORAL
    assert replay_bundle(path).to_dict() == report.to_dict()
    result = rescore_bundle(path, [oracle], output_root=tmp_path / "derived", oracle_version="same-v1")
    assert result.to_dict()["trials"] == report.to_dict()["trials"]
    assert result.trials[0].findings[0].evidence_origin == "local-canary-fixture"
    from typer.testing import CliRunner

    from neuralstrike.main import app

    gate = CliRunner().invoke(app, ["replay", str(path), "--verify-oracles"])
    assert gate.exit_code == 1, gate.output
    assert "oracles verified" in gate.output


async def test_actual_phase0_schema_one_bundle_still_loads(indirect_bundle):
    from neuralstrike.evaluation.bundle import load_bundle

    path, original = indirect_bundle
    manifest = json.loads((path / "manifest.json").read_text())
    manifest["schema_version"] = 1
    for filename in manifest["files"]:
        document = json.loads((path / filename).read_text())
        if filename == "meta.json":
            for field in ["category", "severity", "provenance", "completed_at"]:
                document.pop(field)
        elif filename.startswith("trial-"):
            for field in ["response_present", "evidence_id", "oracle_policy"]:
                document.pop(field)
            for finding in document["findings"]:
                for field in [
                    "tool_name",
                    "tool_call_id",
                    "arguments_digest",
                    "receipt_id",
                    "evidence_origin",
                ]:
                    finding.pop(field)
        else:
            # Use the already-migrated component files, not an invented legacy shape.
            continue
        (path / filename).write_text(json.dumps(document))
    report = json.loads((path / "report.json").read_text())
    report["meta"] = json.loads((path / "meta.json").read_text())
    report["trials"] = [json.loads((path / "trial-0.json").read_text())]
    (path / "report.json").write_text(json.dumps(report))
    for filename in manifest["files"]:
        manifest["files"][filename] = hashlib.sha256((path / filename).read_bytes()).hexdigest()
    (path / "manifest.json").write_text(json.dumps(manifest))
    loaded = load_bundle(path)
    assert loaded.report.score == original.score
    assert loaded.report.meta.category == "uncategorized"  # Not retained in old zero-coverage scores.
    assert any("legacy" in limit for limit in loaded.limitations)


async def test_boolean_score_count_is_not_an_integer(indirect_bundle):
    from neuralstrike.evaluation.bundle import BundleError, replay_bundle

    path, _ = indirect_bundle
    report = json.loads((path / "report.json").read_text())
    report["score"]["succeeded"] = False
    (path / "report.json").write_text(json.dumps(report))
    rehash(path, "report.json")
    with pytest.raises(BundleError):
        replay_bundle(path)


async def test_indirect_replay_can_verify_original_deterministic_oracles(indirect_bundle):
    from neuralstrike.evaluation.bundle import replay_bundle

    path, original = indirect_bundle
    with patch.object(httpx.AsyncClient, "send", AsyncMock(side_effect=AssertionError("network forbidden"))):
        replay = replay_bundle(path, verify_oracles=True)
    assert replay.to_dict() == original.to_dict()


async def test_original_oracle_verification_never_silently_uses_new_implementation(indirect_bundle):
    from neuralstrike.evaluation.bundle import BundleError, replay_bundle

    path, _ = indirect_bundle
    report = json.loads((path / "report.json").read_text())
    trial_document = json.loads((path / "trial-0.json").read_text())
    trial_document["oracle_policy"]["implementation_digest"] = "changed-version"
    # Deliberate author rewrite: update evidence ID and both files to test the
    # implementation-version boundary independently from byte-corruption checks.
    observation = {
        k: v
        for k, v in trial_document.items()
        if k not in {"verdict", "fidelity", "findings", "evidence_id", "oracle_policy"}
    }
    trial_document["evidence_id"] = (
        "sha256:"
        + hashlib.sha256(json.dumps(observation, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    )
    report["trials"] = [trial_document]
    (path / "trial-0.json").write_text(json.dumps(trial_document))
    (path / "report.json").write_text(json.dumps(report))
    rehash(path, "trial-0.json")
    rehash(path, "report.json")
    with pytest.raises(BundleError, match="implementation"):
        replay_bundle(path, verify_oracles=True)


async def test_malformed_local_receipt_is_rejected_as_bundle_error(tmp_path):
    from neuralstrike.evaluation.bundle import BundleError, load_bundle
    from neuralstrike.evaluation.verdict import SutResponse

    async def factory(index, seed, canary):
        return TrialResult(
            index,
            seed,
            0,
            Verdict.INCONCLUSIVE,
            EvidenceFidelity.VERBAL,
            scenario_id="malformed",
            response=SutResponse(traces=({"origin": "local-canary-fixture", "tool": "x"},)),
        )

    report = await TrialRunner(run_dir=tmp_path).run(Probe("malformed", "fixture", factory))
    with pytest.raises(BundleError):
        load_bundle(tmp_path / report.meta.run_id)


async def test_bundle_records_completion_time_and_round_trips_it(indirect_bundle):
    from neuralstrike.evaluation.bundle import replay_bundle

    path, original = indirect_bundle
    assert original.meta.completed_at is not None
    assert original.meta.completed_at >= original.meta.started_at
    assert replay_bundle(path).meta.completed_at == original.meta.completed_at
