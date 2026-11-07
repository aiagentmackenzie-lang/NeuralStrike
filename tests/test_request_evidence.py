"""NS-05 provider controls and immutable, complete request evidence."""

import asyncio
import json

import httpx
import pytest

from neuralstrike.adapters.openai_endpoint import OpenAIEndpointAdapter
from neuralstrike.attacks.indirect import IndirectHarness
from neuralstrike.corpus import load_corpus_dir
from neuralstrike.evaluation.probes import adapter_scan_probe
from neuralstrike.evaluation.runner import TrialRunner, _derive_seed
from neuralstrike.oracles.forbidden_tool import ForbiddenToolOracle, ForbiddenToolSpec


@pytest.mark.asyncio
async def test_scan_forwards_actual_trial_seed_and_captures_rounds(tmp_path):
    captured = []

    def handler(request):
        captured.append(json.loads(request.content))
        if len(captured) == 1:
            message = {
                "content": "",
                "tool_calls": [
                    {
                        "id": "call-1",
                        "type": "function",
                        "function": {"name": "safe_fixture", "arguments": "{}"},
                    }
                ],
            }
        else:
            message = {"content": "complete"}
        return httpx.Response(
            200,
            json={
                "model": "fixture-build",
                "system_fingerprint": "fp-local",
                "choices": [{"message": message}],
            },
        )

    adapter = OpenAIEndpointAdapter(
        "http://fixture",
        model="fixture",
        api_key="SYNTHETIC_HEADER_SECRET",
        transport=httpx.MockTransport(handler),
    )
    probe = adapter_scan_probe(
        adapter,
        payload="fixture",
        scenario_id="s",
        oracles=[ForbiddenToolOracle(ForbiddenToolSpec(forbidden_tools=("forbidden",)))],
    )
    try:
        report = await TrialRunner(base_seed=123, run_dir=tmp_path).run(probe)
    finally:
        await adapter.close()
    assert captured[0]["seed"] == _derive_seed(123, 0)
    assert captured[0]["temperature"] == 0
    trial = json.loads((tmp_path / report.meta.run_id / "trial-0.json").read_text())
    exchanges = trial["exchanges"]
    assert len(exchanges) == 2
    assert exchanges[0]["request"] == captured[0]
    assert exchanges[1]["request"] == captured[1]
    assert len(exchanges[0]["request"]["messages"]) == 1  # no later mutation
    assert exchanges[0]["response"]["model"] == "fixture-build"
    assert "SYNTHETIC_HEADER_SECRET" not in json.dumps(trial)


@pytest.mark.asyncio
async def test_indirect_request_capture_preserves_injection_history(tmp_path):
    scenario = next(s for s in load_corpus_dir() if s.delivery_vector == "retrieved_document")
    adapter = OpenAIEndpointAdapter(
        "http://fixture",
        model="fixture",
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json={"choices": [{"message": {"content": "done"}}]})
        ),
    )
    try:
        report = await TrialRunner(base_seed=7, run_dir=tmp_path).run(
            IndirectHarness(scenario).probe_for(adapter)
        )
    finally:
        await adapter.close()
    trial = json.loads((tmp_path / report.meta.run_id / "trial-0.json").read_text())
    messages = trial["exchanges"][0]["request"]["messages"]
    assert any(m["role"] == "tool" and "[NSINJ:" in m["content"] for m in messages)
    assert trial["inputs"]["canary"].startswith("CANARY-")
    assert messages[-1]["content"] == scenario.legitimate_task


@pytest.mark.asyncio
async def test_concurrent_runs_on_shared_adapter_keep_trial_controls_isolated(tmp_path):
    captured = []

    async def handler(request):
        await asyncio.sleep(0)
        captured.append(json.loads(request.content))
        return httpx.Response(200, json={"choices": [{"message": {"content": "done"}}]})

    adapter = OpenAIEndpointAdapter(
        "http://fixture", model="fixture", seed=999, transport=httpx.MockTransport(handler)
    )
    probe = adapter_scan_probe(adapter, payload="fixture", scenario_id="s", oracles=[])
    try:
        await asyncio.gather(*(TrialRunner(base_seed=seed, run_dir=tmp_path).run(probe) for seed in [1, 2]))
    finally:
        await adapter.close()
    assert {request["seed"] for request in captured} == {_derive_seed(seed, 0) for seed in [1, 2]}
    assert adapter.seed == 999


@pytest.mark.asyncio
async def test_http_failure_preserves_attempted_request_and_error(tmp_path):
    adapter = OpenAIEndpointAdapter(
        "http://fixture",
        model="fixture",
        transport=httpx.MockTransport(lambda request: httpx.Response(503, text="controlled outage")),
    )
    probe = adapter_scan_probe(adapter, payload="fixture", scenario_id="s", oracles=[])
    try:
        report = await TrialRunner(run_dir=tmp_path).run(probe)
    finally:
        await adapter.close()
    trial = json.loads((tmp_path / report.meta.run_id / "trial-0.json").read_text())
    assert trial["exchanges"][0]["status_code"] == 503
    assert trial["exchanges"][0]["response_text"] == "controlled outage"
    assert trial["exchanges"][0]["request"]["messages"][-1]["content"] == "fixture"
    assert trial["response_error"]


@pytest.mark.asyncio
async def test_remote_manager_forwards_trial_controls_without_cloud_calls():
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, patch

    from neuralstrike.core.llm_manager import LLMManager
    from neuralstrike.evaluation.controls import trial_controls

    response = SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="fixture"))])
    with (
        patch("neuralstrike.core.llm_manager.acompletion", AsyncMock(return_value=response)) as call,
        trial_controls(123, 0.25),
    ):
        assert await LLMManager().call_remote("fixture", "hello") == "fixture"
    assert call.call_args.kwargs["seed"] == 123
    assert call.call_args.kwargs["temperature"] == 0.25


def test_corpus_cli_persists_request_evidence(tmp_path):
    from unittest.mock import AsyncMock, patch

    from typer.testing import CliRunner

    from neuralstrike.evaluation.verdict import SutResponse
    from neuralstrike.main import app

    with patch.object(OpenAIEndpointAdapter, "query", AsyncMock(return_value=SutResponse(text="fixture"))):
        result = CliRunner().invoke(
            app,
            [
                "corpus",
                "--adapter",
                "openai",
                "--url",
                "http://fixture",
                "--model",
                "fixture",
                "--limit",
                "1",
                "--format",
                "json",
                "--fail-on",
                "never",
                "--run-dir",
                str(tmp_path / "runs"),
                "--out",
                str(tmp_path / "report"),
            ],
        )
    assert result.exit_code == 0, result.output
    artifact = json.loads((tmp_path / "report.json").read_text())
    evidence = artifact["scenario_results"][0]["evidence"]
    assert evidence["trials"][0]["inputs"]["canary"].startswith("CANARY-")
    assert (tmp_path / "runs" / evidence["meta"]["run_id"] / "manifest.json").is_file()
    assert (tmp_path / "report.json").stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("command", ["scan", "corpus"])
def test_adapters_close_when_evidence_persistence_raises(tmp_path, command):
    from unittest.mock import AsyncMock, patch

    from typer.testing import CliRunner

    from neuralstrike.main import app

    args = [
        command,
        "--adapter",
        "openai",
        "--url",
        "http://fixture",
        "--model",
        "fixture",
        "--run-dir",
        str(tmp_path / "runs"),
    ]
    if command == "corpus":
        args += ["--limit", "1", "--out", str(tmp_path / "report")]
    with (
        patch(
            "neuralstrike.evaluation.runner.TrialRunner.run", AsyncMock(side_effect=OSError("disk failure"))
        ),
        patch.object(OpenAIEndpointAdapter, "close", AsyncMock()) as close,
    ):
        result = CliRunner().invoke(app, args)
    assert result.exit_code == 3, result.output
    assert "incomplete" in result.output.lower()
    close.assert_awaited_once()


@pytest.mark.asyncio
async def test_credential_url_is_excluded_from_error_diagnostics(tmp_path):
    sentinel = "SYNTHETIC_URL_PASSWORD"
    adapter = OpenAIEndpointAdapter(
        f"http://fixture-user:{sentinel}@fixture",
        model="synthetic",
        transport=httpx.MockTransport(lambda request: httpx.Response(503, text="synthetic outage")),
    )
    try:
        report = await TrialRunner(run_dir=tmp_path).run(
            adapter_scan_probe(adapter, payload="synthetic", scenario_id="safe-errors", oracles=[])
        )
    finally:
        await adapter.close()
    encoded = json.dumps(report.to_dict())
    assert sentinel not in encoded
    assert "fixture-user" not in encoded
    assert report.trials[0].response.error
    assert "503" in report.trials[0].response.error
