"""CLI tests for the Phase 1 `scan` command."""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from neuralstrike.evaluation.verdict import EvidenceFidelity, SutResponse, ToolCall, Verdict
from neuralstrike.main import app
from neuralstrike.oracles.tool_harness import CanaryTool, TraceLog


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


class _FakeOpenAIAdapter:
    """A fake OpenAIEndpointAdapter that always calls grant_admin_access (Behavioral)."""

    def __init__(self, url: str, *, model: str = "", tier: str = "instrumented") -> None:
        self.url = url
        self.model = model
        self.tier = tier
        self.name = "openai_endpoint"

    async def query(
        self,
        prompt: str,
        *,
        system_prompt: str | None = None,
        tools: tuple[Any, ...] = (),
        history: tuple[Any, ...] = (),
        canary_tools: tuple[CanaryTool, ...] = (),
        trace: TraceLog | None = None,
    ) -> SutResponse:
        tool = next((t for t in canary_tools if t.name == "grant_admin_access"), None)
        if tool is not None and trace is not None:
            tool.execute({"user_id": "attacker"}, trace)
        return SutResponse(
            text="admin access granted",
            tool_calls=(ToolCall(name="grant_admin_access", arguments={"user_id": "attacker"}),),
            traces=tuple(trace.to_list()) if trace is not None else (),
        )

    async def close(self) -> None:
        return None


class TestScanCommand:
    def test_help_lists_scan(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "scan" in result.stdout

    def test_rejects_bad_adapter(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["scan", "--adapter", "bogus", "--url", "http://x"])
        assert result.exit_code != 0

    def test_rejects_bad_tier(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app, ["scan", "--adapter", "openai", "--url", "http://x", "--model", "m", "--tier", "bogus"]
        )
        assert result.exit_code != 0

    def test_openai_requires_model(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["scan", "--adapter", "openai", "--url", "http://x"])
        assert result.exit_code != 0

    def test_rejects_bad_fail_on(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app, ["scan", "--adapter", "openai", "--url", "http://x", "--model", "m", "--fail-on", "bogus"]
        )
        assert result.exit_code != 0

    def test_mcp_adapter_redirected_to_recon(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["scan", "--adapter", "mcp", "--url", "http://x"])
        assert result.exit_code != 0
        assert "recon" in result.stdout.lower() or "mcp" in result.stdout.lower()

    def test_openai_scan_succeeds_behavioral(self, runner: CliRunner, tmp_path) -> None:
        """End-to-end: fake adapter calls grant_admin_access -> Succeeded/Behavioral."""
        with patch("neuralstrike.adapters.openai_endpoint.OpenAIEndpointAdapter", _FakeOpenAIAdapter):
            result = runner.invoke(
                app,
                [
                    "scan",
                    "--adapter", "openai",
                    "--url", "http://victim",
                    "--model", "victim-model",
                    "--tier", "instrumented",
                    "--trials", "1",
                    "--run-dir", str(tmp_path / "runs"),
                    "--scenario-id", "asi01-scan-cli",
                ],
            )
        assert result.exit_code == 0, result.stdout
        assert "succeeded" in result.stdout.lower()
        assert "behavioral" in result.stdout.lower()

    def test_scan_saves_baseline(self, runner: CliRunner, tmp_path) -> None:
        with patch("neuralstrike.adapters.openai_endpoint.OpenAIEndpointAdapter", _FakeOpenAIAdapter):
            result = runner.invoke(
                app,
                [
                    "scan",
                    "--adapter", "openai",
                    "--url", "http://victim",
                    "--model", "m",
                    "--save-baseline-dir", str(tmp_path / "bl"),
                    "--run-dir", str(tmp_path / "runs"),
                ],
            )
        assert result.exit_code == 0, result.stdout
        assert "Baseline saved" in result.stdout

    def test_scan_baseline_gate_exit_1_on_vuln(self, runner: CliRunner, tmp_path) -> None:
        from neuralstrike.evaluation.baseline import save_baseline
        from neuralstrike.evaluation.runner import RunMeta, RunReport
        from neuralstrike.evaluation.scoring import score_trials

        # Save a Succeeded baseline; the scan also Succeeds -> pre-existing vuln (exit 1).
        trial = _succeeded_trial()
        meta = RunMeta("r", "asi01-scan", 0, 1, 0.0, 0.7, "t")
        save_baseline(tmp_path / "bl", RunReport(meta=meta, trials=(trial,), score=score_trials([trial])))
        with patch("neuralstrike.adapters.openai_endpoint.OpenAIEndpointAdapter", _FakeOpenAIAdapter):
            result = runner.invoke(
                app,
                [
                    "scan",
                    "--adapter", "openai",
                    "--url", "http://victim",
                    "--model", "m",
                    "--baseline-dir", str(tmp_path / "bl"),
                    "--scenario-id", "asi01-scan",
                    "--run-dir", str(tmp_path / "runs"),
                ],
            )
        assert result.exit_code == 1, result.stdout


def _succeeded_trial():
    from neuralstrike.evaluation.verdict import TrialResult

    return TrialResult(
        trial_index=0,
        seed=0,
        temperature=0.0,
        verdict=Verdict.SUCCEEDED,
        fidelity=EvidenceFidelity.BEHAVIORAL,
        findings=(),
        payload="p",
        response=SutResponse.from_text("x"),
        scenario_id="asi01-scan",
    )
