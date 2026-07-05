"""CLI tests for the Phase-0 `evaluate` + `judge-model-list` commands."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from neuralstrike.main import app


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


class TestEvaluationCommandsSurface:
    def test_help_lists_evaluate_and_judge_model_list(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "evaluate" in result.stdout
        assert "judge-model-list" in result.stdout

    def test_evaluate_rejects_bad_trials(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["evaluate", "--target", "x", "--trials", "0"])
        assert result.exit_code != 0

    def test_evaluate_rejects_bad_fail_on(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["evaluate", "--target", "x", "--fail-on", "bogus"])
        assert result.exit_code != 0

    def test_evaluate_rejects_bad_target_type(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["evaluate", "--target", "x", "--target-type", "bogus"])
        assert result.exit_code != 0


class TestJudgeModelList:
    def test_lists_installed_models(self, runner: CliRunner) -> None:
        from neuralstrike.core.llm_manager import LLMManager

        async def fake_list(self: LLMManager) -> list[str]:
            return ["deepseek-r1:8b", "deepseek-v3.1:671b-cloud"]

        with patch.object(LLMManager, "list_local_models", fake_list):
            result = runner.invoke(app, ["judge-model-list"])
        assert result.exit_code == 0
        assert "deepseek-v3.1:671b-cloud" in result.stdout

    def test_error_exits_3(self, runner: CliRunner) -> None:
        from neuralstrike.core.exceptions import LLMError
        from neuralstrike.core.llm_manager import LLMManager

        async def boom(self: LLMManager) -> list[str]:
            raise LLMError("ollama", "connection refused")

        with patch.object(LLMManager, "list_local_models", boom):
            result = runner.invoke(app, ["judge-model-list"])
        assert result.exit_code == 3


def _resisted_trial():
    from neuralstrike.evaluation.verdict import (
        EvidenceFidelity,
        SutResponse,
        TrialResult,
        Verdict,
    )

    return TrialResult(
        trial_index=0,
        seed=0,
        temperature=0.0,
        verdict=Verdict.RESISTED,
        fidelity=EvidenceFidelity.VERBAL,
        findings=(),
        payload="p",
        response=SutResponse.from_text("no leak"),
        scenario_id="asi01-canary-leak",
    )


def _succeeded_trial():
    from neuralstrike.evaluation.verdict import (
        EvidenceFidelity,
        SutResponse,
        TrialResult,
        Verdict,
    )

    return TrialResult(
        trial_index=0,
        seed=0,
        temperature=0.0,
        verdict=Verdict.SUCCEEDED,
        fidelity=EvidenceFidelity.VERBAL,
        findings=(),
        payload="p",
        response=SutResponse.from_text("CANARY-1234567890abcdef"),
        scenario_id="asi01-canary-leak",
    )


def _report(trial):
    from neuralstrike.evaluation.runner import RunMeta, RunReport
    from neuralstrike.evaluation.scoring import score_trials

    meta = RunMeta("run-test", "asi01-canary-leak", 0, 1, 0.0, 0.7, "t")
    return RunReport(meta=meta, trials=(trial,), score=score_trials([trial]))


class TestEvaluateCommand:
    def test_runs_and_saves_baseline(self, runner: CliRunner, tmp_path: Path) -> None:
        report = _report(_resisted_trial())

        async def fake_run(self, probe, *, trials=1, judge_model=None, attacker_model=None, persist=True):
            return report

        from neuralstrike.core.runtime import ResolvedModels
        fake_resolved = ResolvedModels(
            attacker_model="deepseek-r1",
            judge_model="deepseek-v3.1:671b-cloud",
            judge_fell_back=False,
            available=("deepseek-r1", "deepseek-v3.1:671b-cloud"),
        )
        with patch("neuralstrike.core.runtime.resolve_models", new=AsyncMock(return_value=fake_resolved)), \
             patch("neuralstrike.evaluation.runner.TrialRunner.run", fake_run), \
             patch("neuralstrike.evaluation.probes.canary_extraction_probe") as mock_probe:
            mock_probe.return_value = None  # factory not invoked (run is mocked)
            result = runner.invoke(
                app,
                [
                    "evaluate",
                    "--target", "victim",
                    "--target-type", "local",
                    "--trials", "1",
                    "--save-baseline-dir", str(tmp_path / "bl"),
                    "--run-dir", str(tmp_path / "runs"),
                ],
            )
        assert result.exit_code == 0, result.stdout
        assert "Baseline saved" in result.stdout

    def test_regression_exits_4(self, runner: CliRunner, tmp_path: Path) -> None:
        from neuralstrike.evaluation.baseline import save_baseline

        save_baseline(tmp_path / "bl", _report(_resisted_trial()))
        report = _report(_succeeded_trial())

        async def fake_run(self, probe, *, trials=1, judge_model=None, attacker_model=None, persist=True):
            return report

        from neuralstrike.core.runtime import ResolvedModels
        fake_resolved = ResolvedModels(
            attacker_model="deepseek-r1",
            judge_model="deepseek-v3.1:671b-cloud",
            judge_fell_back=False,
            available=("deepseek-r1", "deepseek-v3.1:671b-cloud"),
        )
        with patch("neuralstrike.core.runtime.resolve_models", new=AsyncMock(return_value=fake_resolved)), \
             patch("neuralstrike.evaluation.runner.TrialRunner.run", fake_run), \
             patch("neuralstrike.evaluation.probes.canary_extraction_probe"):
            result = runner.invoke(
                app,
                [
                    "evaluate",
                    "--target", "victim",
                    "--trials", "1",
                    "--baseline-dir", str(tmp_path / "bl"),
                    "--fail-on", "regression",
                    "--run-dir", str(tmp_path / "runs"),
                ],
            )
        assert result.exit_code == 4, result.stdout

    def test_vuln_exits_1_on_pre_existing(self, runner: CliRunner, tmp_path: Path) -> None:
        from neuralstrike.evaluation.baseline import save_baseline

        save_baseline(tmp_path / "bl", _report(_succeeded_trial()))
        report = _report(_succeeded_trial())

        async def fake_run(self, probe, *, trials=1, judge_model=None, attacker_model=None, persist=True):
            return report

        from neuralstrike.core.runtime import ResolvedModels
        fake_resolved = ResolvedModels(
            attacker_model="deepseek-r1",
            judge_model="deepseek-v3.1:671b-cloud",
            judge_fell_back=False,
            available=("deepseek-r1", "deepseek-v3.1:671b-cloud"),
        )
        with patch("neuralstrike.core.runtime.resolve_models", new=AsyncMock(return_value=fake_resolved)), \
             patch("neuralstrike.evaluation.runner.TrialRunner.run", fake_run), \
             patch("neuralstrike.evaluation.probes.canary_extraction_probe"):
            result = runner.invoke(
                app,
                [
                    "evaluate",
                    "--target", "victim",
                    "--trials", "1",
                    "--baseline-dir", str(tmp_path / "bl"),
                    "--fail-on", "regression",
                    "--run-dir", str(tmp_path / "runs"),
                ],
            )
        assert result.exit_code == 1, result.stdout

    def test_pass_exits_0(self, runner: CliRunner, tmp_path: Path) -> None:
        from neuralstrike.evaluation.baseline import save_baseline

        save_baseline(tmp_path / "bl", _report(_resisted_trial()))
        report = _report(_resisted_trial())

        async def fake_run(self, probe, *, trials=1, judge_model=None, attacker_model=None, persist=True):
            return report

        from neuralstrike.core.runtime import ResolvedModels
        fake_resolved = ResolvedModels(
            attacker_model="deepseek-r1",
            judge_model="deepseek-v3.1:671b-cloud",
            judge_fell_back=False,
            available=("deepseek-r1", "deepseek-v3.1:671b-cloud"),
        )
        with patch("neuralstrike.core.runtime.resolve_models", new=AsyncMock(return_value=fake_resolved)), \
             patch("neuralstrike.evaluation.runner.TrialRunner.run", fake_run), \
             patch("neuralstrike.evaluation.probes.canary_extraction_probe"):
            result = runner.invoke(
                app,
                [
                    "evaluate",
                    "--target", "victim",
                    "--trials", "1",
                    "--baseline-dir", str(tmp_path / "bl"),
                    "--fail-on", "regression",
                    "--run-dir", str(tmp_path / "runs"),
                ],
            )
        assert result.exit_code == 0, result.stdout


class TestRuntimeReachability:
    @pytest.mark.asyncio
    async def test_resolve_models_fallback_chain(self) -> None:
        from neuralstrike.core.llm_manager import LLMManager
        from neuralstrike.core.runtime import resolve_models

        mgr = LLMManager.__new__(LLMManager)
        mgr._base_url = "http://x"
        mgr._client = None
        mgr.list_local_models = AsyncMock(  # type: ignore[method-assign]
            return_value=["deepseek-r1:8b", "kimi-k2.6:cloud"]
        )
        resolved = await resolve_models(
            mgr,
            attacker_model="deepseek-r1:8b",
            judge_model="deepseek-v3.1:671b-cloud",
            judge_fallbacks=("kimi-k2.6:cloud", "gpt-oss:120b-cloud", "deepseek-r1:8b"),
        )
        # Judge falls back to the first reachable model in the chain.
        assert resolved.judge_model == "kimi-k2.6:cloud"
        assert resolved.judge_fell_back is True

    @pytest.mark.asyncio
    async def test_resolve_models_attacker_missing_fails_closed(self) -> None:
        from neuralstrike.core.exceptions import ConfigError
        from neuralstrike.core.llm_manager import LLMManager
        from neuralstrike.core.runtime import resolve_models

        mgr = LLMManager.__new__(LLMManager)
        mgr._base_url = "http://x"
        mgr._client = None
        mgr.list_local_models = AsyncMock(return_value=["x"])  # type: ignore[method-assign]
        with pytest.raises(ConfigError):
            await resolve_models(
                mgr,
                attacker_model="missing-attacker",
                judge_model="x",
            )

    @pytest.mark.asyncio
    async def test_resolve_models_no_reachable_judge_fails_closed(self) -> None:
        from neuralstrike.core.exceptions import ConfigError
        from neuralstrike.core.llm_manager import LLMManager
        from neuralstrike.core.runtime import resolve_models

        mgr = LLMManager.__new__(LLMManager)
        mgr._base_url = "http://x"
        mgr._client = None
        mgr.list_local_models = AsyncMock(return_value=["deepseek-r1:8b"])  # type: ignore[method-assign]
        with pytest.raises(ConfigError):
            await resolve_models(
                mgr,
                attacker_model="deepseek-r1:8b",
                judge_model="missing-judge",
                judge_fallbacks=("also-missing",),
            )

    @pytest.mark.asyncio
    async def test_resolve_models_ollama_down_fails_closed(self) -> None:
        from neuralstrike.core.exceptions import ConfigError, LLMError
        from neuralstrike.core.llm_manager import LLMManager
        from neuralstrike.core.runtime import resolve_models

        mgr = LLMManager.__new__(LLMManager)
        mgr._base_url = "http://x"
        mgr._client = None
        mgr.list_local_models = AsyncMock(side_effect=LLMError("ollama", "down"))  # type: ignore[method-assign]
        with pytest.raises(ConfigError):
            await resolve_models(mgr, attacker_model="x", judge_model="y")
