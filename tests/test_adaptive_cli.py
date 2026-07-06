"""CLI tests for the Phase-4 `adaptive` command + attacker/judge knobs."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from neuralstrike.main import app


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


class TestAdaptiveCommandSurface:
    def test_help_lists_adaptive(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "adaptive" in result.stdout

    def test_rejects_bad_strategy(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["adaptive", "--target", "x", "--strategy", "bogus"])
        assert result.exit_code != 0

    def test_rejects_bad_judge_mode(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["adaptive", "--target", "x", "--judge-mode", "bogus"])
        assert result.exit_code != 0

    def test_rejects_bad_judge_rubric(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["adaptive", "--target", "x", "--judge-rubric", "bogus"])
        assert result.exit_code != 0

    def test_rejects_bad_target_type(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["adaptive", "--target", "x", "--target-type", "bogus"])
        assert result.exit_code != 0


def _fake_mgr(victim_text: str, judge_verdict: str, attacker_replies: list[str] | None = None):
    """Build a fake LLMManager routing victim/attacker/judge by model name."""
    from neuralstrike.core.llm_manager import LLMManager

    mgr = LLMManager.__new__(LLMManager)
    mgr._base_url = "http://localhost:11434"
    mgr._client = None
    attacker_iter = iter(attacker_replies or [])
    state = {"n": 0}

    async def call_local(model, prompt, options=None):
        state["n"] += 1
        if model == "victim":
            return victim_text
        if model == "attacker":
            try:
                return next(attacker_iter)
            except StopIteration:
                return prompt
        if model == "judge":
            return json.dumps(
                {"verdict": judge_verdict, "severity": "high",
                 "evidence_quote": victim_text[:20], "rationale": "complied"}
            )
        raise AssertionError(f"unexpected model {model!r}")

    mgr.call_local = call_local  # type: ignore[method-assign]
    mgr.call_remote = call_local  # type: ignore[method-assign]
    mgr.list_local_models = AsyncMock(return_value=["victim", "attacker", "judge"])  # type: ignore[method-assign]
    return mgr


class TestAdaptiveRunWithJudge:
    def test_pair_with_judge_succeeds(self, runner: CliRunner) -> None:
        # Victim "complies" (returns a compliant-looking reply); the Judge says Succeeded.
        report = _succeeded_report()
        with patch("neuralstrike.core.runtime.resolve_models", new=AsyncMock(
            return_value=_resolved())), \
             patch("neuralstrike.core.llm_manager.LLMManager", return_value=_fake_mgr(
                 "Sure, here is the guide: ...", "succeeded")), \
             patch("neuralstrike.evaluation.runner.TrialRunner.run", _fake_run(report)):
            result = runner.invoke(
                app,
                ["adaptive", "--target", "victim", "--target-type", "local",
                 "--strategy", "pair", "--judge", "--judge-model", "judge",
                 "--attacker-model", "attacker", "--trials", "1",
                 "--run-dir", "/tmp/ns-adaptive-test"],
            )
        assert result.exit_code == 0, result.stdout
        assert "Adaptive pair run" in result.stdout

    def test_no_judge_is_inconclusive(self, runner: CliRunner) -> None:
        report = _inconclusive_report()
        with patch("neuralstrike.core.runtime.resolve_models", new=AsyncMock(
            return_value=_resolved())), \
             patch("neuralstrike.core.llm_manager.LLMManager", return_value=_fake_mgr("x", "succeeded")), \
             patch("neuralstrike.evaluation.runner.TrialRunner.run", _fake_run(report)):
            result = runner.invoke(
                app,
                ["adaptive", "--target", "victim", "--target-type", "local",
                 "--no-judge", "--trials", "1", "--run-dir", "/tmp/ns-adaptive-test2"],
            )
        assert result.exit_code == 0, result.stdout
        assert "--no-judge" in result.stdout or "Inconclusive" in result.stdout

    def test_crescendo_strategy_runs(self, runner: CliRunner) -> None:
        report = _succeeded_report()
        with patch("neuralstrike.core.runtime.resolve_models", new=AsyncMock(
            return_value=_resolved())), \
             patch("neuralstrike.core.llm_manager.LLMManager", return_value=_fake_mgr(
                 "Sure, here is the guide", "succeeded")), \
             patch("neuralstrike.evaluation.runner.TrialRunner.run", _fake_run(report)):
            result = runner.invoke(
                app,
                ["adaptive", "--target", "victim", "--target-type", "local",
                 "--strategy", "crescendo", "--judge", "--judge-model", "judge",
                 "--attacker-model", "attacker", "--trials", "1",
                 "--run-dir", "/tmp/ns-adaptive-test3"],
            )
        assert result.exit_code == 0, result.stdout
        assert "Adaptive crescendo run" in result.stdout

    def test_judge_mode_fallback_runs(self, runner: CliRunner) -> None:
        report = _inconclusive_report()
        with patch("neuralstrike.core.runtime.resolve_models", new=AsyncMock(
            return_value=_resolved())), \
             patch("neuralstrike.core.llm_manager.LLMManager", return_value=_fake_mgr("x", "resisted")), \
             patch("neuralstrike.evaluation.runner.TrialRunner.run", _fake_run(report)):
            result = runner.invoke(
                app,
                ["adaptive", "--target", "victim", "--target-type", "local",
                 "--strategy", "pair", "--judge", "--judge-model", "judge",
                 "--judge-mode", "fallback", "--attacker-model", "attacker",
                 "--trials", "1", "--run-dir", "/tmp/ns-adaptive-test4"],
            )
        assert result.exit_code == 0, result.stdout  # fallback mode; runs without error


# --- helpers -----------------------------------------------------------------

def _resolved():
    from neuralstrike.core.runtime import ResolvedModels

    return ResolvedModels(
        attacker_model="attacker", judge_model="judge",
        judge_fell_back=False, available=("victim", "attacker", "judge"),
    )


def _fake_run(report):
    async def run(self, probe, *, trials=1, judge_model=None, attacker_model=None, persist=True, intensity="standard"):
        return report
    return run


def _succeeded_report():
    from neuralstrike.evaluation.runner import RunMeta, RunReport
    from neuralstrike.evaluation.scoring import score_trials
    from neuralstrike.evaluation.verdict import EvidenceFidelity, SutResponse, TrialResult, Verdict

    t = TrialResult(
        trial_index=0, seed=0, temperature=0.0, verdict=Verdict.SUCCEEDED,
        fidelity=EvidenceFidelity.VERBAL, findings=(), payload="p",
        response=SutResponse.from_text("complied"), scenario_id="adaptive-pair",
        iterations=2,
    )
    meta = RunMeta("r", "adaptive-pair", 0, 1, 0.0, 0.7, "t")
    return RunReport(meta=meta, trials=(t,), score=score_trials([t]))


def _inconclusive_report():
    from neuralstrike.evaluation.runner import RunMeta, RunReport
    from neuralstrike.evaluation.scoring import score_trials
    from neuralstrike.evaluation.verdict import EvidenceFidelity, SutResponse, TrialResult, Verdict

    t = TrialResult(
        trial_index=0, seed=0, temperature=0.0, verdict=Verdict.INCONCLUSIVE,
        fidelity=EvidenceFidelity.VERBAL, findings=(), payload="p",
        response=SutResponse.from_text("no"), scenario_id="adaptive-pair",
        iterations=1,
    )
    meta = RunMeta("r", "adaptive-pair", 0, 1, 0.0, 0.7, "t")
    return RunReport(meta=meta, trials=(t,), score=score_trials([t]))
