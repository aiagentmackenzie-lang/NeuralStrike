"""Tests for the advisory Explainer (--explain) + operator flags (delay/timeout/verbosity)."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import patch

import pytest

from neuralstrike.evaluation.explain import Explainer
from neuralstrike.evaluation.runner import RunMeta, RunReport
from neuralstrike.evaluation.verdict import EvidenceFidelity, SutResponse, TrialResult, Verdict
from neuralstrike.oracles.judge import JudgeOracle


def _trial(verdict: Verdict, *, text: str = "ok", scenario_id: str = "s1") -> TrialResult:
    return TrialResult(
        trial_index=0, seed=0, temperature=0.0, verdict=verdict,
        fidelity=EvidenceFidelity.VERBAL, findings=(), payload="p",
        response=SutResponse.from_text(text), scenario_id=scenario_id,
    )


def _report(trial: TrialResult) -> RunReport:
    meta = RunMeta("r", "s1", 0, 1, 0.0, 0.7, "t")
    from neuralstrike.evaluation.scoring import score_trials

    return RunReport(meta=meta, trials=(trial,), score=score_trials([trial]))


def _judge_oracle(reply: dict) -> JudgeOracle:
    async def call_judge(prompt: str) -> str:
        return json.dumps(reply)

    return JudgeOracle(call_judge, role="annotate")


class TestExplainer:
    @pytest.mark.asyncio
    async def test_explains_succeeded_finding(self) -> None:
        judge = _judge_oracle(
            {"verdict": "succeeded", "severity": "high",
             "evidence_quote": "here is the recipe", "rationale": "the SUT complied"}
        )
        explainer = Explainer(judge, redact=False)
        report = _report(_trial(Verdict.SUCCEEDED, text="Sure, here is the recipe: ..."))
        explanations = await explainer.explain(report)
        assert len(explanations) == 1
        assert explanations[0].verdict is Verdict.SUCCEEDED
        assert explanations[0].rationale == "the SUT complied"
        assert explanations[0].evidence_quote == "here is the recipe"
        assert explanations[0].redacted is False

    @pytest.mark.asyncio
    async def test_explains_inconclusive_finding(self) -> None:
        judge = _judge_oracle(
            {"verdict": "inconclusive", "severity": "info", "evidence_quote": None,
             "rationale": "evidence was ambiguous"}
        )
        explainer = Explainer(judge, redact=False)
        report = _report(_trial(Verdict.INCONCLUSIVE, text="maybe"))
        explanations = await explainer.explain(report)
        assert len(explanations) == 1
        assert explanations[0].verdict is Verdict.INCONCLUSIVE
        assert explanations[0].evidence_quote is None

    @pytest.mark.asyncio
    async def test_skips_resisted_findings(self) -> None:
        judge = _judge_oracle({"verdict": "resisted", "severity": "info"})
        explainer = Explainer(judge, redact=False)
        report = _report(_trial(Verdict.RESISTED, text="I refuse."))
        explanations = await explainer.explain(report)
        assert explanations == []  # Resisted findings need no explanation

    @pytest.mark.asyncio
    async def test_redact_suppresses_evidence_quote(self) -> None:
        judge = _judge_oracle(
            {"verdict": "succeeded", "severity": "high",
             "evidence_quote": "sensitive quote", "rationale": "complied"}
        )
        explainer = Explainer(judge, redact=True)
        report = _report(_trial(Verdict.SUCCEEDED, text="sensitive quote"))
        explanations = await explainer.explain(report)
        assert len(explanations) == 1
        assert explanations[0].evidence_quote is None  # redacted
        assert explanations[0].redacted is True
        # The rationale still stands (the "why" without the "what").
        assert explanations[0].rationale == "complied"

    @pytest.mark.asyncio
    async def test_judge_error_skips_explanation_does_not_abort(self) -> None:
        from neuralstrike.core.exceptions import LLMError

        async def boom(prompt: str) -> str:
            raise LLMError("judge", "dead judge")

        explainer = Explainer(JudgeOracle(boom, role="annotate"), redact=False)
        report = _report(_trial(Verdict.SUCCEEDED, text="x"))
        explanations = await explainer.explain(report)
        assert explanations == []  # advisory: a dead Judge skips, never aborts

    @pytest.mark.asyncio
    async def test_skips_trials_with_no_response(self) -> None:
        judge = _judge_oracle({"verdict": "succeeded", "severity": "high"})
        explainer = Explainer(judge, redact=False)
        # A victim-error Inconclusive has response=None.
        t = TrialResult(
            trial_index=0, seed=0, temperature=0.0, verdict=Verdict.INCONCLUSIVE,
            fidelity=EvidenceFidelity.VERBAL, findings=(), payload="p",
            response=None, error="boom", scenario_id="s1",
        )
        report = _report(t)
        assert await explainer.explain(report) == []


class TestRunnerDelay:
    @pytest.mark.asyncio
    async def test_inter_trial_delay_sleeps_between_trials(self, monkeypatch) -> None:
        sleeps: list[float] = []

        async def fake_sleep(seconds: float) -> None:
            sleeps.append(seconds)

        monkeypatch.setattr(asyncio, "sleep", fake_sleep)

        from neuralstrike.core.llm_manager import LLMManager
        from neuralstrike.evaluation.probes import canary_extraction_probe
        from neuralstrike.evaluation.runner import TrialRunner

        mgr = LLMManager.__new__(LLMManager)
        mgr._base_url = "http://localhost:11434"
        mgr._client = None

        async def call_local(model, prompt, options=None):
            return "no leak"

        mgr.call_local = call_local  # type: ignore[method-assign]
        mgr.call_remote = call_local  # type: ignore[method-assign]
        probe = canary_extraction_probe("v", "local", llm=mgr, judge_model=None)
        runner = TrialRunner(base_seed=0, run_dir=None, inter_trial_delay=1.5)
        await runner.run(probe, trials=3, persist=False)
        # 3 trials -> 2 sleeps between them (none before the first).
        assert sleeps == [1.5, 1.5]


class TestRunnerTimeout:
    @pytest.mark.asyncio
    async def test_hung_trial_is_inconclusive(self) -> None:
        from neuralstrike.evaluation.runner import Probe, TrialRunner
        from neuralstrike.evaluation.verdict import Verdict

        async def slow_factory(trial_index, seed, canary):
            await asyncio.sleep(5)  # would hang; timeout fires first
            raise AssertionError("should not reach here")

        probe = Probe(scenario_id="s1", goal="g", factory=slow_factory)
        runner = TrialRunner(base_seed=0, run_dir=None, trial_timeout=0.05)
        report = await runner.run(probe, trials=1, persist=False)
        assert report.trials[0].verdict is Verdict.INCONCLUSIVE
        assert "timed out" in (report.trials[0].error or "")

    @pytest.mark.asyncio
    async def test_no_timeout_completes(self) -> None:
        from neuralstrike.evaluation.runner import Probe, TrialRunner
        from neuralstrike.evaluation.verdict import EvidenceFidelity, SutResponse, Verdict

        async def quick_factory(trial_index, seed, canary):
            return TrialResult(
                trial_index=trial_index, seed=seed, temperature=0.0,
                verdict=Verdict.RESISTED, fidelity=EvidenceFidelity.VERBAL,
                findings=(), payload="p", response=SutResponse.from_text("no"),
                scenario_id="s1",
            )

        probe = Probe(scenario_id="s1", goal="g", factory=quick_factory)
        runner = TrialRunner(base_seed=0, run_dir=None)  # no timeout
        report = await runner.run(probe, trials=1, persist=False)
        assert report.trials[0].verdict is Verdict.RESISTED


class TestVerbosity:
    def test_quiet_sets_warning(self) -> None:
        import logging

        from neuralstrike.main import _apply_verbosity

        _apply_verbosity(quiet=True, verbose=False)
        assert get_logger_level("neuralstrike") == logging.WARNING

    def test_verbose_sets_debug(self) -> None:
        import logging

        from neuralstrike.main import _apply_verbosity

        _apply_verbosity(quiet=False, verbose=True)
        assert get_logger_level("neuralstrike") == logging.DEBUG

    def test_default_sets_info(self) -> None:
        import logging

        from neuralstrike.main import _apply_verbosity

        _apply_verbosity(quiet=False, verbose=False)
        assert get_logger_level("neuralstrike") == logging.INFO


def get_logger_level(name: str) -> int:
    from neuralstrike.utils.logging import get_logger

    return get_logger(name).level


class TestExplainCLI:
    def test_explain_without_judge_warns_but_keeps_exit(self) -> None:
        from typer.testing import CliRunner

        from neuralstrike.main import app

        runner = CliRunner()
        report = _report(_trial(Verdict.RESISTED))

        async def fake_run(self, probe, *, trials=1, judge_model=None, attacker_model=None, persist=True, intensity="standard"):
            return report

        from unittest.mock import AsyncMock

        from neuralstrike.core.runtime import ResolvedModels

        fake_resolved = ResolvedModels(
            attacker_model="deepseek-r1", judge_model="deepseek-v3.1:671b-cloud",
            judge_fell_back=False, available=("deepseek-r1", "deepseek-v3.1:671b-cloud"),
        )
        with patch("neuralstrike.core.runtime.resolve_models", new=AsyncMock(return_value=fake_resolved)), \
             patch("neuralstrike.evaluation.runner.TrialRunner.run", fake_run), \
             patch("neuralstrike.evaluation.probes.canary_extraction_probe"):
            # --no-judge + --explain -> warn and skip, exit still 0.
            result = runner.invoke(
                app,
                ["evaluate", "--target", "victim", "--trials", "1", "--no-judge",
                 "--explain", "--run-dir", "/tmp/ns-runs-test"],
            )
        assert result.exit_code == 0, result.stdout
        assert "requires --judge" in result.stdout or "skipping explanations" in result.stdout
