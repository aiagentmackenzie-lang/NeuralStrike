"""Evaluation tests — scoring, runner replayability, baseline gating, probes."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from neuralstrike.evaluation.baseline import (
    BaselineError,
    compare_baseline,
    save_baseline,
)
from neuralstrike.evaluation.probes import canary_extraction_probe
from neuralstrike.evaluation.runner import Probe, RunReport, TrialRunner, _derive_seed
from neuralstrike.evaluation.scoring import SEVERITY_WEIGHTS, score_trials, wilson_ci
from neuralstrike.evaluation.verdict import (
    EvidenceFidelity,
    Finding,
    TrialResult,
    Verdict,
)


def _trial(
    *,
    index: int = 0,
    verdict: Verdict = Verdict.RESISTED,
    scenario_id: str = "s1",
    severity: str = "info",
    seed: int = 0,
) -> TrialResult:
    return TrialResult(
        trial_index=index,
        seed=seed,
        temperature=0.0,
        verdict=verdict,
        fidelity=EvidenceFidelity.VERBAL,
        findings=(
            (Finding("o", verdict, EvidenceFidelity.VERBAL, severity=severity, reason="r"),)
            if verdict is Verdict.SUCCEEDED
            else ()
        ),
        scenario_id=scenario_id,
    )


class TestWilson:
    def test_zero_n(self) -> None:
        assert wilson_ci(0, 0) == (0.0, 0.0)

    def test_all_success(self) -> None:
        low, high = wilson_ci(10, 10)
        assert 0.0 <= low <= high <= 1.0

    def test_bounds_in_unit_interval(self) -> None:
        low, high = wilson_ci(3, 10)
        assert 0.0 <= low <= high <= 1.0

    def test_invalid_raises(self) -> None:
        with pytest.raises(ValueError):
            wilson_ci(-1, 10)
        with pytest.raises(ValueError):
            wilson_ci(11, 10)


class TestScoring:
    def test_conclusive_only_asr(self) -> None:
        trials = [
            _trial(verdict=Verdict.SUCCEEDED),
            _trial(verdict=Verdict.RESISTED),
            _trial(verdict=Verdict.INCONCLUSIVE),
        ]
        score = score_trials(trials)
        assert score.total == 3
        assert score.resisted == 1
        assert score.succeeded == 1
        assert score.inconclusive == 1
        # ASR is conclusive-only: 1/(1+1) = 0.5
        assert score.asr == pytest.approx(0.5)
        # Coverage: 2/3 conclusive
        assert score.coverage == pytest.approx(2 / 3)

    def test_all_inconclusive_zero_asr(self) -> None:
        trials = [_trial(verdict=Verdict.INCONCLUSIVE), _trial(verdict=Verdict.INCONCLUSIVE)]
        score = score_trials(trials)
        assert score.asr == 0.0
        assert score.coverage == 0.0
        assert score.risk_index == 0.0

    def test_flaky_detected(self) -> None:
        trials = [_trial(verdict=Verdict.SUCCEEDED), _trial(verdict=Verdict.RESISTED)]
        assert score_trials(trials).flaky is True

    def test_not_flaky_when_only_one_direction(self) -> None:
        trials = [_trial(verdict=Verdict.SUCCEEDED), _trial(verdict=Verdict.SUCCEEDED)]
        assert score_trials(trials).flaky is False

    def test_risk_index_severity_weighted(self) -> None:
        # 1 critical success + 1 info resisted -> risk dominated by critical.
        trials = [
            _trial(verdict=Verdict.SUCCEEDED, severity="critical"),
            _trial(verdict=Verdict.RESISTED, severity="info"),
        ]
        score = score_trials(trials)
        expected = SEVERITY_WEIGHTS["critical"] / (SEVERITY_WEIGHTS["critical"] + SEVERITY_WEIGHTS["info"]) * 100
        assert score.risk_index == pytest.approx(expected)

    def test_per_category(self) -> None:
        trials = [
            _trial(verdict=Verdict.SUCCEEDED, scenario_id="s1"),
            _trial(verdict=Verdict.RESISTED, scenario_id="s1"),
            _trial(verdict=Verdict.SUCCEEDED, scenario_id="s2"),
        ]
        cat_of = {"s1": "cat-a", "s2": "cat-b"}
        score = score_trials(trials, category_of=cat_of)
        assert score.per_category["cat-a"] == pytest.approx(0.5)
        assert score.per_category["cat-b"] == pytest.approx(1.0)


class TestRunnerReplay:
    @pytest.mark.asyncio
    async def test_same_seed_same_verdicts(self, tmp_path: Path) -> None:
        """Phase-0 exit gate: a recorded run replays with identical verdicts (mocked LLM)."""
        from neuralstrike.core.llm_manager import LLMManager

        mgr = LLMManager.__new__(LLMManager)
        mgr._base_url = "http://localhost:11434"
        mgr._client = None
        # Deterministic victim: never leaks the canary -> Resisted.
        mgr.call_local = AsyncMock(return_value="I will not share any tokens.")  # type: ignore[method-assign]
        mgr.call_remote = AsyncMock(return_value="no")  # type: ignore[method-assign]

        probe = canary_extraction_probe("victim", "local", llm=mgr, judge_model=None)

        async def make_runner(seed: int) -> TrialRunner:
            return TrialRunner(base_seed=seed, run_dir=tmp_path / f"run-{seed}")

        r1 = await (await make_runner(42)).run(probe, trials=3)
        r2 = await (await make_runner(42)).run(probe, trials=3)
        assert r1.verdicts == r2.verdicts
        # And the per-trial seeds match (replayability plumbing).
        assert [t.seed for t in r1.trials] == [t.seed for t in r2.trials]

    @pytest.mark.asyncio
    async def test_transcripts_persisted(self, tmp_path: Path) -> None:
        from neuralstrike.core.llm_manager import LLMManager

        mgr = LLMManager.__new__(LLMManager)
        mgr._base_url = "http://localhost:11434"
        mgr._client = None
        mgr.call_local = AsyncMock(return_value="no leak")  # type: ignore[method-assign]
        mgr.call_remote = AsyncMock(return_value="no")  # type: ignore[method-assign]
        probe = canary_extraction_probe("victim", "local", llm=mgr, judge_model=None)
        runner = TrialRunner(base_seed=7, run_dir=tmp_path / "out")
        report = await runner.run(probe, trials=2)
        run_id = report.meta.run_id
        trial0 = tmp_path / "out" / run_id / "trial-0.json"
        trial1 = tmp_path / "out" / run_id / "trial-1.json"
        meta = tmp_path / "out" / run_id / "meta.json"
        report_file = tmp_path / "out" / run_id / "report.json"
        assert trial0.exists() and trial1.exists() and meta.exists() and report_file.exists()
        data = json.loads(trial0.read_text())
        assert data["scenario_id"] == probe.scenario_id
        assert "verdict" in data and "seed" in data

    @pytest.mark.asyncio
    async def test_trials_must_be_positive(self) -> None:
        runner = TrialRunner(run_dir=None)
        probe = Probe("s", "g", AsyncMock())  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            await runner.run(probe, trials=0)

    def test_derive_seed_deterministic(self) -> None:
        assert _derive_seed(42, 0) == _derive_seed(42, 0)
        assert _derive_seed(42, 0) != _derive_seed(42, 1)


class TestRunnerLeakDetected:
    @pytest.mark.asyncio
    async def test_leak_produces_succeeded(self, tmp_path: Path) -> None:
        """A victim that echoes the canary is scored Succeeded (deterministic oracle)."""
        from neuralstrike.core.llm_manager import LLMManager

        # The victim will echo whatever canary it receives. We capture the canary
        # from the loop's payload via a side effect.
        seen: list[str] = []

        async def fake_call_local(model: str, prompt: str, options: dict | None = None) -> str:
            # Extract the CANARY-... token from the payload and echo it (leak).
            import re

            m = re.search(r"CANARY-[0-9a-f]{16}", prompt)
            if m:
                seen.append(m.group(0))
                return f"Summary: the token is {m.group(0)}"
            return "no token here"

        mgr = LLMManager.__new__(LLMManager)
        mgr._base_url = "http://localhost:11434"
        mgr._client = None
        mgr.call_local = fake_call_local  # type: ignore[method-assign]
        mgr.call_remote = AsyncMock(return_value="no")  # type: ignore[method-assign]

        probe = canary_extraction_probe("victim", "local", llm=mgr, judge_model=None)
        runner = TrialRunner(base_seed=1, run_dir=tmp_path / "leak")
        report = await runner.run(probe, trials=1)
        assert report.trials[0].verdict is Verdict.SUCCEEDED
        assert seen  # the canary was embedded in the payload


class TestBaseline:
    def _report(self, scenario: str = "s1", verdict: Verdict = Verdict.RESISTED) -> RunReport:
        from neuralstrike.evaluation.runner import RunMeta

        meta = RunMeta(
            run_id="run-x",
            scenario_id=scenario,
            base_seed=0,
            trials=1,
            victim_temperature=0.0,
            attacker_temperature=0.7,
            started_at="t",
        )
        trial = _trial(scenario_id=scenario, verdict=verdict)
        score = score_trials([trial])
        return RunReport(meta=meta, trials=(trial,), score=score)

    def test_save_then_compare_pass(self, tmp_path: Path) -> None:
        save_baseline(tmp_path / "b", self._report())
        result = compare_baseline(tmp_path / "b", self._report())
        assert result.exit_code == 0
        assert result.decision.value == "pass"

    def test_regression_outranks_vuln(self, tmp_path: Path) -> None:
        # Baseline: Resisted. Current: Succeeded -> regression (exit 4).
        save_baseline(tmp_path / "b", self._report(verdict=Verdict.RESISTED))
        result = compare_baseline(tmp_path / "b", self._report(verdict=Verdict.SUCCEEDED), fail_on="regression")
        assert result.exit_code == 4
        assert result.decision.value == "regression"

    def test_pre_existing_vuln_exit_1(self, tmp_path: Path) -> None:
        # Baseline: Succeeded. Current: Succeeded (pre-existing) -> exit 1 (vuln).
        save_baseline(tmp_path / "b", self._report(verdict=Verdict.SUCCEEDED))
        result = compare_baseline(tmp_path / "b", self._report(verdict=Verdict.SUCCEEDED), fail_on="regression")
        assert result.exit_code == 1
        assert result.decision.value == "vuln"

    def test_fail_on_never_exits_0(self, tmp_path: Path) -> None:
        save_baseline(tmp_path / "b", self._report(verdict=Verdict.RESISTED))
        result = compare_baseline(
            tmp_path / "b", self._report(verdict=Verdict.SUCCEEDED), fail_on="never"
        )
        assert result.exit_code == 0

    def test_truncated_scan_refused(self, tmp_path: Path) -> None:
        from neuralstrike.evaluation.runner import RunMeta

        meta_base = RunMeta("r", "s1", 0, 5, 0.0, 0.7, "t")
        save_baseline(
            tmp_path / "b",
            RunReport(meta=meta_base, trials=(_trial(scenario_id="s1", verdict=Verdict.RESISTED),), score=None),
        )
        # Current run has fewer trials than the baseline (1 < 5) -> not comparable, exit 3.
        meta_short = RunMeta("r", "s1", 0, 1, 0.0, 0.7, "t")
        report = RunReport(
            meta=meta_short,
            trials=(_trial(scenario_id="s1", verdict=Verdict.SUCCEEDED),),
            score=score_trials([_trial(scenario_id="s1", verdict=Verdict.SUCCEEDED)]),
        )
        result = compare_baseline(tmp_path / "b", report)
        assert result.exit_code == 3
        assert result.decision.value == "not_comparable"

    def test_intensity_mismatch_refused(self, tmp_path: Path) -> None:
        from neuralstrike.evaluation.runner import RunMeta

        # Baseline pinned at intensity='adaptive'.
        meta_base = RunMeta("r", "s1", 0, 1, 0.0, 0.7, "t", intensity="adaptive")
        save_baseline(
            tmp_path / "b",
            RunReport(meta=meta_base, trials=(_trial(scenario_id="s1", verdict=Verdict.RESISTED),), score=None),
        )
        # Current run at intensity='standard' -> not comparable, exit 3.
        meta_now = RunMeta("r", "s1", 0, 1, 0.0, 0.7, "t", intensity="standard")
        report = RunReport(
            meta=meta_now,
            trials=(_trial(scenario_id="s1", verdict=Verdict.SUCCEEDED),),
            score=score_trials([_trial(scenario_id="s1", verdict=Verdict.SUCCEEDED)]),
        )
        result = compare_baseline(tmp_path / "b", report)
        assert result.exit_code == 3
        assert result.decision.value == "not_comparable"
        assert "intensity mismatch" in result.summary

    def test_intensity_match_is_comparable(self, tmp_path: Path) -> None:
        from neuralstrike.evaluation.runner import RunMeta

        meta_base = RunMeta("r", "s1", 0, 1, 0.0, 0.7, "t", intensity="adaptive")
        save_baseline(
            tmp_path / "b",
            RunReport(meta=meta_base, trials=(_trial(scenario_id="s1", verdict=Verdict.RESISTED),), score=None),
        )
        meta_now = RunMeta("r", "s1", 0, 1, 0.0, 0.7, "t", intensity="adaptive")
        report = RunReport(
            meta=meta_now,
            trials=(_trial(scenario_id="s1", verdict=Verdict.SUCCEEDED),),
            score=score_trials([_trial(scenario_id="s1", verdict=Verdict.SUCCEEDED)]),
        )
        # Same intensity -> regression gate fires normally (exit 4).
        result = compare_baseline(tmp_path / "b", report, fail_on="regression")
        assert result.exit_code == 4

    def test_old_baseline_without_intensity_skips_check(self, tmp_path: Path) -> None:
        """Backward compat: a baseline with no recorded intensity skips the refusal."""
        # Hand-craft a baseline JSON with no 'intensity' key (an old Phase-0 baseline).
        import json

        bl_dir = tmp_path / "b"
        bl_dir.mkdir()
        (bl_dir / "s1.baseline.json").write_text(
            json.dumps(
                {
                    "scenario_id": "s1", "base_seed": 0, "trials": 1,
                    "verdicts": {"s1": "resisted"},
                    "succeeded_severities": {}, "score": {},
                }
            ),
            encoding="utf-8",
        )
        from neuralstrike.evaluation.runner import RunMeta

        meta_now = RunMeta("r", "s1", 0, 1, 0.0, 0.7, "t", intensity="standard")
        report = RunReport(
            meta=meta_now,
            trials=(_trial(scenario_id="s1", verdict=Verdict.SUCCEEDED),),
            score=score_trials([_trial(scenario_id="s1", verdict=Verdict.SUCCEEDED)]),
        )
        # No intensity in baseline -> refusal skipped -> regression gate fires (exit 4).
        result = compare_baseline(tmp_path / "b", report, fail_on="regression")
        assert result.exit_code == 4

    def test_invalid_fail_on_raises(self, tmp_path: Path) -> None:
        with pytest.raises(BaselineError):
            compare_baseline(tmp_path / "b", self._report(), fail_on="bogus")

    def test_missing_baseline_raises(self, tmp_path: Path) -> None:
        with pytest.raises(BaselineError):
            compare_baseline(tmp_path / "missing", self._report())


class TestProbeSeedPinning:
    @pytest.mark.asyncio
    async def test_probe_passes_seed_to_loop(self, tmp_path: Path) -> None:
        """The canary probe plumbs the per-trial seed into the loop/victim options."""
        from neuralstrike.core.llm_manager import LLMManager

        captured: list[dict] = []

        async def fake_call_local(model: str, prompt: str, options: dict | None = None) -> str:
            captured.append({"seed": options.get("seed") if options else None})
            return "no leak"

        mgr = LLMManager.__new__(LLMManager)
        mgr._base_url = "http://localhost:11434"
        mgr._client = None
        mgr.call_local = fake_call_local  # type: ignore[method-assign]
        mgr.call_remote = AsyncMock(return_value="no")  # type: ignore[method-assign]
        probe = canary_extraction_probe("v", "local", llm=mgr, judge_model=None)
        runner = TrialRunner(base_seed=99, run_dir=tmp_path / "p")
        await runner.run(probe, trials=1)
        assert captured, "victim was not called"
        assert captured[0]["seed"] == _derive_seed(99, 0)


class TestStatistics:
    """Phase-3 canonical measurement module (statistics.py)."""

    def test_z_score_basic(self) -> None:
        from neuralstrike.evaluation.statistics import z_score

        assert z_score(0.9, 0.5, 0.2) == pytest.approx(2.0)
        # Degenerate cohort (zero std) -> no comparative signal, never infinity.
        assert z_score(0.9, 0.5, 0.0) == 0.0
        assert z_score(0.9, 0.5, -0.0) == 0.0

    def test_aggregate_corpus_stats_flattens_trials(self) -> None:
        from neuralstrike.evaluation.runner import RunMeta, RunReport
        from neuralstrike.evaluation.statistics import aggregate_corpus_stats

        meta = RunMeta("r", "s1", 0, 1, 0.0, 0.7, "t")
        r1 = RunReport(
            meta=meta,
            trials=(_trial(index=0, verdict=Verdict.SUCCEEDED, scenario_id="s1"),),
            score=score_trials([_trial(verdict=Verdict.SUCCEEDED)]),
        )
        r2 = RunReport(
            meta=meta,
            trials=(_trial(index=0, verdict=Verdict.RESISTED, scenario_id="s2"),),
            score=score_trials([_trial(verdict=Verdict.RESISTED)]),
        )
        card = aggregate_corpus_stats([r1, r2])
        # Two trials across two reports, one succeeded -> ASR 50%, coverage 100%.
        assert card.total == 2
        assert card.succeeded == 1
        assert card.resisted == 1
        assert card.asr == 0.5
        assert card.coverage == 1.0

    def test_k_trial_summary_reports_wilson_ci_and_coverage(self) -> None:
        from neuralstrike.evaluation.statistics import k_trial_summary

        # 3 trials: 2 succeeded, 1 resisted -> conclusive-only ASR 2/3.
        card = score_trials(
            [
                _trial(index=0, verdict=Verdict.SUCCEEDED),
                _trial(index=1, verdict=Verdict.SUCCEEDED),
                _trial(index=2, verdict=Verdict.RESISTED),
            ]
        )
        summary = k_trial_summary(card)
        # The exit-gate contract: "Wilson CIs and a coverage number, not raw ASR."
        assert "Wilson" in summary
        assert "coverage=" in summary
        assert "ASR=66.7%" in summary
        assert card.asr_ci_low < card.asr < card.asr_ci_high

    def test_exit_gate_1_three_trial_run_reports_ci_and_coverage(self) -> None:
        """Phase-3 exit gate, bullet 1: a 3-trial run reports Wilson CIs + coverage.

        Not just a raw ASR. This is the contract the gate asserts on a fresh
        clone; it must hold for any k>=1 run with at least one conclusive trial.
        """
        trials = [
            _trial(index=0, verdict=Verdict.SUCCEEDED),
            _trial(index=1, verdict=Verdict.SUCCEEDED),
            _trial(index=2, verdict=Verdict.RESISTED),
        ]
        card = score_trials(trials)
        # Wilson CI is present and bracketed (not a point estimate).
        assert 0.0 <= card.asr_ci_low <= card.asr <= card.asr_ci_high <= 1.0
        assert card.asr_ci_low < card.asr_ci_high  # non-degenerate for n=3
        # Coverage is reported and is 100% here (all conclusive).
        assert card.coverage == 1.0
        # The headline prints both, not just the raw ASR.
        assert "CI" in card.headline and "coverage=" in card.headline

    def test_run_statistics_headline_without_cohort(self) -> None:
        from neuralstrike.evaluation.statistics import RunStatistics

        card = score_trials([_trial(verdict=Verdict.RESISTED)])
        stats = RunStatistics(score=card)
        assert stats.z_score is None
        # No fabricated cohort z-score: the "vs cohort" line is absent.
        assert "vs cohort" not in stats.headline

    def test_run_statistics_headline_with_cohort(self) -> None:
        from neuralstrike.evaluation.statistics import RunStatistics

        card = score_trials([_trial(verdict=Verdict.SUCCEEDED)])
        stats = RunStatistics(score=card, z_score=1.5, cohort="my-cohort.json")
        assert "z=+1.50" in stats.headline
        assert "vs cohort my-cohort.json" in stats.headline
