"""Calibration tests — cohort-relative z-score, informational, no built-in cohort."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from neuralstrike.evaluation.calibration import (
    CalibrationError,
    Cohort,
    CohortStats,
    calibrate,
    load_cohort,
)
from neuralstrike.evaluation.scoring import score_trials
from neuralstrike.evaluation.verdict import EvidenceFidelity, TrialResult, Verdict
from neuralstrike.main import app


def _trial(verdict: Verdict = Verdict.SUCCEEDED) -> TrialResult:
    return TrialResult(
        trial_index=0,
        seed=0,
        temperature=0.0,
        verdict=verdict,
        fidelity=EvidenceFidelity.VERBAL,
        findings=(),
        scenario_id="s1",
    )


class TestCohortLoading:
    def test_loads_valid_cohort(self, tmp_path: Path) -> None:
        p = tmp_path / "c.json"
        p.write_text(
            json.dumps(
                {
                    "name": "defenders",
                    "description": "20 SUTs",
                    "asr": {"mean": 0.45, "std": 0.12, "n": 20},
                    "per_category": {"asi01": {"mean": 0.6, "std": 0.1}},
                }
            ),
            encoding="utf-8",
        )
        cohort = load_cohort(p)
        assert cohort.name == "defenders"
        assert cohort.asr.mean == 0.45
        assert cohort.asr.std == 0.12
        assert cohort.per_category["asi01"].mean == 0.6

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(CalibrationError):
            load_cohort(tmp_path / "nope.json")

    def test_missing_name_raises(self, tmp_path: Path) -> None:
        p = tmp_path / "c.json"
        p.write_text(json.dumps({"asr": {"mean": 0.4, "std": 0.1}}), encoding="utf-8")
        with pytest.raises(CalibrationError):
            load_cohort(p)

    def test_missing_asr_raises(self, tmp_path: Path) -> None:
        p = tmp_path / "c.json"
        p.write_text(json.dumps({"name": "x"}), encoding="utf-8")
        with pytest.raises(CalibrationError):
            load_cohort(p)

    def test_mean_out_of_range_raises(self, tmp_path: Path) -> None:
        p = tmp_path / "c.json"
        p.write_text(json.dumps({"name": "x", "asr": {"mean": 1.5, "std": 0.1}}), encoding="utf-8")
        with pytest.raises(CalibrationError):
            load_cohort(p)

    def test_negative_std_raises(self, tmp_path: Path) -> None:
        p = tmp_path / "c.json"
        p.write_text(json.dumps({"name": "x", "asr": {"mean": 0.5, "std": -0.1}}), encoding="utf-8")
        with pytest.raises(CalibrationError):
            load_cohort(p)

    def test_invalid_json_raises(self, tmp_path: Path) -> None:
        p = tmp_path / "c.json"
        p.write_text("{not json", encoding="utf-8")
        with pytest.raises(CalibrationError):
            load_cohort(p)


class TestCalibrate:
    def test_z_score_above_cohort(self) -> None:
        score = score_trials(
            [_trial(Verdict.SUCCEEDED), _trial(Verdict.SUCCEEDED), _trial(Verdict.RESISTED)]
        )
        cohort = Cohort(name="c", asr=CohortStats(mean=0.4, std=0.1))
        cal = calibrate(score, cohort)
        assert cal.z == pytest.approx((score.asr - 0.4) / 0.1)
        assert cal.observed_asr == score.asr
        assert "above" in cal.interpretation or "consistent" in cal.interpretation

    def test_degenerate_cohort_zero_z(self) -> None:
        score = score_trials([_trial(Verdict.SUCCEEDED)])
        cohort = Cohort(name="c", asr=CohortStats(mean=0.5, std=0.0))
        cal = calibrate(score, cohort)
        assert cal.z == 0.0
        assert cal.interpretation == "degenerate cohort (std=0); no comparative signal"

    def test_interpretation_buckets(self) -> None:
        from neuralstrike.evaluation.statistics import ScoreCard

        cohort = Cohort(name="c", asr=CohortStats(mean=0.5, std=0.1))
        # z = (0.75 - 0.5)/0.1 = 2.5 -> far above (clear of the 2.0 boundary).
        far_above = ScoreCard(
            total=10, resisted=3, succeeded=7, inconclusive=0,
            asr=0.75, asr_ci_low=0.4, asr_ci_high=0.9, coverage=1.0, risk_index=70.0, flaky=False,
        )
        assert calibrate(far_above, cohort).interpretation == "far above cohort average (>+2 sigma)"

        consistent = ScoreCard(
            total=10, resisted=5, succeeded=5, inconclusive=0,
            asr=0.5, asr_ci_low=0.2, asr_ci_high=0.8, coverage=1.0, risk_index=50.0, flaky=False,
        )
        assert calibrate(consistent, cohort).interpretation == "consistent with cohort average (within +/-1 sigma)"

        # z = (0.05 - 0.5)/0.1 = -4.5 -> far below.
        far_below = ScoreCard(
            total=10, resisted=9, succeeded=1, inconclusive=0,
            asr=0.05, asr_ci_low=0.0, asr_ci_high=0.4, coverage=1.0, risk_index=10.0, flaky=False,
        )
        assert calibrate(far_below, cohort).interpretation == "far below cohort average (<-2 sigma)"

    def test_per_category_only_for_overlap(self) -> None:
        from neuralstrike.evaluation.statistics import ScoreCard

        score = ScoreCard(
            total=2, resisted=1, succeeded=1, inconclusive=0,
            asr=0.5, asr_ci_low=0.0, asr_ci_high=1.0, coverage=1.0, risk_index=50.0, flaky=False,
            per_category={"asi01": 0.8, "asi02": 0.2},
        )
        cohort = Cohort(
            name="c",
            asr=CohortStats(mean=0.5, std=0.1),
            per_category={"asi01": CohortStats(mean=0.5, std=0.1)},  # asi02 absent in cohort
        )
        cal = calibrate(score, cohort)
        assert "asi01" in cal.per_category
        assert "asi02" not in cal.per_category  # not fabricated


class TestNoBundledCohortInvariant:
    """Decision: ship NO built-in cohort. A fabricated cohort makes every z-score a lie."""

    def test_no_cohort_json_shipped_in_repo(self) -> None:
        # No *.cohort.json or cohorts/ directory ships in the package or repo.
        import neuralstrike

        pkg_root = Path(neuralstrike.__file__).resolve().parent
        candidates = list(pkg_root.rglob("*.cohort.json")) + list(pkg_root.rglob("cohort*.json"))
        repo_root = pkg_root.parent.parent
        candidates += list((repo_root / "cohorts").glob("*")) if (repo_root / "cohorts").is_dir() else []
        assert not candidates, (
            "NeuralStrike must ship NO built-in cohort file (a fabricated cohort makes "
            f"every z-score a lie); found: {candidates}"
        )


class TestCalibrationCLIInformational:
    """--calibration prints a z-score but never changes the exit code."""

    def _report(self):
        from neuralstrike.evaluation.runner import RunMeta, RunReport

        trial = TrialResult(
            trial_index=0, seed=0, temperature=0.0,
            verdict=Verdict.RESISTED, fidelity=EvidenceFidelity.VERBAL,
            findings=(), payload="p", scenario_id="asi01-canary-leak",
        )
        meta = RunMeta("run-test", "asi01-canary-leak", 0, 1, 0.0, 0.7, "t")
        return RunReport(meta=meta, trials=(trial,), score=score_trials([trial]))

    def test_calibration_does_not_change_pass_exit(self, tmp_path: Path) -> None:
        runner = CliRunner()
        report = self._report()

        async def fake_run(self, probe, *, trials=1, judge_model=None, attacker_model=None, persist=True, intensity="standard"):
            return report

        from neuralstrike.core.runtime import ResolvedModels

        fake_resolved = ResolvedModels(
            attacker_model="deepseek-r1", judge_model="deepseek-v3.1:671b-cloud",
            judge_fell_back=False, available=("deepseek-r1", "deepseek-v3.1:671b-cloud"),
        )
        cohort_p = tmp_path / "c.json"
        cohort_p.write_text(json.dumps({"name": "c", "asr": {"mean": 0.2, "std": 0.1, "n": 5}}), encoding="utf-8")
        with patch("neuralstrike.core.runtime.resolve_models", new=AsyncMock(return_value=fake_resolved)), \
             patch("neuralstrike.evaluation.runner.TrialRunner.run", fake_run), \
             patch("neuralstrike.evaluation.probes.canary_extraction_probe"):
            result = runner.invoke(
                app,
                [
                    "evaluate", "--target", "victim", "--trials", "1",
                    "--calibration", str(cohort_p),
                    "--run-dir", str(tmp_path / "runs"),
                ],
            )
        assert result.exit_code == 0, result.stdout
        assert "Cohort calibration" in result.stdout  # the z-score printed

    def test_calibration_bad_file_skips_but_keeps_exit(self, tmp_path: Path) -> None:
        runner = CliRunner()
        report = self._report()

        async def fake_run(self, probe, *, trials=1, judge_model=None, attacker_model=None, persist=True, intensity="standard"):
            return report

        from neuralstrike.core.runtime import ResolvedModels

        fake_resolved = ResolvedModels(
            attacker_model="deepseek-r1", judge_model="deepseek-v3.1:671b-cloud",
            judge_fell_back=False, available=("deepseek-r1", "deepseek-v3.1:671b-cloud"),
        )
        with patch("neuralstrike.core.runtime.resolve_models", new=AsyncMock(return_value=fake_resolved)), \
             patch("neuralstrike.evaluation.runner.TrialRunner.run", fake_run), \
             patch("neuralstrike.evaluation.probes.canary_extraction_probe"):
            result = runner.invoke(
                app,
                [
                    "evaluate", "--target", "victim", "--trials", "1",
                    "--calibration", str(tmp_path / "missing.json"),
                    "--run-dir", str(tmp_path / "runs"),
                ],
            )
        assert result.exit_code == 0, result.stdout  # gate still passes; calibration skipped
        assert "Calibration skipped" in result.stdout
