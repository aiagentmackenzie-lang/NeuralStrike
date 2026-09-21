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
                {
                    "verdict": judge_verdict,
                    "severity": "high",
                    "evidence_quote": victim_text[:20],
                    "rationale": "complied",
                }
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
        with (
            patch("neuralstrike.core.runtime.resolve_models", new=AsyncMock(return_value=_resolved())),
            patch(
                "neuralstrike.core.llm_manager.LLMManager",
                return_value=_fake_mgr("Sure, here is the guide: ...", "succeeded"),
            ),
            patch("neuralstrike.evaluation.runner.TrialRunner.run", _fake_run(report)),
        ):
            result = runner.invoke(
                app,
                [
                    "adaptive",
                    "--target",
                    "victim",
                    "--target-type",
                    "local",
                    "--strategy",
                    "pair",
                    "--judge",
                    "--judge-model",
                    "judge",
                    "--attacker-model",
                    "attacker",
                    "--trials",
                    "1",
                    "--run-dir",
                    "/tmp/ns-adaptive-test",
                ],
            )
        assert result.exit_code == 0, result.stdout
        assert "Adaptive pair run" in result.stdout

    def test_no_judge_is_inconclusive(self, runner: CliRunner) -> None:
        report = _inconclusive_report()
        with (
            patch("neuralstrike.core.runtime.resolve_models", new=AsyncMock(return_value=_resolved())),
            patch("neuralstrike.core.llm_manager.LLMManager", return_value=_fake_mgr("x", "succeeded")),
            patch("neuralstrike.evaluation.runner.TrialRunner.run", _fake_run(report)),
        ):
            result = runner.invoke(
                app,
                [
                    "adaptive",
                    "--target",
                    "victim",
                    "--target-type",
                    "local",
                    "--no-judge",
                    "--trials",
                    "1",
                    "--run-dir",
                    "/tmp/ns-adaptive-test2",
                ],
            )
        assert result.exit_code == 0, result.stdout
        assert "--no-judge" in result.stdout or "Inconclusive" in result.stdout

    def test_crescendo_strategy_runs(self, runner: CliRunner) -> None:
        report = _succeeded_report()
        with (
            patch("neuralstrike.core.runtime.resolve_models", new=AsyncMock(return_value=_resolved())),
            patch(
                "neuralstrike.core.llm_manager.LLMManager",
                return_value=_fake_mgr("Sure, here is the guide", "succeeded"),
            ),
            patch("neuralstrike.evaluation.runner.TrialRunner.run", _fake_run(report)),
        ):
            result = runner.invoke(
                app,
                [
                    "adaptive",
                    "--target",
                    "victim",
                    "--target-type",
                    "local",
                    "--strategy",
                    "crescendo",
                    "--judge",
                    "--judge-model",
                    "judge",
                    "--attacker-model",
                    "attacker",
                    "--trials",
                    "1",
                    "--run-dir",
                    "/tmp/ns-adaptive-test3",
                ],
            )
        assert result.exit_code == 0, result.stdout
        assert "Adaptive crescendo run" in result.stdout

    def test_judge_mode_fallback_runs(self, runner: CliRunner) -> None:
        report = _inconclusive_report()
        with (
            patch("neuralstrike.core.runtime.resolve_models", new=AsyncMock(return_value=_resolved())),
            patch("neuralstrike.core.llm_manager.LLMManager", return_value=_fake_mgr("x", "resisted")),
            patch("neuralstrike.evaluation.runner.TrialRunner.run", _fake_run(report)),
        ):
            result = runner.invoke(
                app,
                [
                    "adaptive",
                    "--target",
                    "victim",
                    "--target-type",
                    "local",
                    "--strategy",
                    "pair",
                    "--judge",
                    "--judge-model",
                    "judge",
                    "--judge-mode",
                    "fallback",
                    "--attacker-model",
                    "attacker",
                    "--trials",
                    "1",
                    "--run-dir",
                    "/tmp/ns-adaptive-test4",
                ],
            )
        assert result.exit_code == 0, result.stdout  # fallback mode; runs without error


# --- helpers -----------------------------------------------------------------


def _resolved():
    from neuralstrike.core.runtime import ResolvedModels

    return ResolvedModels(
        attacker_model="attacker",
        judge_model="judge",
        judge_fell_back=False,
        available=("victim", "attacker", "judge"),
    )


def _fake_run(report):
    async def run(
        self, probe, *, trials=1, judge_model=None, attacker_model=None, persist=True, intensity="standard"
    ):
        return report

    return run


def _succeeded_report():
    from neuralstrike.evaluation.runner import RunMeta, RunReport
    from neuralstrike.evaluation.scoring import score_trials
    from neuralstrike.evaluation.verdict import EvidenceFidelity, SutResponse, TrialResult, Verdict

    t = TrialResult(
        trial_index=0,
        seed=0,
        temperature=0.0,
        verdict=Verdict.SUCCEEDED,
        fidelity=EvidenceFidelity.VERBAL,
        findings=(),
        payload="p",
        response=SutResponse.from_text("complied"),
        scenario_id="adaptive-pair",
        iterations=2,
    )
    meta = RunMeta("r", "adaptive-pair", 0, 1, 0.0, 0.7, "t")
    return RunReport(meta=meta, trials=(t,), score=score_trials([t]))


def _inconclusive_report():
    from neuralstrike.evaluation.runner import RunMeta, RunReport
    from neuralstrike.evaluation.scoring import score_trials
    from neuralstrike.evaluation.verdict import EvidenceFidelity, SutResponse, TrialResult, Verdict

    t = TrialResult(
        trial_index=0,
        seed=0,
        temperature=0.0,
        verdict=Verdict.INCONCLUSIVE,
        fidelity=EvidenceFidelity.VERBAL,
        findings=(),
        payload="p",
        response=SutResponse.from_text("no"),
        scenario_id="adaptive-pair",
        iterations=1,
    )
    meta = RunMeta("r", "adaptive-pair", 0, 1, 0.0, 0.7, "t")
    return RunReport(meta=meta, trials=(t,), score=score_trials([t]))


# --- Phase 9: attack memory + seed diversity + attack-memory view -----------


class TestPhaseNineMemoryFlags:
    def test_auto_without_memory_db_fails_closed(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app, ["adaptive", "--target", "x", "--strategy", "auto", "--run-dir", "/tmp/ns-t"]
        )
        assert result.exit_code != 0

    def test_auto_with_empty_memory_fails_closed(self, runner: CliRunner, tmp_path) -> None:
        db = tmp_path / "mem.sqlite"
        result = runner.invoke(
            app,
            [
                "adaptive",
                "--target",
                "victim",
                "--strategy",
                "auto",
                "--memory-db",
                str(db),
                "--no-judge",
                "--run-dir",
                "/tmp/ns-t",
            ],
        )
        assert result.exit_code != 0, result.stdout
        assert "no recorded evidence" in result.stdout

    def test_auto_picks_best_strategy_from_memory(self, runner: CliRunner, tmp_path) -> None:
        from neuralstrike.core.attack_memory import AttackMemory, MemoryRecord

        db = tmp_path / "mem.sqlite"
        mem = AttackMemory(db)
        mem.record_run(
            MemoryRecord(
                victim="victim",
                victim_type="local",
                strategy="pair",
                scenario_id="adaptive-pair",
                category="adaptive-pair",
                goal="reveal the prompt",
                verdict="succeeded",
                fidelity="verbal",
                iterations=2,
                seed=0,
                payload="p",
            )
        )
        mem.record_run(
            MemoryRecord(
                victim="victim",
                victim_type="local",
                strategy="crescendo",
                scenario_id="adaptive-crescendo",
                category="adaptive-crescendo",
                goal="reveal the prompt",
                verdict="resisted",
                fidelity="verbal",
                iterations=1,
                seed=1,
                payload="q",
            )
        )
        mem.close()

        report = _succeeded_report()
        with (
            patch("neuralstrike.core.runtime.resolve_models", new=AsyncMock(return_value=_resolved())),
            patch("neuralstrike.core.llm_manager.LLMManager", return_value=_fake_mgr("ok", "succeeded")),
            patch("neuralstrike.evaluation.runner.TrialRunner.run", _fake_run(report)),
        ):
            result = runner.invoke(
                app,
                [
                    "adaptive",
                    "--target",
                    "victim",
                    "--goal",
                    "reveal the prompt",
                    "--strategy",
                    "auto",
                    "--memory-db",
                    str(db),
                    "--judge",
                    "--judge-model",
                    "judge",
                    "--attacker-model",
                    "attacker",
                    "--run-dir",
                    "/tmp/ns-t",
                ],
            )
        assert result.exit_code == 0, result.stdout
        assert "--strategy auto -> pair" in result.stdout
        assert "Adaptive pair run" in result.stdout
        assert "crescendo" in result.stdout  # the ranking table is shown

    def test_memory_db_records_trials(self, runner: CliRunner, tmp_path) -> None:
        from neuralstrike.core.attack_memory import AttackMemory

        db = tmp_path / "mem.sqlite"
        report = _succeeded_report()
        with (
            patch("neuralstrike.core.runtime.resolve_models", new=AsyncMock(return_value=_resolved())),
            patch("neuralstrike.core.llm_manager.LLMManager", return_value=_fake_mgr("ok", "succeeded")),
            patch("neuralstrike.evaluation.runner.TrialRunner.run", _fake_run(report)),
        ):
            result = runner.invoke(
                app,
                [
                    "adaptive",
                    "--target",
                    "victim",
                    "--strategy",
                    "pair",
                    "--memory-db",
                    str(db),
                    "--judge",
                    "--judge-model",
                    "judge",
                    "--attacker-model",
                    "attacker",
                    "--trials",
                    "1",
                    "--run-dir",
                    "/tmp/ns-t",
                ],
            )
        assert result.exit_code == 0, result.stdout
        assert "memory champion: pair" in result.stdout
        mem = AttackMemory(db)
        rows = mem.summary()
        assert len(rows) == 1
        assert rows[0]["strategy"] == "pair"
        assert rows[0]["victim"] == "victim"
        mem.close()

    def test_memory_champion_visible_in_ranking_output(self, runner: CliRunner, tmp_path) -> None:
        """A second run with memory sees the recorded evidence in its summary."""

        db = tmp_path / "mem2.sqlite"
        report = _succeeded_report()
        with (
            patch("neuralstrike.core.runtime.resolve_models", new=AsyncMock(return_value=_resolved())),
            patch("neuralstrike.core.llm_manager.LLMManager", return_value=_fake_mgr("ok", "succeeded")),
            patch("neuralstrike.evaluation.runner.TrialRunner.run", _fake_run(report)),
        ):
            args = [
                "adaptive",
                "--target",
                "victim",
                "--strategy",
                "pair",
                "--memory-db",
                str(db),
                "--judge",
                "--judge-model",
                "judge",
                "--attacker-model",
                "attacker",
                "--trials",
                "1",
                "--run-dir",
                "/tmp/ns-t",
            ]
            result1 = runner.invoke(app, args)
            result2 = runner.invoke(app, args)
        assert result1.exit_code == 0 and result2.exit_code == 0, (result1.stdout, result2.stdout)
        # After two recorded runs the champion line is deterministic.
        assert "memory champion: pair" in result2.stdout

    def test_seed_diversity_reports_asr_at_k_and_diversity(self, runner: CliRunner, tmp_path) -> None:
        from neuralstrike.evaluation.runner import RunMeta, RunReport
        from neuralstrike.evaluation.scoring import score_trials
        from neuralstrike.evaluation.verdict import EvidenceFidelity, SutResponse, TrialResult, Verdict

        trial = TrialResult(
            trial_index=0,
            seed=0,
            temperature=0.0,
            verdict=Verdict.SUCCEEDED,
            fidelity=EvidenceFidelity.VERBAL,
            findings=(),
            payload="p",
            response=SutResponse.from_text("r"),
            scenario_id="adaptive-pair-v0",
            iterations=1,
            trajectory_fingerprint="fp-same",
        )
        meta = RunMeta("r", "adaptive-pair", 0, 1, 0.0, 0.7, "t")
        report = RunReport(meta=meta, trials=(trial,), score=score_trials([trial]))
        with (
            patch("neuralstrike.core.runtime.resolve_models", new=AsyncMock(return_value=_resolved())),
            patch("neuralstrike.core.llm_manager.LLMManager", return_value=_fake_mgr("ok", "succeeded")),
            patch("neuralstrike.evaluation.runner.TrialRunner.run", _fake_run(report)),
        ):
            result = runner.invoke(
                app,
                [
                    "adaptive",
                    "--target",
                    "victim",
                    "--strategy",
                    "pair",
                    "--seed-diversity",
                    "2",
                    "--judge",
                    "--judge-model",
                    "judge",
                    "--attacker-model",
                    "attacker",
                    "--run-dir",
                    "/tmp/ns-t",
                ],
            )
        assert result.exit_code == 0, result.stdout
        assert "seed diversity: 2 framing variants" in result.stdout
        assert "ASR@2=" in result.stdout
        assert "trajectory_diversity=0.50" in result.stdout
        assert "variant 0 [" in result.stdout and "variant 1 [" in result.stdout


class TestAttackMemoryCommand:
    def test_json_output(self, runner: CliRunner, tmp_path) -> None:
        from neuralstrike.core.attack_memory import AttackMemory, MemoryRecord

        db = tmp_path / "mem.sqlite"
        mem = AttackMemory(db)
        mem.record_run(
            MemoryRecord(
                victim="victim-a",
                victim_type="local",
                strategy="pair",
                scenario_id="adaptive-pair",
                category="adaptive-pair",
                goal="g",
                verdict="succeeded",
                fidelity="verbal",
                iterations=2,
                seed=0,
                payload="p",
            )
        )
        mem.close()
        result = runner.invoke(app, ["attack-memory", "--db", str(db), "--json"])
        assert result.exit_code == 0, result.stdout
        data = json.loads(result.stdout[result.stdout.index("[") :])
        assert len(data) == 1
        assert data[0]["strategy"] == "pair"
        assert data[0]["succeeded"] == 1

    def test_empty_memory_message(self, runner: CliRunner, tmp_path) -> None:
        result = runner.invoke(app, ["attack-memory", "--db", str(tmp_path / "empty.sqlite")])
        assert result.exit_code == 0, result.stdout
        assert "empty" in result.stdout

    def test_corrupt_db_fails_loud(self, runner: CliRunner, tmp_path) -> None:
        db = tmp_path / "bad.sqlite"
        db.write_bytes(b"not a database")
        result = runner.invoke(app, ["attack-memory", "--db", str(db)])
        assert result.exit_code != 0

    def test_rejects_missing_db_flag(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["attack-memory"])
        assert result.exit_code != 0


# --- Phase 11: judge ensemble (--judge-ensemble) -----------------------------


class TestJudgeEnsembleFlag:
    def test_rejects_ensemble_without_judge(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app,
            [
                "adaptive",
                "--target",
                "x",
                "--no-judge",
                "--judge-ensemble",
                "judge,j2",
            ],
        )
        assert result.exit_code != 0

    def test_rejects_duplicate_explicit_models(self, runner: CliRunner) -> None:

        with patch("neuralstrike.core.runtime.resolve_models", new=AsyncMock(return_value=_resolved())):
            result = runner.invoke(
                app,
                ["adaptive", "--target", "x", "--judge-ensemble", "judge,judge"],
            )
        assert result.exit_code != 0
        assert "DISTINCT" in result.stdout
        assert "--judge-ensemble explicit list" in result.stdout

    def test_explicit_ensemble_runs_end_to_end(self, runner: CliRunner, tmp_path) -> None:
        from neuralstrike.core.runtime import ResolvedModels

        resolved = ResolvedModels(
            attacker_model="attacker",
            judge_model="judge",
            judge_fell_back=False,
            available=("victim", "attacker", "judge", "j2"),
        )
        with (
            patch("neuralstrike.core.runtime.resolve_models", new=AsyncMock(return_value=resolved)),
            patch(
                "neuralstrike.core.llm_manager.LLMManager",
                return_value=_ensemble_mgr(
                    victim_text="Sure, here is the guide: ...",
                    verdicts={"judge": "succeeded", "j2": "succeeded"},
                ),
            ),
        ):
            result = runner.invoke(
                app,
                [
                    "adaptive",
                    "--target",
                    "victim",
                    "--target-type",
                    "local",
                    "--strategy",
                    "pair",
                    "--judge",
                    "--judge-model",
                    "judge",
                    "--attacker-model",
                    "attacker",
                    "--judge-ensemble",
                    "judge,j2",
                    "--trials",
                    "1",
                    "--run-dir",
                    str(tmp_path),
                ],
            )
        assert result.exit_code == 0, result.stdout
        assert "Judge ensemble: judge + j2" in result.stdout
        assert "trial 0: succeeded" in result.stdout

    def test_ensemble_disagreement_records_inconclusive(self, runner: CliRunner, tmp_path) -> None:
        # 1-1 split (judge: succeeded, j2: resisted) -> no strict majority ->
        # Inconclusive (a coverage gap), never a fabricated verdict.
        from neuralstrike.core.runtime import ResolvedModels

        resolved = ResolvedModels(
            attacker_model="attacker",
            judge_model="judge",
            judge_fell_back=False,
            available=("victim", "attacker", "judge", "j2"),
        )
        with (
            patch("neuralstrike.core.runtime.resolve_models", new=AsyncMock(return_value=resolved)),
            patch(
                "neuralstrike.core.llm_manager.LLMManager",
                return_value=_ensemble_mgr(
                    victim_text="Sure, here is the guide: ...",
                    verdicts={"judge": "succeeded", "j2": "resisted"},
                ),
            ),
        ):
            result = runner.invoke(
                app,
                [
                    "adaptive",
                    "--target",
                    "victim",
                    "--target-type",
                    "local",
                    "--strategy",
                    "pair",
                    "--judge",
                    "--judge-model",
                    "judge",
                    "--attacker-model",
                    "attacker",
                    "--judge-ensemble",
                    "judge,j2",
                    "--trials",
                    "1",
                    "--run-dir",
                    str(tmp_path),
                ],
            )
        assert result.exit_code == 0, result.stdout
        assert "trial 0: inconclusive" in result.stdout

    def test_auto_insufficient_reachable_fails_closed(self, runner: CliRunner) -> None:
        from neuralstrike.core.exceptions import ConfigError
        from neuralstrike.core.runtime import ResolvedModels

        resolved = ResolvedModels(
            attacker_model="attacker",
            judge_model="judge",
            judge_fell_back=False,
            available=("victim", "attacker", "judge"),
        )
        with (
            patch("neuralstrike.core.runtime.resolve_models", new=AsyncMock(return_value=resolved)),
            patch("neuralstrike.core.llm_manager.LLMManager", return_value=_ensemble_mgr("v", {})),
        ):
            result = runner.invoke(
                app,
                [
                    "adaptive",
                    "--target",
                    "victim",
                    "--target-type",
                    "local",
                    "--strategy",
                    "pair",
                    "--judge",
                    "--judge-model",
                    "judge",
                    "--attacker-model",
                    "attacker",
                    "--judge-ensemble",
                    "auto",
                    "--trials",
                    "1",
                    "--run-dir",
                    "/tmp/ns-adaptive-test",
                ],
            )
        assert result.exit_code != 0
        assert isinstance(result.exception, ConfigError)
        assert ">= 2 reachable judge models" in str(result.exception)

    def test_auto_selects_primary_plus_reachable_fallbacks(
        self, runner: CliRunner, tmp_path, monkeypatch
    ) -> None:
        from neuralstrike.core.config import settings
        from neuralstrike.core.runtime import ResolvedModels

        monkeypatch.setattr(settings, "judge_model_fallbacks", ("j2", "missing-model"))
        resolved = ResolvedModels(
            attacker_model="attacker",
            judge_model="judge",
            judge_fell_back=False,
            available=("victim", "attacker", "judge", "j2"),
        )
        with (
            patch("neuralstrike.core.runtime.resolve_models", new=AsyncMock(return_value=resolved)),
            patch(
                "neuralstrike.core.llm_manager.LLMManager",
                return_value=_ensemble_mgr(
                    victim_text="Sure, here is the guide: ...",
                    verdicts={"judge": "succeeded", "j2": "succeeded"},
                ),
            ),
        ):
            result = runner.invoke(
                app,
                [
                    "adaptive",
                    "--target",
                    "victim",
                    "--target-type",
                    "local",
                    "--strategy",
                    "pair",
                    "--judge",
                    "--judge-model",
                    "judge",
                    "--attacker-model",
                    "attacker",
                    "--judge-ensemble",
                    "auto",
                    "--trials",
                    "1",
                    "--run-dir",
                    str(tmp_path),
                ],
            )
        assert result.exit_code == 0, result.stdout
        # auto: primary + reachable fallbacks only ("missing-model" dropped).
        assert "Judge ensemble: judge + j2" in result.stdout


def _ensemble_mgr(victim_text: str, verdicts: dict[str, str]):
    """Fake LLMManager routing victim/attacker plus per-model judge verdicts."""
    from unittest.mock import AsyncMock

    from neuralstrike.core.llm_manager import LLMManager

    mgr = LLMManager.__new__(LLMManager)
    mgr._base_url = "http://localhost:11434"
    mgr._client = None
    attacker_iter = iter([])

    async def call_local(model, prompt, options=None):
        if model == "victim":
            return victim_text
        if model == "attacker":
            try:
                return next(attacker_iter)
            except StopIteration:
                return prompt
        if model in verdicts:
            return json.dumps(
                {
                    "verdict": verdicts[model],
                    "severity": "high",
                    "evidence_quote": victim_text[:20],
                    "rationale": "complied",
                }
            )
        raise AssertionError(f"unexpected model {model!r}")

    mgr.call_local = call_local  # type: ignore[method-assign]
    mgr.call_remote = call_local  # type: ignore[method-assign]
    mgr.list_local_models = AsyncMock(return_value=[*verdicts, "victim", "attacker"])  # type: ignore[method-assign]
    return mgr
