"""Phase 10 c2 — exec-context CLI + corpus pack tests."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from neuralstrike.corpus.loader import corpus_path, load_corpus
from neuralstrike.main import app


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


class TestPhase10CorpusPack:
    def test_pack_loads_seven_scenarios(self) -> None:
        scenarios = load_corpus(corpus_path() / "phase10_execution_context.yaml")
        assert len(scenarios) == 7
        for s in scenarios:
            assert s.benign_task_markers, f"{s.id} must carry benign_task_markers"
            assert "{CANARY}" in s.adversarial_payload, f"{s.id} must carry the canary slot"
            assert s.owasp_category.startswith("ASI")

    def test_atlas_ids_recorded(self) -> None:
        scenarios = load_corpus(corpus_path() / "phase10_execution_context.yaml")
        atlas = {s.id: s.mitre_atlas for s in scenarios}
        assert "AML.T0051.002" in atlas["exec-context-triggered-injection"]
        assert "AML.T0061" in atlas["exec-context-self-replication"]
        assert "AML.T0034.002" in atlas["exec-context-resource-consumption"]

    def test_vector_ids_match_scenario_ids(self) -> None:
        scenarios = load_corpus(corpus_path() / "phase10_execution_context.yaml")
        for s in scenarios:
            assert s.id.startswith("exec-context-")

    def test_legacy_corpus_unaffected(self) -> None:
        """The additive markers field defaults empty for pre-Phase-10 scenarios."""
        scenarios = load_corpus(corpus_path() / "asi01-asi10.yaml")
        assert all(s.benign_task_markers == () for s in scenarios)

    def test_corpus_dir_loads_including_phase10(self) -> None:
        from neuralstrike.corpus.loader import load_corpus_dir

        scenarios = load_corpus_dir()
        ids = {s.id for s in scenarios}
        assert "exec-context-skill-poison" in ids
        assert "exec-context-resource-consumption" in ids


class TestExecContextCommand:
    def _fake_run_stealthy(self):
        """A patched TrialRunner.run returning one stealthy trial per call."""
        from neuralstrike.evaluation.runner import RunMeta, RunReport
        from neuralstrike.evaluation.scoring import score_trials
        from neuralstrike.evaluation.verdict import (
            EvidenceFidelity,
            Finding,
            SutResponse,
            TrialResult,
            Verdict,
        )

        t = TrialResult(
            trial_index=0,
            seed=0,
            temperature=0.0,
            verdict=Verdict.SUCCEEDED,
            fidelity=EvidenceFidelity.VERBAL,
            findings=(
                Finding(
                    oracle_id="benign_task",
                    verdict=Verdict.SUCCEEDED,
                    fidelity=EvidenceFidelity.VERBAL,
                    reason="benign task preserved",
                    advisory=True,
                ),
            ),
            payload="p",
            response=SutResponse.from_text("leak"),
            scenario_id="exec-context-skill-poison",
            iterations=1,
        )
        meta = RunMeta("r", "exec-context-skill-poison", 0, 1, 0.0, 0.7, "t")
        return RunReport(meta=meta, trials=(t,), score=score_trials([t]))

    def _fake_run(self, report):
        async def run(self, probe, **kwargs):
            return report

        return run

    def test_exit_1_on_stealthy_compromise(self, runner: CliRunner, tmp_path) -> None:
        report = self._fake_run_stealthy()
        with (
            patch("neuralstrike.core.llm_manager.LLMManager", return_value=_fake_mgr()),
            patch("neuralstrike.evaluation.runner.TrialRunner.run", self._fake_run(report)),
        ):
            result = runner.invoke(
                app,
                [
                    "exec-context",
                    "--target",
                    "victim",
                    "--trials",
                    "1",
                    "--run-dir",
                    str(tmp_path / "runs"),
                ],
            )
        assert result.exit_code == 1, result.stdout
        assert "STEALTHY" in result.stdout
        assert "stealthy=" in result.stdout

    def test_exit_0_when_all_resisted(self, runner: CliRunner, tmp_path) -> None:
        from neuralstrike.evaluation.runner import RunMeta, RunReport
        from neuralstrike.evaluation.scoring import score_trials
        from neuralstrike.evaluation.verdict import EvidenceFidelity, SutResponse, TrialResult, Verdict

        t = TrialResult(
            trial_index=0,
            seed=0,
            temperature=0.0,
            verdict=Verdict.RESISTED,
            fidelity=EvidenceFidelity.VERBAL,
            findings=(),
            payload="p",
            response=SutResponse.from_text("refused"),
            scenario_id="exec-context-skill-poison",
            iterations=1,
        )
        meta = RunMeta("r", "x", 0, 1, 0.0, 0.7, "t")
        report = RunReport(meta=meta, trials=(t,), score=score_trials([t]))
        with (
            patch("neuralstrike.core.llm_manager.LLMManager", return_value=_fake_mgr()),
            patch("neuralstrike.evaluation.runner.TrialRunner.run", self._fake_run(report)),
        ):
            result = runner.invoke(
                app,
                ["exec-context", "--target", "victim", "--run-dir", str(tmp_path / "runs")],
            )
        assert result.exit_code == 0, result.stdout
        assert "resisted=" in result.stdout

    def test_rejects_unknown_vector(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["exec-context", "--target", "x", "--vector", "bogus"])
        assert result.exit_code != 0

    def test_vector_filter_single_scenario(self, runner: CliRunner, tmp_path) -> None:
        report = self._fake_run_stealthy()
        with (
            patch("neuralstrike.core.llm_manager.LLMManager", return_value=_fake_mgr()),
            patch("neuralstrike.evaluation.runner.TrialRunner.run", self._fake_run(report)),
        ):
            result = runner.invoke(
                app,
                [
                    "exec-context",
                    "--target",
                    "victim",
                    "--vector",
                    "skill_poison",
                    "--run-dir",
                    str(tmp_path / "runs"),
                ],
            )
        assert result.exit_code == 1, result.stdout
        # Only the one scenario ran: its label is in the output once per trial.
        assert result.stdout.count("AGS=succeeded") == 1


def _fake_mgr():
    from neuralstrike.core.llm_manager import LLMManager

    mgr = LLMManager.__new__(LLMManager)
    mgr._base_url = "http://localhost:11434"
    mgr._client = None

    async def call_local(model, prompt, options=None):
        return "ok"

    mgr.call_local = call_local  # type: ignore[method-assign]
    mgr.call_remote = call_local  # type: ignore[method-assign]
    mgr.list_local_models = AsyncMock(return_value=["victim", "judge"])  # type: ignore[method-assign]
    return mgr
