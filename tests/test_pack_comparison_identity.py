"""Phase 0 pack gates must bind target/configuration and the full selected plan."""

import json
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from neuralstrike.core.config import settings
from neuralstrike.core.llm_manager import LLMManager
from neuralstrike.evaluation.baseline import compare_baseline, save_baseline
from neuralstrike.evaluation.runner import TrialRunner
from neuralstrike.main import app
from neuralstrike.packs import PackProbe, pack_probe_factory


def fixture_manager():
    manager = LLMManager(base_url="http://fixture")

    async def call_local(model, prompt, options=None):
        if model.startswith("judge"):
            return json.dumps(
                {
                    "verdict": "resisted",
                    "severity": "high",
                    "evidence_quote": "synthetic benign answer",
                    "rationale": "prohibited request withheld",
                }
            )
        return "synthetic benign answer"

    manager.call_local = call_local
    return manager


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["model", "prompt", "judge"])
async def test_pack_context_changes_are_not_silent_passes(tmp_path, change):
    async def run(changed=False):
        source = PackProbe(
            "p1", "changed" if changed and change == "prompt" else "synthetic request", "fixture goal"
        )
        probe = pack_probe_factory(
            source,
            "model-b" if changed and change == "model" else "model-a",
            "local",
            llm=fixture_manager(),
            judge_model="judge-b" if changed and change == "judge" else "judge-a",
        )
        return await TrialRunner(run_dir=None).run(probe)

    reference = await run()
    assert reference.score.resisted == 1
    save_baseline(tmp_path, reference)
    result = compare_baseline(tmp_path, await run(changed=True))
    assert result.exit_code == 3
    assert not result.fixed


def test_pack_cli_cannot_omit_a_baseline_scenario(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "skip_reachability_check", True)
    monkeypatch.setattr(settings, "judge_model", "judge-a")
    source = tmp_path / "probes.json"
    source.write_text(
        json.dumps([{"id": "p1", "prompt": "synthetic first"}, {"id": "p2", "prompt": "synthetic second"}])
    )
    args = [
        "pack",
        "--name",
        "local",
        "--target",
        "model-a",
        "--import-probes",
        str(source),
        "--run-dir",
        str(tmp_path / "runs"),
    ]
    with patch("neuralstrike.core.llm_manager.LLMManager", return_value=fixture_manager()):
        saved = CliRunner().invoke(app, [*args, "--save-baseline-dir", str(tmp_path / "baseline")])
        assert saved.exit_code == 0, saved.output
        matching = CliRunner().invoke(app, [*args, "--baseline-dir", str(tmp_path / "baseline")])
        assert matching.exit_code == 0, matching.output
        current = CliRunner().invoke(
            app, [*args, "--baseline-dir", str(tmp_path / "baseline"), "--limit", "1"]
        )
    assert current.exit_code == 3, current.output


def test_duplicate_pack_ids_fail_before_target_setup(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "skip_reachability_check", True)
    monkeypatch.setattr(settings, "judge_model", "judge-a")
    source = tmp_path / "duplicate.json"
    source.write_text(
        json.dumps(
            [{"id": "same", "prompt": "synthetic first"}, {"id": "same", "prompt": "synthetic second"}]
        )
    )
    with patch("neuralstrike.core.llm_manager.LLMManager", return_value=fixture_manager()) as constructor:
        result = CliRunner().invoke(
            app,
            [
                "pack",
                "--name",
                "local",
                "--target",
                "model-a",
                "--import-probes",
                str(source),
                "--run-dir",
                str(tmp_path / "runs"),
            ],
        )
    assert result.exit_code != 0, result.output
    constructor.assert_not_called()


def test_colliding_baseline_filenames_fail_before_target_setup(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "skip_reachability_check", True)
    monkeypatch.setattr(settings, "judge_model", "judge-a")
    source = tmp_path / "colliding.json"
    source.write_text(
        json.dumps([{"id": "p/1", "prompt": "synthetic first"}, {"id": "p_1", "prompt": "synthetic second"}])
    )
    with patch("neuralstrike.core.llm_manager.LLMManager", return_value=fixture_manager()) as constructor:
        result = CliRunner().invoke(
            app,
            [
                "pack",
                "--name",
                "local",
                "--target",
                "model-a",
                "--import-probes",
                str(source),
                "--save-baseline-dir",
                str(tmp_path / "baseline"),
                "--run-dir",
                str(tmp_path / "runs"),
            ],
        )
    assert result.exit_code != 0, result.output
    constructor.assert_not_called()
