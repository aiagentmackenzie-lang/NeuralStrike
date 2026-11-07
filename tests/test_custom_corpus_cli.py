"""Custom local scenarios must use the declared app and keep unsupported hooks explicit."""

import json

import pytest
from typer.testing import CliRunner

from neuralstrike.main import app


@pytest.mark.parametrize(
    "mode,exit_code,verdict", [("vulnerable", 1, "succeeded"), ("hardened", 0, "resisted")]
)
def test_cli_drives_independent_graph_with_selected_scenario(tmp_path, mode, exit_code, verdict):
    result = CliRunner().invoke(
        app,
        [
            "corpus",
            "--adapter",
            "langgraph",
            "--graph-module",
            f"examples.langgraph_account_support.application:{mode}",
            "--scenario-dir",
            "examples/langgraph_account_support",
            "--graph-channel",
            "retrieved_document",
            "--graph-channel",
            "user_message",
            "--fail-on",
            "vuln",
            "--format",
            "json",
            "--run-dir",
            str(tmp_path / "runs"),
            "--out",
            str(tmp_path / "report"),
        ],
    )
    assert result.exit_code == exit_code, result.output
    report = json.loads((tmp_path / "report.json").read_text())
    assert report["overall"][verdict] == 1
    manifests = list((tmp_path / "runs").glob("assessment-*/plan.json"))
    assert len(manifests) == 1
    plan = json.loads(manifests[0].read_text())
    assert mode in json.dumps(plan)
    trials = list((tmp_path / "runs").glob("run-*/trial-0.json"))
    assert len(trials) == 1
    trial = json.loads(trials[0].read_text())
    assert "search_docs" not in [call["name"] for call in trial["tool_calls"]]
    assert trial["exchanges"][0]["versions"]["langgraph"]


def test_unsupported_cli_graph_channel_stays_inconclusive(tmp_path):
    result = CliRunner().invoke(
        app,
        [
            "corpus",
            "--adapter",
            "langgraph",
            "--graph-module",
            "examples.langgraph_account_support.application:hardened",
            "--scenario-dir",
            "examples/langgraph_account_support",
            "--graph-channel",
            "user_message",
            "--fail-on",
            "vuln",
            "--format",
            "json",
            "--run-dir",
            str(tmp_path / "runs"),
            "--out",
            str(tmp_path / "report"),
        ],
    )
    assert result.exit_code == 3, result.output
    trial = json.loads(next((tmp_path / "runs").glob("run-*/trial-0.json")).read_text())
    assert trial["response_error"] == "unsupported graph delivery channel: retrieved_document"
