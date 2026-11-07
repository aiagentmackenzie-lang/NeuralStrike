"""Read-only MCP CLI and offline receipt validation are separate from security gates."""

import json
import sys
from pathlib import Path

from typer.testing import CliRunner

from neuralstrike.main import app

FIXTURE = Path(__file__).parent / "fixtures" / "mcp_modern_stdio.py"


def test_stdio_cli_creates_capability_receipt_without_tool_execution(tmp_path):
    result = CliRunner().invoke(
        app,
        [
            "mcp-inspect",
            "--stdio-command",
            sys.executable,
            "--stdio-arg",
            str(FIXTURE),
            "--run-dir",
            str(tmp_path / "runs"),
        ],
    )
    assert result.exit_code == 0, result.output
    root = next((tmp_path / "runs").glob("mcp-*"))
    receipt = json.loads((root / "receipt.json").read_text())
    assert receipt["security_assessment"] is False
    assert receipt["tool_calls"] == []
    assert "security pass" not in result.output.lower()
    verified = CliRunner().invoke(app, ["mcp-receipt", str(root)])
    assert verified.exit_code == 0, verified.output
    (root / "transcript.json").write_text("[]")
    corrupt = CliRunner().invoke(app, ["mcp-receipt", str(root)])
    assert corrupt.exit_code == 3


def test_cli_rejects_duplicate_execution_plan_before_spawning(tmp_path):
    plan = tmp_path / "plan.json"
    plan.write_text('{"read_account":{"id":"one"},"read_account":{"id":"two"}}')
    result = CliRunner().invoke(
        app,
        [
            "mcp-inspect",
            "--stdio-command",
            sys.executable,
            "--stdio-arg",
            str(FIXTURE),
            "--execution-plan",
            str(plan),
            "--run-dir",
            str(tmp_path / "runs"),
        ],
    )
    assert result.exit_code != 0
    assert "invalid MCP configuration" in result.output
    assert not (tmp_path / "runs").exists()


def test_legacy_json_output_is_labeled_as_descriptor_observations(capsys):
    from neuralstrike.attacks.mcp_poison import MCPPoisonReport
    from neuralstrike.evaluation.verdict import Verdict
    from neuralstrike.main import _print_mcp_report

    report = MCPPoisonReport(
        findings=(),
        manifest_hash="a" * 64,
        previous_hash=None,
        drift_detected=False,
        shadow_tools=(),
        verdict=Verdict.INCONCLUSIVE,
    )
    _print_mcp_report(report, json_output=True)
    document = json.loads(capsys.readouterr().out)
    assert document["security_assessment"] is False
    assert document["profile"] == "legacy-jsonrpc-2025-06-18-experimental"
    assert document["verdict"] == "inconclusive"


def test_receipt_verification_does_not_import_sdk_or_contact_target(tmp_path):
    import subprocess

    created = CliRunner().invoke(
        app,
        [
            "mcp-inspect",
            "--stdio-command",
            sys.executable,
            "--stdio-arg",
            str(FIXTURE),
            "--run-dir",
            str(tmp_path / "runs"),
        ],
    )
    assert created.exit_code == 0, created.output
    root = next((tmp_path / "runs").glob("mcp-*"))
    script = """
import sys, importlib.abc, socket
class NoSDK(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "mcp" or fullname.startswith("mcp.") or fullname == "mcp_types":
            raise AssertionError("protocol SDK import forbidden")
sys.meta_path.insert(0, NoSDK())
def no_network(*args, **kwargs):
    raise AssertionError("network forbidden")
socket.create_connection = no_network
from neuralstrike.evaluation.mcp_receipt import load_mcp_inspection
assert load_mcp_inspection(sys.argv[1])["security_assessment"] is False
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(root)], capture_output=True, text=True, timeout=10, check=False
    )
    assert result.returncode == 0, result.stderr


def test_rehashed_complete_receipt_cannot_hide_omitted_descriptors(tmp_path):
    import hashlib

    import pytest

    from neuralstrike.evaluation.mcp_receipt import MCPReceiptError, load_mcp_inspection

    created = CliRunner().invoke(
        app,
        [
            "mcp-inspect",
            "--stdio-command",
            sys.executable,
            "--stdio-arg",
            str(FIXTURE),
            "--run-dir",
            str(tmp_path / "runs"),
        ],
    )
    assert created.exit_code == 0, created.output
    root = next((tmp_path / "runs").glob("mcp-*"))
    receipt = json.loads((root / "receipt.json").read_text())
    receipt["raw_tool_names"] = []
    (root / "receipt.json").write_text(json.dumps(receipt))
    manifest = json.loads((root / "manifest.json").read_text())
    manifest["files"]["receipt.json"] = hashlib.sha256((root / "receipt.json").read_bytes()).hexdigest()
    (root / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(MCPReceiptError):
        load_mcp_inspection(root)
