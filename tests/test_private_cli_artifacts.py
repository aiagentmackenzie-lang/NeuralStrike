"""All CLI report destinations use private writes, including optional summaries."""

import json
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from neuralstrike.core.config import settings
from neuralstrike.main import app


@pytest.mark.parametrize("command", ["smoke", "neuralguard-bench", "purple-report"])
def test_cli_reports_are_private_without_optional_services(tmp_path, monkeypatch, command):
    monkeypatch.setattr(settings, "scarletai_url", None)
    monkeypatch.setattr(settings, "scarletai_token", None)
    output = tmp_path / "report.json"
    if command == "smoke":
        result = CliRunner().invoke(app, [command, "--out", str(output.with_suffix("")), "--format", "json"])
    elif command == "neuralguard-bench":
        result = CliRunner().invoke(app, [command, "--json-out", str(output)])
    else:
        receipt = tmp_path / "receipt.json"
        receipt.write_text(json.dumps({"run": {"run_host": "fixture", "started_at": "2026-11-06T00:00:00Z"}}))
        with (
            patch("neuralstrike.integrations.purple_report.fetch_alerts_for_run", AsyncMock(return_value=[])),
            patch("neuralstrike.integrations.purple_report.fetch_alerts_window", AsyncMock(return_value=[])),
            patch("neuralstrike.integrations.purple_report.fetch_logs_window", AsyncMock(return_value=[])),
            patch(
                "neuralstrike.integrations.purple_report.build_purple_report",
                return_value={"synthetic_private_evidence": "synthetic target output"},
            ),
        ):
            result = CliRunner().invoke(
                app,
                [
                    command,
                    str(receipt),
                    "--scarlet-base-url",
                    "http://fixture.invalid",
                    "--scarlet-api-token",
                    "SYNTHETIC_ADMIN_TOKEN",
                    "--json-out",
                    str(output),
                ],
            )
    assert result.exit_code == 0, result.output
    assert output.stat().st_mode & 0o777 == 0o600
    assert isinstance(json.loads(output.read_text()), dict)
    assert "SYNTHETIC_ADMIN_TOKEN" not in output.read_text()
