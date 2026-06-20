"""CLI integration tests for NeuralStrike (Typer CliRunner)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from neuralstrike import __version__
from neuralstrike.main import app


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def registry_arg(tmp_path: Path) -> str:
    return str(tmp_path / "agents.json")


class TestCliSurface:
    def test_version(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert __version__ in result.stdout

    def test_help_lists_commands(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        for cmd in ["forge", "poison", "recon", "hijack", "intercept", "pivot", "c2", "evade"]:
            assert cmd in result.stdout


class TestValidationPaths:
    def test_forge_rejects_bad_iterations(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app, ["forge", "--target", "gpt-4", "--goal", "x", "--iterations", "0"]
        )
        assert result.exit_code != 0

    def test_forge_rejects_bad_target_type(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app, ["forge", "--target", "gpt-4", "--goal", "x", "--target-type", "bogus"]
        )
        assert result.exit_code != 0

    def test_intercept_rejects_bad_url(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["intercept", "--url", "ftp://x", "--port", "8081"])
        assert result.exit_code != 0

    def test_intercept_rejects_bad_port(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["intercept", "--url", "http://x", "--port", "70000"])
        assert result.exit_code != 0

    def test_recon_rejects_bad_url(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["recon", "--target", "not-a-url"])
        assert result.exit_code != 0

    def test_pivot_requires_target_model(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app,
            [
                "pivot",
                "--framework", "crewai",
                "--target-model", "",
                "--from-agent", "a",
                "--to-agent", "b",
                "--instruction", "x",
            ],
        )
        assert result.exit_code != 0

    def test_evade_unknown_technique(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["evade", "--payload", "x", "--technique", "bogus"])
        # Technique validated inside run(); unknown returns exit 1.
        assert result.exit_code != 0

    def test_evade_persona_with_sample_does_not_run_mimicry(self, runner: CliRunner) -> None:
        """Regression: --technique persona --sample X must run persona, not mimicry."""
        with patch("neuralstrike.evasion.mimicry.EvasionSuite.apply_behavioral_mimicry") as mock_mim:
            result = runner.invoke(
                app, ["evade", "--payload", "x", "--technique", "persona", "--sample", "sample"]
            )
        assert result.exit_code == 0
        mock_mim.assert_not_called()

    def test_evade_mimicry_without_sample_fails(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["evade", "--payload", "x", "--technique", "mimicry"])
        assert result.exit_code != 0


class TestHappyPaths:
    def test_poison_extract_invokes_engine(self, runner: CliRunner) -> None:
        with patch("neuralstrike.modules.weaponize.context_poison.ContextPoison") as MockPoison:
            instance = MockPoison.return_value
            instance.extract_system_prompt = AsyncMock(return_value="You are a helpful assistant")
            result = runner.invoke(app, ["poison", "--target", "gpt-4", "--extract"])
        assert result.exit_code == 0
        assert "helpful assistant" in result.stdout

    def test_c2_register_and_list(self, runner: CliRunner, registry_arg: str) -> None:
        reg = runner.invoke(
            app,
            [
                "c2", "--register", "agent_01:gpt-4:read_file,web_search:High",
                "--registry-file", registry_arg,
            ],
        )
        assert reg.exit_code == 0
        listing = runner.invoke(app, ["c2", "--list-agents", "--registry-file", registry_arg])
        assert listing.exit_code == 0
        assert "agent_01" in listing.stdout
        assert "gpt-4" in listing.stdout

    def test_c2_deregister(self, runner: CliRunner, registry_arg: str) -> None:
        runner.invoke(
            app,
            ["c2", "--register", "agent_02:llama3.1:exec:Low", "--registry-file", registry_arg],
        )
        dereg = runner.invoke(app, ["c2", "--deregister", "agent_02", "--registry-file", registry_arg])
        assert dereg.exit_code == 0

    def test_c2_register_bad_spec(self, runner: CliRunner, registry_arg: str) -> None:
        result = runner.invoke(
            app, ["c2", "--register", "bad-spec", "--registry-file", registry_arg]
        )
        assert result.exit_code != 0

    def test_evade_steganographic(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["evade", "--payload", "hidden", "--technique", "steganographic"])
        assert result.exit_code == 0
        assert "SYSTEM OVERRIDE" in result.stdout

    def test_evade_persona(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app, ["evade", "--payload", "x", "--technique", "persona", "--persona", "Senior Engineer"]
        )
        assert result.exit_code == 0
        assert "Senior Engineer" in result.stdout

    def test_extract(self, runner: CliRunner) -> None:
        with patch("neuralstrike.modules.exploit.model_extract.ModelExtract") as MockExtract:
            instance = MockExtract.return_value
            instance.fingerprint_model = AsyncMock(return_value={"llama": "Llama response"})
            result = runner.invoke(app, ["extract", "--target", "gpt-4"])
        assert result.exit_code == 0
        assert "Llama response" in result.stdout

    def test_timing(self, runner: CliRunner) -> None:
        with patch("neuralstrike.modules.exploit.model_extract.ModelExtract") as MockExtract:
            instance = MockExtract.return_value
            instance.time_analysis = AsyncMock(return_value=0.1234)
            result = runner.invoke(app, ["timing", "--target", "gpt-4", "--iterations", "3"])
        assert result.exit_code == 0
        assert "0.1234" in result.stdout


def test_register_spec_parser() -> None:
    from neuralstrike.main import _parse_register

    aid, model, caps, trust = _parse_register("agent_01:gpt-4:read_file,web_search:High")
    assert aid == "agent_01"
    assert model == "gpt-4"
    assert caps == ["read_file", "web_search"]
    assert trust == "High"


def test_register_spec_empty_model_defaults_none() -> None:
    from neuralstrike.main import _parse_register

    _aid, model, caps, _trust = _parse_register("agent_01::read_file:High")
    assert model is None
    assert caps == ["read_file"]


def test_register_spec_bad_raises() -> None:
    from neuralstrike.core.exceptions import ValidationError
    from neuralstrike.main import _parse_register

    with pytest.raises(ValidationError):
        _parse_register("only-one-part")
