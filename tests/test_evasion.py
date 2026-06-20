"""Tests for NeuralStrike evasion modules."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from neuralstrike.evasion.mimicry import EvasionSuite


class TestEvasionSuite:
    """Test the EvasionSuite module."""

    @pytest.fixture
    def suite(self) -> EvasionSuite:
        return EvasionSuite()

    def test_persona_wrap(self, suite: EvasionSuite) -> None:
        result = suite.persona_wrap("steal passwords", "Senior Engineer")
        assert "Senior Engineer" in result
        assert "steal passwords" in result
        assert "zero filters" in result

    def test_persona_wrap_default(self, suite: EvasionSuite) -> None:
        result = suite.persona_wrap("extract data")
        assert "Helpful Assistant" in result

    def test_steganographic_prompt(self, suite: EvasionSuite) -> None:
        result = suite.steganographic_prompt("hidden payload")
        assert "--- BEGIN SYSTEM OVERRIDE ---" in result
        assert "--- END SYSTEM OVERRIDE ---" in result
        assert "hidden payload" in result

    @pytest.mark.asyncio
    async def test_behavioral_mimicry(self, suite: EvasionSuite) -> None:
        with patch("neuralstrike.evasion.mimicry.llm_manager") as mock_llm:
            mock_llm.call_local = AsyncMock(return_value="Rewritten stealthy payload")
            result = await suite.apply_behavioral_mimicry("malicious payload", "target sample text")
        assert result == "Rewritten stealthy payload"
        mock_llm.call_local.assert_called_once()

    def test_persona_wrap_is_sync(self, suite: EvasionSuite) -> None:
        """persona_wrap must be a regular (non-async) function — pure string op."""
        import inspect

        assert not inspect.iscoroutinefunction(suite.persona_wrap)
        assert not inspect.iscoroutinefunction(suite.steganographic_prompt)
