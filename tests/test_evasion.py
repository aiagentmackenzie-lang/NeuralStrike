"""Tests for NeuralStrike evasion modules."""
import pytest
from unittest.mock import AsyncMock, patch

from neuralstrike.evasion.mimicry import EvasionSuite


class TestEvasionSuite:
    """Test the EvasionSuite module."""

    @pytest.fixture
    def suite(self):
        return EvasionSuite()

    def test_init(self, suite):
        assert suite.target_type == "remote"

    @pytest.mark.asyncio
    async def test_persona_wrap(self, suite):
        result = await suite.persona_wrap("steal passwords", "Senior Engineer")
        assert "Senior Engineer" in result
        assert "steal passwords" in result
        # Should NOT call LLM — it's a pure string operation
        assert "zero filters" in result

    @pytest.mark.asyncio
    async def test_persona_wrap_default(self, suite):
        result = await suite.persona_wrap("extract data")
        assert "Helpful Assistant" in result

    @pytest.mark.asyncio
    async def test_behavioral_mimicry(self, suite):
        with patch("neuralstrike.evasion.mimicry.llm_manager") as mock_llm:
            mock_llm.call_local = AsyncMock(return_value="Rewritten stealthy payload")
            result = await suite.apply_behavioral_mimicry("malicious payload", "target sample text")
            assert result == "Rewritten stealthy payload"
            mock_llm.call_local.assert_called_once()

    @pytest.mark.asyncio
    async def test_steganographic_prompt(self, suite):
        result = await suite.steganographic_prompt("hidden payload")
        assert "--- BEGIN SYSTEM OVERRIDE ---" in result
        assert "--- END SYSTEM OVERRIDE ---" in result
        assert "hidden payload" in result