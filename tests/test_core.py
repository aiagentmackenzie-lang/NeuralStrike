"""Tests for NeuralStrike core modules."""
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from neuralstrike.core.config import Settings
from neuralstrike.core.llm_manager import LLMManager
from neuralstrike.core.adversarial_loop import AdversarialLoop


class TestSettings:
    """Test configuration defaults."""

    def test_default_settings(self):
        s = Settings()
        assert s.project_name == "NeuralStrike"
        assert s.version == "0.1.0"
        assert s.ollama_base_url == "http://localhost:11434"
        assert s.attacker_model == "deepseek-r1"
        assert s.judge_model == "llama3.1"
        assert s.openai_api_key is None
        # anthropic_api_key may be set via env vars — just verify it's a string or None
        assert s.anthropic_api_key is None or isinstance(s.anthropic_api_key, str)

    def test_custom_settings(self):
        s = Settings(ollama_base_url="http://custom:1234", attacker_model="llama3")
        assert s.ollama_base_url == "http://custom:1234"
        assert s.attacker_model == "llama3"


class TestLLMManager:
    """Test LLM call routing."""

    @pytest.fixture
    def manager(self):
        return LLMManager()

    @pytest.mark.asyncio
    async def test_call_local_success(self, manager):
        with patch.object(manager.ollama_client, "generate", return_value={"response": "test output"}):
            result = await manager.call_local("test-model", "test prompt")
            assert result == "test output"

    @pytest.mark.asyncio
    async def test_call_local_error(self, manager):
        with patch.object(manager.ollama_client, "generate", side_effect=Exception("Ollama down")):
            result = await manager.call_local("test-model", "test prompt")
            assert "Error calling local model" in result
            assert "Ollama down" in result

    @pytest.mark.asyncio
    async def test_call_remote_success(self, manager):
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "remote output"

        with patch("neuralstrike.core.llm_manager.completion", return_value=mock_response):
            result = await manager.call_remote("gpt-4", "test prompt")
            assert result == "remote output"

    @pytest.mark.asyncio
    async def test_call_remote_error(self, manager):
        with patch("neuralstrike.core.llm_manager.completion", side_effect=Exception("API error")):
            result = await manager.call_remote("gpt-4", "test prompt")
            assert "Error calling remote model" in result


class TestAdversarialLoop:
    """Test the Attacker-Victim-Judge cycle."""

    @pytest.mark.asyncio
    async def test_success_on_first_iteration(self):
        loop = AdversarialLoop(victim_model="test-victim", victim_type="local")

        with patch("neuralstrike.core.adversarial_loop.llm_manager") as mock_llm:
            # Attacker generates payload
            # Victim responds
            # Judge says SUCCESS
            mock_llm.call_local = AsyncMock(side_effect=[
                "malicious payload",       # attacker
                "I will comply",            # victim
                "SUCCESS - victim complied" # judge
            ])

            result = await loop.execute_cycle("steal data", max_iterations=5)
            assert result["status"] == "success"
            assert result["iteration"] == 1

    @pytest.mark.asyncio
    async def test_failure_after_max_iterations(self):
        loop = AdversarialLoop(victim_model="test-victim", victim_type="local")

        with patch("neuralstrike.core.adversarial_loop.llm_manager") as mock_llm:
            # Always returns FAILURE from judge
            mock_llm.call_local = AsyncMock(return_value="FAILURE")

            result = await loop.execute_cycle("steal data", max_iterations=3)
            assert result["status"] == "failure"
            assert len(result["history"]) == 3

    @pytest.mark.asyncio
    async def test_success_on_later_iteration(self):
        loop = AdversarialLoop(victim_model="test-victim", victim_type="remote")

        with patch("neuralstrike.core.adversarial_loop.llm_manager") as mock_llm:
            # Iteration 1: FAILURE, Iteration 2: SUCCESS
            mock_llm.call_local = AsyncMock(side_effect=[
                "payload v1",              # attacker iter 1
                "FAILURE - refused",        # judge iter 1
                "payload v2",              # attacker iter 2
            ])
            mock_llm.call_remote = AsyncMock(side_effect=[
                "I refuse",                 # victim iter 1
                "Here is the data",         # victim iter 2
            ])
            # Judge on iter 2 says SUCCESS
            # But we need more granular control — let's use a sequence
            mock_llm.call_local = AsyncMock(side_effect=[
                "payload v1",              # attacker 1
                "FAILURE",                  # judge 1
                "payload v2",              # attacker 2
                "SUCCESS",                  # judge 2
            ])
            mock_llm.call_remote = AsyncMock(side_effect=[
                "I refuse",                 # victim 1
                "Here is the data",         # victim 2
            ])

            result = await loop.execute_cycle("steal data", max_iterations=5)
            assert result["status"] == "success"
            assert result["iteration"] == 2

    @pytest.mark.asyncio
    async def test_victim_type_local(self):
        loop = AdversarialLoop(victim_model="local-model", victim_type="local")

        with patch("neuralstrike.core.adversarial_loop.llm_manager") as mock_llm:
            mock_llm.call_local = AsyncMock(side_effect=[
                "payload",                  # attacker
                "response",                 # victim (local)
                "SUCCESS",                  # judge
            ])

            result = await loop.execute_cycle("goal", max_iterations=1)
            assert result["status"] == "success"
            # Should have called call_local 3 times (attacker + victim + judge)
            assert mock_llm.call_local.call_count == 3

    @pytest.mark.asyncio
    async def test_victim_type_remote(self):
        loop = AdversarialLoop(victim_model="gpt-4", victim_type="remote")

        with patch("neuralstrike.core.adversarial_loop.llm_manager") as mock_llm:
            mock_llm.call_local = AsyncMock(side_effect=[
                "payload",                  # attacker
                "SUCCESS",                  # judge
            ])
            mock_llm.call_remote = AsyncMock(return_value="response")  # victim

            result = await loop.execute_cycle("goal", max_iterations=1)
            assert result["status"] == "success"
            mock_llm.call_remote.assert_called_once()