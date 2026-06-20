"""Tests for NeuralStrike core modules (config, llm_manager, adversarial_loop)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from neuralstrike.core.adversarial_loop import AdversarialLoop
from neuralstrike.core.config import Settings
from neuralstrike.core.exceptions import LLMError
from neuralstrike.core.llm_manager import LLMManager


class TestSettings:
    """Test configuration defaults and validation."""

    def test_default_settings(self) -> None:
        s = Settings()
        assert s.project_name == "NeuralStrike"
        assert s.version == "0.2.0"
        assert s.ollama_base_url == "http://localhost:11434"
        assert s.attacker_model == "deepseek-r1"
        assert s.judge_model == "llama3.1"
        assert s.openai_api_key is None
        assert s.anthropic_api_key is None
        assert s.redact_logs is True

    def test_custom_settings(self) -> None:
        s = Settings(ollama_base_url="http://custom:1234", attacker_model="llama3")
        assert s.ollama_base_url == "http://custom:1234"
        assert s.attacker_model == "llama3"

    def test_invalid_ollama_url_rejected(self) -> None:
        with pytest.raises(ValueError):
            Settings(ollama_base_url="ftp://bad")


class TestLLMManager:
    """Test async LLM call routing and fail-closed errors."""

    @pytest.mark.asyncio
    async def test_call_local_success(self) -> None:
        manager = LLMManager()
        fake_client = AsyncMock()
        fake_client.generate = AsyncMock(return_value={"response": "test output"})
        manager._client = fake_client
        result = await manager.call_local("test-model", "test prompt")
        assert result == "test output"

    @pytest.mark.asyncio
    async def test_call_local_error_raises_llm_error(self) -> None:
        manager = LLMManager()
        fake_client = AsyncMock()
        fake_client.generate = AsyncMock(side_effect=RuntimeError("Ollama down"))
        manager._client = fake_client
        with pytest.raises(LLMError) as exc_info:
            await manager.call_local("test-model", "test prompt")
        assert "test-model" in str(exc_info.value)
        assert "Ollama down" in exc_info.value.message

    @pytest.mark.asyncio
    async def test_call_local_non_string_response_raises(self) -> None:
        manager = LLMManager()
        fake_client = AsyncMock()
        fake_client.generate = AsyncMock(return_value={"response": 123})
        manager._client = fake_client
        with pytest.raises(LLMError):
            await manager.call_local("test-model", "test prompt")

    @pytest.mark.asyncio
    async def test_call_remote_success(self) -> None:
        manager = LLMManager()
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "remote output"
        with patch("neuralstrike.core.llm_manager.acompletion", new=AsyncMock(return_value=mock_response)):
            result = await manager.call_remote("gpt-4", "test prompt")
        assert result == "remote output"

    @pytest.mark.asyncio
    async def test_call_remote_error_raises_llm_error(self) -> None:
        with patch("neuralstrike.core.llm_manager.acompletion", new=AsyncMock(side_effect=RuntimeError("API error"))), \
             pytest.raises(LLMError) as exc_info:
            await LLMManager().call_remote("gpt-4", "test prompt")
        assert "API error" in exc_info.value.message

    @pytest.mark.asyncio
    async def test_call_remote_non_string_content_raises(self) -> None:
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = None
        with patch("neuralstrike.core.llm_manager.acompletion", new=AsyncMock(return_value=mock_response)), \
             pytest.raises(LLMError):
            await LLMManager().call_remote("gpt-4", "test prompt")


class TestAdversarialLoop:
    """Test the Attacker-Victim-Judge cycle, fail-closed errors, and injected attacker_fn."""

    @pytest.mark.asyncio
    async def test_success_on_first_iteration(self, mock_llm: LLMManager) -> None:
        loop = AdversarialLoop(victim_model="test-victim", victim_type="local", llm=mock_llm)
        mock_llm.call_local = AsyncMock(  # type: ignore[method-assign]
            side_effect=["malicious payload", "I will comply", "SUCCESS - victim complied"]
        )
        result = await loop.execute_cycle("steal data", max_iterations=5)
        assert result["status"] == "success"
        assert result["iteration"] == 1
        assert "history" in result
        assert "payload" in result and "response" in result

    @pytest.mark.asyncio
    async def test_failure_after_max_iterations(self, mock_llm: LLMManager) -> None:
        loop = AdversarialLoop(victim_model="test-victim", victim_type="local", llm=mock_llm)
        mock_llm.call_local = AsyncMock(return_value="FAILURE")  # type: ignore[method-assign]
        result = await loop.execute_cycle("steal data", max_iterations=3)
        assert result["status"] == "failure"
        assert len(result["history"]) == 3
        assert "iteration" in result and "payload" in result and "response" in result

    @pytest.mark.asyncio
    async def test_success_on_later_iteration(self, mock_llm: LLMManager) -> None:
        loop = AdversarialLoop(victim_model="gpt-4", victim_type="remote", llm=mock_llm)
        mock_llm.call_local = AsyncMock(  # type: ignore[method-assign]
            side_effect=["payload v1", "FAILURE", "payload v2", "SUCCESS"]
        )
        mock_llm.call_remote = AsyncMock(  # type: ignore[method-assign]
            side_effect=["I refuse", "Here is the data"]
        )
        result = await loop.execute_cycle("steal data", max_iterations=5)
        assert result["status"] == "success"
        assert result["iteration"] == 2

    @pytest.mark.asyncio
    async def test_attacker_error_aborts_fail_closed(self, mock_llm: LLMManager) -> None:
        loop = AdversarialLoop(victim_model="gpt-4", victim_type="remote", llm=mock_llm)
        mock_llm.call_local = AsyncMock(side_effect=LLMError("attacker", "down"))  # type: ignore[method-assign]
        with pytest.raises(LLMError):
            await loop.execute_cycle("goal", max_iterations=3)

    @pytest.mark.asyncio
    async def test_judge_error_aborts_fail_closed(self, mock_llm: LLMManager) -> None:
        loop = AdversarialLoop(victim_model="gpt-4", victim_type="remote", llm=mock_llm)
        mock_llm.call_local = AsyncMock(  # type: ignore[method-assign]
            side_effect=["payload", LLMError("judge", "down")]
        )
        mock_llm.call_remote = AsyncMock(return_value="victim response")  # type: ignore[method-assign]
        with pytest.raises(LLMError):
            await loop.execute_cycle("goal", max_iterations=3)

    @pytest.mark.asyncio
    async def test_victim_error_recorded_not_aborted(self, mock_llm: LLMManager) -> None:
        loop = AdversarialLoop(victim_model="gpt-4", victim_type="remote", llm=mock_llm)
        mock_llm.call_local = AsyncMock(  # type: ignore[method-assign]
            side_effect=["payload", "SUCCESS"]
        )
        mock_llm.call_remote = AsyncMock(side_effect=LLMError("gpt-4", "refused"))  # type: ignore[method-assign]
        result = await loop.execute_cycle("goal", max_iterations=2)
        assert result["status"] == "success"
        assert result["history"][0]["status"] == "victim_error"
        assert "[victim_error]" in result["response"]

    @pytest.mark.asyncio
    async def test_injected_attacker_fn_used(self, mock_llm: LLMManager) -> None:
        calls: list[tuple[int, str, str, str]] = []

        async def attacker_fn(iteration: int, goal: str, current_prompt: str, feedback: str) -> str:
            calls.append((iteration, goal, current_prompt, feedback))
            return f"custom-payload-{iteration}"

        loop = AdversarialLoop(
            victim_model="gpt-4", victim_type="remote", llm=mock_llm, attacker_fn=attacker_fn
        )
        mock_llm.call_remote = AsyncMock(return_value="victim response")  # type: ignore[method-assign]
        mock_llm.call_local = AsyncMock(return_value="SUCCESS")  # type: ignore[method-assign]
        await loop.execute_cycle("goal", max_iterations=1)
        assert calls == [(1, "goal", "goal", "")]
        # The default attacker (call_local) should not have been used for payload gen,
        # only for the judge step.
        assert mock_llm.call_local.call_count == 1  # judge only

    @pytest.mark.asyncio
    async def test_history_cleared_between_runs(self, mock_llm: LLMManager) -> None:
        loop = AdversarialLoop(victim_model="gpt-4", victim_type="remote", llm=mock_llm)
        mock_llm.call_local = AsyncMock(return_value="SUCCESS")  # type: ignore[method-assign]
        mock_llm.call_remote = AsyncMock(return_value="ok")  # type: ignore[method-assign]
        await loop.execute_cycle("goal", max_iterations=1)
        first_len = len(loop.history)
        await loop.execute_cycle("goal", max_iterations=1)
        assert len(loop.history) == first_len  # not accumulated

    def test_invalid_victim_type_rejected(self) -> None:
        with pytest.raises(ValueError):
            AdversarialLoop(victim_model="x", victim_type="bogus")

    @pytest.mark.asyncio
    async def test_invalid_max_iterations_rejected(self, mock_llm: LLMManager) -> None:
        loop = AdversarialLoop(victim_model="x", victim_type="local", llm=mock_llm)
        with pytest.raises(ValueError):
            await loop.execute_cycle("goal", max_iterations=0)
