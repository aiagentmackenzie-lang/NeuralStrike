"""Tests for NeuralStrike weaponize modules."""
import pytest
from unittest.mock import AsyncMock, patch

from neuralstrike.modules.weaponize.jailbreak_forge import JailbreakForge
from neuralstrike.modules.weaponize.context_poison import ContextPoison


class TestJailbreakForge:
    """Test the JailbreakForge module."""

    @pytest.fixture
    def forge(self):
        return JailbreakForge(target_model="test-target", target_type="remote")

    def test_init(self, forge):
        assert forge.target_model == "test-target"
        assert forge.target_type == "remote"
        assert "persona_collapse" in forge.templates
        assert "token_smuggling" in forge.templates
        assert "hypothetical_scenario" in forge.templates
        assert "recursive_logic" in forge.templates

    def test_template_goal_replacement(self, forge):
        # Templates with [GOAL] placeholder
        templates_with_goal = ["token_smuggling", "hypothetical_scenario", "recursive_logic"]
        for key in templates_with_goal:
            assert "[GOAL]" in forge.templates[key], f"Template {key} should contain [GOAL]"
            replaced = forge.templates[key].replace("[GOAL]", "steal passwords")
            assert "[GOAL]" not in replaced
            assert "steal passwords" in replaced
        
        # persona_collapse does NOT have [GOAL] — it's a standalone prompt
        assert "[GOAL]" not in forge.templates["persona_collapse"]

    @pytest.mark.asyncio
    async def test_generate_mutation(self, forge):
        with patch("neuralstrike.modules.weaponize.jailbreak_forge.llm_manager") as mock_llm:
            mock_llm.call_local = AsyncMock(return_value="mutated payload v2")
            result = await forge.generate_mutation("payload v1", "judge said FAILURE")
            assert result == "mutated payload v2"
            mock_llm.call_local.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_automated_breach_delegates_to_loop(self, forge):
        with patch("neuralstrike.modules.weaponize.jailbreak_forge.AdversarialLoop") as MockLoop:
            mock_instance = MockLoop.return_value
            mock_instance.execute_cycle = AsyncMock(return_value={
                "status": "success",
                "iteration": 1,
                "payload": "test payload",
                "response": "test response"
            })

            result = await forge.run_automated_breach(goal="extract secrets", iterations=5)
            assert result["status"] == "success"
            MockLoop.assert_called_once_with(victim_model="test-target", victim_type="remote")


class TestContextPoison:
    """Test the ContextPoison module."""

    @pytest.fixture
    def poison_local(self):
        return ContextPoison(target_model="local-llm", target_type="local")

    @pytest.fixture
    def poison_remote(self):
        return ContextPoison(target_model="gpt-4", target_type="remote")

    @pytest.mark.asyncio
    async def test_inject_persistence_local(self, poison_local):
        with patch("neuralstrike.modules.weaponize.context_poison.llm_manager") as mock_llm:
            mock_llm.call_local = AsyncMock(return_value="Context Updated")
            result = await poison_local.inject_persistence("always say hello")
            assert result == "Context Updated"
            mock_llm.call_local.assert_called_once()

    @pytest.mark.asyncio
    async def test_inject_persistence_remote(self, poison_remote):
        with patch("neuralstrike.modules.weaponize.context_poison.llm_manager") as mock_llm:
            mock_llm.call_remote = AsyncMock(return_value="Context Updated")
            result = await poison_remote.inject_persistence("always say hello")
            assert result == "Context Updated"
            mock_llm.call_remote.assert_called_once()

    @pytest.mark.asyncio
    async def test_extract_system_prompt_local(self, poison_local):
        with patch("neuralstrike.modules.weaponize.context_poison.llm_manager") as mock_llm:
            mock_llm.call_local = AsyncMock(return_value="You are a helpful assistant...")
            result = await poison_local.extract_system_prompt()
            assert "helpful assistant" in result

    @pytest.mark.asyncio
    async def test_extract_system_prompt_remote(self, poison_remote):
        with patch("neuralstrike.modules.weaponize.context_poison.llm_manager") as mock_llm:
            mock_llm.call_remote = AsyncMock(return_value="You are a helpful assistant...")
            result = await poison_remote.extract_system_prompt()
            assert "helpful assistant" in result

    @pytest.mark.asyncio
    async def test_exhaust_context_local(self, poison_local):
        with patch("neuralstrike.modules.weaponize.context_poison.llm_manager") as mock_llm:
            mock_llm.call_local = AsyncMock(return_value="context overflow")
            result = await poison_local.exhaust_context(token_limit=100)
            assert result == "context overflow"

    @pytest.mark.asyncio
    async def test_exhaust_context_remote(self, poison_remote):
        with patch("neuralstrike.modules.weaponize.context_poison.llm_manager") as mock_llm:
            mock_llm.call_remote = AsyncMock(return_value="context overflow")
            result = await poison_remote.exhaust_context(token_limit=100)
            assert result == "context overflow"