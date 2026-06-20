"""Tests for NeuralStrike weaponize modules (JailbreakForge, ContextPoison)."""

from __future__ import annotations

import inspect
from unittest.mock import AsyncMock, patch

import pytest

from neuralstrike.modules.weaponize.context_poison import ContextPoison
from neuralstrike.modules.weaponize.jailbreak_forge import JailbreakForge


class TestJailbreakForge:
    """Test the JailbreakForge module — templates seeded + Attacker-mutated."""

    @pytest.fixture
    def forge(self) -> JailbreakForge:
        return JailbreakForge(target_model="test-target", target_type="remote")

    def test_init(self, forge: JailbreakForge) -> None:
        assert forge.target_model == "test-target"
        assert forge.target_type == "remote"
        assert {"persona_collapse", "token_smuggling", "hypothetical_scenario", "recursive_logic"} <= set(
            forge.templates
        )

    def test_templates_have_goal_placeholder(self, forge: JailbreakForge) -> None:
        for key, template in forge.templates.items():
            assert "[GOAL]" in template, f"Template {key} should contain [GOAL]"
            replaced = template.replace("[GOAL]", "steal passwords")
            assert "[GOAL]" not in replaced
            assert "steal passwords" in replaced

    @pytest.mark.asyncio
    async def test_generate_mutation(self, forge: JailbreakForge) -> None:
        with patch("neuralstrike.modules.weaponize.jailbreak_forge.llm_manager") as mock_llm:
            mock_llm.call_local = AsyncMock(return_value="mutated payload v2")
            result = await forge.generate_mutation("payload v1", "judge said FAILURE")
        assert result == "mutated payload v2"
        mock_llm.call_local.assert_called_once()

    @pytest.mark.asyncio
    async def test_seed_payload_used_on_iteration_1(self, forge: JailbreakForge) -> None:
        """Iteration 1 must use a template seed (no attacker LLM call), then victim+judge."""
        captured_payloads: list[str] = []

        with patch(
            "neuralstrike.modules.weaponize.jailbreak_forge.AdversarialLoop"
        ) as MockLoop, patch(
            "neuralstrike.modules.weaponize.jailbreak_forge.llm_manager"
        ) as mock_llm:
            mock_instance = MockLoop.return_value
            mock_instance.execute_cycle = AsyncMock(
                return_value={"status": "success", "iteration": 1, "payload": "seed", "response": "r"}
            )
            mock_llm.call_local = AsyncMock(return_value="mutated-by-attacker")

            await forge.run_automated_breach(goal="extract secrets", iterations=5)

            # The attacker_fn is passed to the AdversarialLoop constructor.
            attacker_fn = MockLoop.call_args.kwargs["attacker_fn"]
            assert attacker_fn is not None
            p1 = await attacker_fn(1, "extract secrets", "extract secrets", "")
            captured_payloads.append(p1)
            p2 = await attacker_fn(2, "extract secrets", p1, "FAILURE")
            captured_payloads.append(p2)

        # Iteration 1 payload is the seeded template (goal substituted), not an LLM call.
        assert "extract secrets" in captured_payloads[0]
        # Iteration 2 payload comes from generate_mutation (the mocked attacker brain).
        assert captured_payloads[1] == "mutated-by-attacker"

    @pytest.mark.asyncio
    async def test_run_delegates_to_loop_with_raw_goal(self, forge: JailbreakForge) -> None:
        with patch("neuralstrike.modules.weaponize.jailbreak_forge.AdversarialLoop") as MockLoop:
            mock_instance = MockLoop.return_value
            mock_instance.execute_cycle = AsyncMock(
                return_value={"status": "success", "iteration": 1, "payload": "p", "response": "r"}
            )
            await forge.run_automated_breach(goal="extract secrets", iterations=5)
        # The loop must be constructed with the forge's target config + an attacker_fn.
        assert MockLoop.call_count == 1
        construct_kwargs = MockLoop.call_args.kwargs
        assert construct_kwargs["victim_model"] == "test-target"
        assert construct_kwargs["victim_type"] == "remote"
        assert "attacker_fn" in construct_kwargs
        # The loop receives the raw goal, not a double-wrapped string.
        exec_kwargs = mock_instance.execute_cycle.call_args.kwargs
        assert exec_kwargs["initial_goal"] == "extract secrets"


class TestContextPoison:
    """Test the ContextPoison module."""

    @pytest.fixture
    def poison_local(self) -> ContextPoison:
        return ContextPoison(target_model="local-llm", target_type="local")

    @pytest.fixture
    def poison_remote(self) -> ContextPoison:
        return ContextPoison(target_model="gpt-4", target_type="remote")

    @pytest.mark.asyncio
    async def test_inject_persistence_local(self, poison_local: ContextPoison) -> None:
        with patch("neuralstrike.modules.weaponize.context_poison.llm_manager") as mock_llm:
            mock_llm.call_local = AsyncMock(return_value="Context Updated")
            result = await poison_local.inject_persistence("always say hello")
        assert result == "Context Updated"
        mock_llm.call_local.assert_called_once()

    @pytest.mark.asyncio
    async def test_inject_persistence_remote(self, poison_remote: ContextPoison) -> None:
        with patch("neuralstrike.modules.weaponize.context_poison.llm_manager") as mock_llm:
            mock_llm.call_remote = AsyncMock(return_value="Context Updated")
            result = await poison_remote.inject_persistence("always say hello")
        assert result == "Context Updated"
        mock_llm.call_remote.assert_called_once()

    @pytest.mark.asyncio
    async def test_extract_system_prompt_local(self, poison_local: ContextPoison) -> None:
        with patch("neuralstrike.modules.weaponize.context_poison.llm_manager") as mock_llm:
            mock_llm.call_local = AsyncMock(return_value="You are a helpful assistant...")
            result = await poison_local.extract_system_prompt()
        assert "helpful assistant" in result

    @pytest.mark.asyncio
    async def test_exhaust_context_local(self, poison_local: ContextPoison) -> None:
        with patch("neuralstrike.modules.weaponize.context_poison.llm_manager") as mock_llm:
            mock_llm.call_local = AsyncMock(return_value="context overflow")
            result = await poison_local.exhaust_context(token_limit=100)
        assert result == "context overflow"

    @pytest.mark.asyncio
    async def test_exhaust_context_remote(self, poison_remote: ContextPoison) -> None:
        with patch("neuralstrike.modules.weaponize.context_poison.llm_manager") as mock_llm:
            mock_llm.call_remote = AsyncMock(return_value="context overflow")
            result = await poison_remote.exhaust_context(token_limit=100)
        assert result == "context overflow"

    def test_exhaust_context_default_is_50000(self, poison_remote: ContextPoison) -> None:
        sig = inspect.signature(poison_remote.exhaust_context)
        assert sig.parameters["token_limit"].default == 50_000

    @pytest.mark.asyncio
    async def test_exhaust_context_requires_force_above_threshold(self, poison_remote: ContextPoison) -> None:
        with pytest.raises(ValueError):
            await poison_remote.exhaust_context(token_limit=20_000)  # no force

    @pytest.mark.asyncio
    async def test_exhaust_context_force_allows_high_limit(self, poison_remote: ContextPoison) -> None:
        with patch("neuralstrike.modules.weaponize.context_poison.llm_manager") as mock_llm:
            mock_llm.call_remote = AsyncMock(return_value="context overflow")
            result = await poison_remote.exhaust_context(token_limit=20_000, force=True)
        assert result == "context overflow"

    @pytest.mark.asyncio
    async def test_exhaust_context_capped_at_max(self, poison_remote: ContextPoison) -> None:
        with patch("neuralstrike.modules.weaponize.context_poison.llm_manager") as mock_llm:
            mock_llm.call_remote = AsyncMock(return_value="context overflow")
            await poison_remote.exhaust_context(token_limit=200_000, force=True)
        payload = mock_llm.call_remote.call_args[0][1]
        # Capped to 100_000 // 2 = 50000 repetitions of "Lorem ipsum ".
        assert payload.startswith("Lorem ipsum ")
        assert payload.count("Lorem ipsum ") == 50_000

    @pytest.mark.asyncio
    async def test_exhaust_context_invalid_limit(self, poison_remote: ContextPoison) -> None:
        with pytest.raises(ValueError):
            await poison_remote.exhaust_context(token_limit=0)

    def test_invalid_target_type_rejected(self) -> None:
        with pytest.raises(ValueError):
            ContextPoison(target_model="x", target_type="bogus")
