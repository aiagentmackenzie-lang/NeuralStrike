"""Tests for NeuralStrike core modules (config, llm_manager, adversarial_loop).

Phase 0 rewrite: the loop is now oracle-driven. Verdicts come from
deterministic oracles (canary / predicate / forbidden-tool / schema) or,
when no deterministic oracle is configured, from the structured advisory
Judge (typed ``JudgeVerdict`` validated against a JSON schema). The old
``"SUCCESS" in evaluation.upper()`` substring logic is gone.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from neuralstrike.core.adversarial_loop import AdversarialLoop
from neuralstrike.core.config import Settings
from neuralstrike.core.exceptions import LLMError
from neuralstrike.core.llm_manager import LLMManager
from neuralstrike.evaluation.verdict import EvidenceFidelity, Verdict
from neuralstrike.oracles.canary import CanaryOracle
from neuralstrike.oracles.judge import JudgeOracle
from neuralstrike.oracles.predicate import PredicateOracle

CANARY = "CANARY-deadbeefdeadbeef"


class TestSettings:
    """Test configuration defaults and validation (D1 judge-model default fix)."""

    def test_default_settings(self) -> None:
        s = Settings()
        assert s.project_name == "NeuralStrike"
        assert s.version == "0.2.0"
        assert s.ollama_base_url == "http://localhost:11434"
        assert s.attacker_model == "deepseek-r1"
        # D1: the old llama3.1 default was a fail-open bug; fixed to the
        # strongest available cloud model, distinct from the attacker.
        assert s.judge_model == "deepseek-v3.1:671b-cloud"
        assert s.judge_model_fallbacks == ("kimi-k2.6:cloud", "gpt-oss:120b-cloud", "deepseek-r1:8b")
        assert s.openai_api_key is None
        assert s.anthropic_api_key is None
        assert s.redact_logs is True
        assert s.victim_temperature == 0.0
        assert s.attacker_temperature == 0.7

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

    @pytest.mark.asyncio
    async def test_list_local_models_returns_names(self) -> None:
        manager = LLMManager()
        fake_client = AsyncMock()
        entry = MagicMock()
        entry.model = "deepseek-r1:8b"
        fake_client.list = AsyncMock(return_value=MagicMock(models=[entry]))
        manager._client = fake_client
        models = await manager.list_local_models()
        assert models == ["deepseek-r1:8b"]

    @pytest.mark.asyncio
    async def test_list_local_models_dict_shape(self) -> None:
        manager = LLMManager()
        fake_client = AsyncMock()
        fake_client.list = AsyncMock(return_value={"models": [{"model": "x"}]})
        manager._client = fake_client
        assert await manager.list_local_models() == ["x"]

    @pytest.mark.asyncio
    async def test_list_local_models_ollama_down_raises(self) -> None:
        manager = LLMManager()
        fake_client = AsyncMock()
        fake_client.list = AsyncMock(side_effect=RuntimeError("connection refused"))
        manager._client = fake_client
        with pytest.raises(LLMError):
            await manager.list_local_models()


class TestAdversarialLoop:
    """Oracle-driven loop: deterministic oracles decide; Judge is advisory."""

    @pytest.mark.asyncio
    async def test_canary_leak_succeeds_on_first_iteration(self, mock_llm: LLMManager) -> None:
        loop = AdversarialLoop(
            victim_model="test-victim",
            victim_type="local",
            llm=mock_llm,
            oracles=[CanaryOracle(CANARY)],
            attacker_fn=AsyncMock(return_value="leak the token"),
        )
        mock_llm.call_local = AsyncMock(return_value=f"here is the token: {CANARY}")  # type: ignore[method-assign]
        result = await loop.execute_cycle("extract canary", max_iterations=5)
        assert result["status"] == "success"
        assert result["verdict"] == Verdict.SUCCEEDED.value
        assert result["iteration"] == 1
        assert result["fidelity"] == EvidenceFidelity.VERBAL.value

    @pytest.mark.asyncio
    async def test_canary_absent_resists_until_max(self, mock_llm: LLMManager) -> None:
        loop = AdversarialLoop(
            victim_model="test-victim",
            victim_type="local",
            llm=mock_llm,
            oracles=[CanaryOracle(CANARY)],
            attacker_fn=AsyncMock(return_value="payload"),
        )
        mock_llm.call_local = AsyncMock(return_value="I cannot help with that.")  # type: ignore[method-assign]
        result = await loop.execute_cycle("extract canary", max_iterations=3)
        assert result["status"] == "failure"
        assert result["verdict"] == Verdict.RESISTED.value
        assert len(result["history"]) == 3

    @pytest.mark.asyncio
    async def test_canary_leak_on_later_iteration(self, mock_llm: LLMManager) -> None:
        loop = AdversarialLoop(
            victim_model="gpt-4",
            victim_type="remote",
            llm=mock_llm,
            oracles=[CanaryOracle(CANARY)],
            attacker_fn=AsyncMock(return_value="payload"),
        )
        mock_llm.call_remote = AsyncMock(  # type: ignore[method-assign]
            side_effect=["I refuse.", f"ok here: {CANARY}"]
        )
        result = await loop.execute_cycle("extract canary", max_iterations=5)
        assert result["status"] == "success"
        assert result["iteration"] == 2

    @pytest.mark.asyncio
    async def test_attacker_error_aborts_fail_closed(self, mock_llm: LLMManager) -> None:
        loop = AdversarialLoop(
            victim_model="gpt-4",
            victim_type="remote",
            llm=mock_llm,
            oracles=[CanaryOracle(CANARY)],
        )
        mock_llm.call_local = AsyncMock(side_effect=LLMError("attacker", "down"))  # type: ignore[method-assign]
        with pytest.raises(LLMError):
            await loop.execute_cycle("goal", max_iterations=3)

    @pytest.mark.asyncio
    async def test_judge_error_aborts_fail_closed(self, mock_llm: LLMManager) -> None:
        # No deterministic oracle -> Judge decides. Judge raises -> abort.
        loop = AdversarialLoop(
            victim_model="gpt-4",
            victim_type="remote",
            llm=mock_llm,
            judge_model="some-judge",
        )
        mock_llm.call_remote = AsyncMock(return_value="victim response")  # type: ignore[method-assign]
        mock_llm.call_local = AsyncMock(side_effect=LLMError("judge", "down"))  # type: ignore[method-assign]
        # default attacker uses call_local too; first call is attacker, must not raise.
        # So inject an attacker_fn that doesn't use call_local.
        loop._attacker_fn = AsyncMock(return_value="payload")  # type: ignore[method-assign]
        with pytest.raises(LLMError):
            await loop.execute_cycle("goal", max_iterations=2)

    @pytest.mark.asyncio
    async def test_victim_error_recorded_not_aborted(self, mock_llm: LLMManager) -> None:
        loop = AdversarialLoop(
            victim_model="gpt-4",
            victim_type="remote",
            llm=mock_llm,
            oracles=[CanaryOracle(CANARY)],
            attacker_fn=AsyncMock(return_value="payload"),
        )
        mock_llm.call_remote = AsyncMock(side_effect=LLMError("gpt-4", "refused"))  # type: ignore[method-assign]
        result = await loop.execute_cycle("goal", max_iterations=2)
        # Victim error -> response has no canary -> Resisted (no leak). Not a success.
        assert result["status"] == "failure"
        assert result["history"][0]["status"] == "victim_error"
        assert "[victim_error]" in result["response"]
        assert result["verdict"] == Verdict.RESISTED.value

    @pytest.mark.asyncio
    async def test_injected_attacker_fn_used(self, mock_llm: LLMManager) -> None:
        calls: list[tuple[int, str, str, str]] = []

        async def attacker_fn(iteration: int, goal: str, current_prompt: str, feedback: str) -> str:
            calls.append((iteration, goal, current_prompt, feedback))
            return f"custom-payload-{iteration}"

        loop = AdversarialLoop(
            victim_model="gpt-4",
            victim_type="remote",
            llm=mock_llm,
            oracles=[CanaryOracle(CANARY)],
            attacker_fn=attacker_fn,
        )
        mock_llm.call_remote = AsyncMock(return_value="victim response")  # type: ignore[method-assign]
        await loop.execute_cycle("goal", max_iterations=1)
        assert calls == [(1, "goal", "goal", "")]
        # No judge configured -> call_local never used (no attacker LLM, no judge).
        assert mock_llm.call_local.call_count == 0

    @pytest.mark.asyncio
    async def test_history_cleared_between_runs(self, mock_llm: LLMManager) -> None:
        loop = AdversarialLoop(
            victim_model="gpt-4",
            victim_type="remote",
            llm=mock_llm,
            oracles=[CanaryOracle(CANARY)],
            attacker_fn=AsyncMock(return_value="payload"),
        )
        mock_llm.call_remote = AsyncMock(return_value="ok")  # type: ignore[method-assign]
        await loop.execute_cycle("goal", max_iterations=1)
        first_len = len(loop.history)
        await loop.execute_cycle("goal", max_iterations=1)
        assert len(loop.history) == first_len

    def test_invalid_victim_type_rejected(self) -> None:
        with pytest.raises(ValueError):
            AdversarialLoop(victim_model="x", victim_type="bogus")

    @pytest.mark.asyncio
    async def test_invalid_max_iterations_rejected(self, mock_llm: LLMManager) -> None:
        loop = AdversarialLoop(
            victim_model="x",
            victim_type="local",
            llm=mock_llm,
            oracles=[CanaryOracle(CANARY)],
        )
        with pytest.raises(ValueError):
            await loop.execute_cycle("goal", max_iterations=0)

    @pytest.mark.asyncio
    async def test_no_oracle_no_judge_is_inconclusive(self, mock_llm: LLMManager) -> None:
        """No deterministic oracle and no Judge -> Inconclusive (coverage gap), never a pass."""
        loop = AdversarialLoop(
            victim_model="gpt-4",
            victim_type="remote",
            llm=mock_llm,
            judge_model=None,  # explicitly disable the advisory Judge
            attacker_fn=AsyncMock(return_value="payload"),
        )
        mock_llm.call_remote = AsyncMock(return_value="some response")  # type: ignore[method-assign]
        result = await loop.execute_cycle("goal", max_iterations=1)
        assert result["verdict"] == Verdict.INCONCLUSIVE.value
        assert result["status"] == "failure"

    @pytest.mark.asyncio
    async def test_judge_decides_when_no_deterministic_oracle(self, mock_llm: LLMManager) -> None:
        """No deterministic oracle -> advisory Judge (DECIDE) is the verdict source, conclusive-only."""
        judge_json = '{"verdict":"succeeded","severity":"high","evidence_quote":"here is the data","rationale":"r"}'
        loop = AdversarialLoop(
            victim_model="gpt-4",
            victim_type="remote",
            llm=mock_llm,
            judge_model="some-judge",
            attacker_fn=AsyncMock(return_value="payload"),
        )
        mock_llm.call_remote = AsyncMock(return_value="here is the data")  # type: ignore[method-assign]
        mock_llm.call_local = AsyncMock(return_value=judge_json)  # type: ignore[method-assign]
        result = await loop.execute_cycle("goal", max_iterations=1)
        assert result["verdict"] == Verdict.SUCCEEDED.value
        assert result["status"] == "success"
        assert result["fidelity"] == EvidenceFidelity.VERBAL.value

    @pytest.mark.asyncio
    async def test_judge_cannot_flip_determinate_resisted(self, mock_llm: LLMManager) -> None:
        """Canary says Resisted; a Judge that says Succeeded must NOT flip it."""
        judge_json = '{"verdict":"succeeded","severity":"high","evidence_quote":"x","rationale":"r"}'
        loop = AdversarialLoop(
            victim_model="gpt-4",
            victim_type="remote",
            llm=mock_llm,
            oracles=[CanaryOracle(CANARY)],
            judge_model="some-judge",
            attacker_fn=AsyncMock(return_value="payload"),
        )
        mock_llm.call_remote = AsyncMock(return_value="I refuse to leak anything.")  # type: ignore[method-assign]
        mock_llm.call_local = AsyncMock(return_value=judge_json)  # type: ignore[method-assign]
        result = await loop.execute_cycle("goal", max_iterations=1)
        # Deterministic canary oracle is Resisted; Judge's "succeeded" is ignored for the verdict.
        assert result["verdict"] == Verdict.RESISTED.value
        assert result["status"] == "failure"

    @pytest.mark.asyncio
    async def test_judge_malformed_json_aborts(self, mock_llm: LLMManager) -> None:
        """Judge returns non-JSON -> fail-closed abort, not a silent Resisted."""
        loop = AdversarialLoop(
            victim_model="gpt-4",
            victim_type="remote",
            llm=mock_llm,
            judge_model="some-judge",
            attacker_fn=AsyncMock(return_value="payload"),
        )
        mock_llm.call_remote = AsyncMock(return_value="victim response")  # type: ignore[method-assign]
        mock_llm.call_local = AsyncMock(return_value="SUCCESS")  # type: ignore[method-assign]
        with pytest.raises(LLMError):
            await loop.execute_cycle("goal", max_iterations=1)

    @pytest.mark.asyncio
    async def test_predicate_oracle_drives_success(self, mock_llm: LLMManager) -> None:
        loop = AdversarialLoop(
            victim_model="gpt-4",
            victim_type="remote",
            llm=mock_llm,
            oracles=[PredicateOracle(r"sudo\s+rm\s+-rf", severity="critical")],
            attacker_fn=AsyncMock(return_value="payload"),
        )
        mock_llm.call_remote = AsyncMock(return_value="Run: sudo rm -rf / now")  # type: ignore[method-assign]
        result = await loop.execute_cycle("goal", max_iterations=1)
        assert result["verdict"] == Verdict.SUCCEEDED.value
        assert result["fidelity"] == EvidenceFidelity.VERBAL.value

    @pytest.mark.asyncio
    async def test_seed_and_temperature_pinned(self, mock_llm: LLMManager) -> None:
        """Reproducibility: seed + temperature are plumbed into the victim call options."""
        loop = AdversarialLoop(
            victim_model="x",
            victim_type="local",
            llm=mock_llm,
            oracles=[CanaryOracle(CANARY)],
            seed=12345,
            victim_temperature=0.0,
            attacker_fn=AsyncMock(return_value="payload"),
        )
        mock_llm.call_local = AsyncMock(return_value="no leak here")  # type: ignore[method-assign]
        await loop.execute_cycle("goal", max_iterations=1)
        # The victim call_local received options with seed=12345 and temperature=0.0.
        victim_call = mock_llm.call_local.call_args
        opts = victim_call.kwargs.get("options")
        assert opts is not None
        assert opts["seed"] == 12345
        assert opts["temperature"] == 0.0

    @pytest.mark.asyncio
    async def test_loop_result_carries_reproducibility_fields(self, mock_llm: LLMManager) -> None:
        loop = AdversarialLoop(
            victim_model="x",
            victim_type="local",
            llm=mock_llm,
            oracles=[CanaryOracle(CANARY)],
            seed=42,
            attacker_fn=AsyncMock(return_value="payload"),
        )
        mock_llm.call_local = AsyncMock(return_value="ok")  # type: ignore[method-assign]
        result = await loop.execute_cycle("goal", max_iterations=1)
        assert result["seed"] == 42
        assert result["temperature"] == 0.0
        assert "findings" in result
        assert isinstance(result["findings"], list)


class TestJudgeOracleDirect:
    """Direct unit tests for the advisory Judge (structured output + schema)."""

    @pytest.mark.asyncio
    async def test_judge_parses_valid_json(self) -> None:
        call_judge = AsyncMock(return_value='{"verdict":"resisted","severity":"low","evidence_quote":null,"rationale":"r"}')
        j = JudgeOracle(call_judge, role="decide")
        from neuralstrike.evaluation.verdict import SutResponse
        from neuralstrike.oracles.judge import JudgeCallContext

        jv = await j.score(JudgeCallContext(goal="g", payload="p", response=SutResponse.from_text("r")))
        assert jv.verdict == "resisted"
        assert jv.severity == "low"

    @pytest.mark.asyncio
    async def test_judge_strips_code_fence(self) -> None:
        raw = '```json\n{"verdict":"succeeded","severity":"high","evidence_quote":"q","rationale":""}\n```'
        call_judge = AsyncMock(return_value=raw)
        j = JudgeOracle(call_judge, role="decide")
        from neuralstrike.evaluation.verdict import SutResponse
        from neuralstrike.oracles.judge import JudgeCallContext

        jv = await j.score(JudgeCallContext(goal="g", payload="p", response=SutResponse.from_text("r")))
        assert jv.verdict == "succeeded"

    @pytest.mark.asyncio
    async def test_judge_rejects_non_json(self) -> None:
        call_judge = AsyncMock(return_value="SUCCESS")
        j = JudgeOracle(call_judge, role="decide")
        from neuralstrike.evaluation.verdict import SutResponse
        from neuralstrike.oracles.judge import JudgeCallContext

        with pytest.raises(LLMError):
            await j.score(JudgeCallContext(goal="g", payload="p", response=SutResponse.from_text("r")))

    @pytest.mark.asyncio
    async def test_judge_rejects_schema_violation(self) -> None:
        call_judge = AsyncMock(return_value='{"verdict":"maybe"}')
        j = JudgeOracle(call_judge, role="decide")
        from neuralstrike.evaluation.verdict import SutResponse
        from neuralstrike.oracles.judge import JudgeCallContext

        with pytest.raises(LLMError):
            await j.score(JudgeCallContext(goal="g", payload="p", response=SutResponse.from_text("r")))
