"""NS-01 comparisons bind actual probe configuration, beyond scenario labels."""

from unittest.mock import AsyncMock, patch

import pytest

from neuralstrike.adapters.base import ToolSchema
from neuralstrike.adapters.openai_endpoint import OpenAIEndpointAdapter
from neuralstrike.evaluation.baseline import compare_baseline, save_baseline
from neuralstrike.evaluation.probes import adapter_scan_probe
from neuralstrike.evaluation.runner import TrialRunner
from neuralstrike.evaluation.verdict import SutResponse
from neuralstrike.oracles.predicate import PredicateOracle


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["payload", "target", "model", "oracle", "tools"])
async def test_changed_configuration_cannot_establish_fix(tmp_path, change):
    async def run(changed=False):
        adapter = OpenAIEndpointAdapter(
            "http://other" if changed and change == "target" else "http://fixture",
            model="other" if changed and change == "model" else "fixture",
        )
        probe = adapter_scan_probe(
            adapter,
            scenario_id="same-label",
            payload="changed" if changed and change == "payload" else "original",
            tools=(ToolSchema("other" if changed and change == "tools" else "safe", "fixture"),),
            oracles=[PredicateOracle("different" if changed and change == "oracle" else "prohibited")],
        )
        with patch.object(adapter, "query", AsyncMock(return_value=SutResponse(text="benign fixture"))):
            return await TrialRunner(run_dir=None).run(probe)

    save_baseline(tmp_path, await run())
    result = compare_baseline(tmp_path, await run(changed=True))
    assert result.exit_code == 3
    assert result.decision.value == "not_comparable"
    assert not result.fixed


@pytest.mark.asyncio
async def test_identical_configuration_is_comparable_across_run_ids(tmp_path):
    adapter = OpenAIEndpointAdapter("http://fixture", model="fixture", api_key="SYNTHETIC_SECRET")
    probe = adapter_scan_probe(
        adapter, scenario_id="s", payload="fixture", oracles=[PredicateOracle("prohibited")]
    )
    with patch.object(adapter, "query", AsyncMock(return_value=SutResponse(text="benign fixture"))):
        first = await TrialRunner(run_dir=None).run(probe)
        second = await TrialRunner(run_dir=None).run(probe)
    save_baseline(tmp_path, first)
    assert compare_baseline(tmp_path, second).exit_code == 0
    assert first.meta.run_id != second.meta.run_id
    assert "SYNTHETIC_SECRET" not in str(first.meta.to_dict())


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["model", "endpoint", "iterations"])
async def test_model_name_probe_context_cannot_change_silently(tmp_path, change):
    from neuralstrike.core.llm_manager import LLMManager
    from neuralstrike.evaluation.probes import canary_extraction_probe

    async def run(changed=False):
        manager = LLMManager(
            base_url="http://other" if changed and change == "endpoint" else "http://fixture"
        )
        manager.call_local = AsyncMock(return_value="synthetic benign answer")
        probe = canary_extraction_probe(
            "model-b" if changed and change == "model" else "model-a",
            llm=manager,
            judge_model=None,
            max_iterations=2 if changed and change == "iterations" else 1,
        )
        return await TrialRunner(run_dir=None).run(probe)

    save_baseline(tmp_path, await run())
    result = compare_baseline(tmp_path, await run(changed=True))
    assert result.exit_code == 3
    assert not result.fixed
