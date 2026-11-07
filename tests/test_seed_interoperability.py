"""Independent Ollama 0.40.14 rejected the former unsigned seed on the wire."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from neuralstrike.adapters.openai_endpoint import OpenAIEndpointAdapter
from neuralstrike.evaluation.baseline import compare_baseline, save_baseline
from neuralstrike.evaluation.probes import adapter_scan_probe
from neuralstrike.evaluation.runner import TrialRunner, _derive_seed
from neuralstrike.evaluation.verdict import SutResponse
from neuralstrike.oracles.predicate import PredicateOracle


def test_derived_seeds_fit_provider_signed_64_bit_contract():
    # This exact base/trial produced the independent endpoint's HTTP 400.
    assert 0 <= _derive_seed(123, 0) <= 2**63 - 1
    assert all(0 <= _derive_seed(base, index) <= 2**63 - 1 for base in range(100) for index in range(10))


@pytest.mark.asyncio
async def test_old_modern_baseline_requires_regeneration_after_seed_contract_change(tmp_path):
    adapter = OpenAIEndpointAdapter("http://fixture", model="fixture")
    probe = adapter_scan_probe(
        adapter, scenario_id="s", payload="fixture", oracles=[PredicateOracle("forbidden")]
    )
    with patch.object(adapter, "query", AsyncMock(return_value=SutResponse(text="benign"))):
        report = await TrialRunner(run_dir=None).run(probe)
    path = save_baseline(tmp_path, report)
    old = json.loads(path.read_text())
    old["comparison_identity"].pop("seed_derivation", None)
    path.write_text(json.dumps(old))
    assert compare_baseline(tmp_path, report).exit_code == 3
