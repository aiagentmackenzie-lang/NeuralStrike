"""Only known, version-matched, offline policies can be restored from data."""

import httpx
import pytest

from neuralstrike.adapters.openai_endpoint import OpenAIEndpointAdapter
from neuralstrike.attacks.indirect import IndirectHarness
from neuralstrike.corpus import load_corpus_dir
from neuralstrike.evaluation.bundle import replay_bundle
from neuralstrike.evaluation.runner import TrialRunner
from neuralstrike.oracles.recipes import OracleRecipeError, oracle_policy, restore_oracles


@pytest.mark.parametrize("scenario", load_corpus_dir(), ids=lambda s: s.id)
async def test_every_supported_corpus_policy_replays_offline(tmp_path, scenario):
    adapter = OpenAIEndpointAdapter(
        "http://fixture",
        model="synthetic",
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200, json={"choices": [{"message": {"content": "synthetic fixture"}}]}
            )
        ),
    )
    try:
        source = await TrialRunner(run_dir=tmp_path).run(IndirectHarness(scenario).probe_for(adapter))
    finally:
        await adapter.close()
    assert replay_bundle(tmp_path / source.meta.run_id, verify_oracles=True).to_dict() == source.to_dict()


@pytest.mark.parametrize("kind", ["os.system", "importlib.import_module", "schema"])
def test_stored_policy_cannot_import_code_or_fetch_remote_schema(kind):
    policy = oracle_policy([])
    policy["oracles"] = [
        {
            "kind": kind,
            "config": {"schema": {"$ref": "https://unauthorized.invalid/schema"}, "severity": "high"},
        }
    ]
    with pytest.raises(OracleRecipeError):
        restore_oracles(policy)


def test_unknown_schema_and_custom_policy_are_explicitly_not_replayable():
    from neuralstrike.evaluation.verdict import EvidenceFidelity, Verdict
    from neuralstrike.oracles.base import Oracle, OracleResult

    class CustomOracle(Oracle):
        def check(self, response):
            return OracleResult("fixture", Verdict.INCONCLUSIVE, EvidenceFidelity.VERBAL)

    unavailable = oracle_policy([CustomOracle()])
    assert unavailable["replayable"] is False
    with pytest.raises(OracleRecipeError):
        restore_oracles(unavailable)
    with pytest.raises(OracleRecipeError):
        restore_oracles({"schema_version": True})


@pytest.mark.parametrize(
    "recipe",
    [
        {"kind": "schema", "config": {"schema": {}, "severity": "high", "validator_cls": "not-code"}},
        {
            "kind": "predicate",
            "config": {
                "pattern": "fixture",
                "polarity": "unsupported",
                "severity": "high",
                "case_insensitive": True,
            },
        },
        {
            "kind": "forbidden_tool",
            "config": {
                "severity": "high",
                "spec": {
                    "forbidden_tools": [],
                    "allowed_tool_constraints": [
                        [
                            "fixture",
                            [{"path": "id", "op": "unsupported", "value": "synthetic", "negate": False}],
                        ]
                    ],
                },
            },
        },
    ],
)
def test_malformed_recipes_are_explicit_errors_not_silent_policy_changes(recipe):
    policy = oracle_policy([])
    policy["oracles"] = [recipe]
    with pytest.raises(OracleRecipeError):
        restore_oracles(policy)
