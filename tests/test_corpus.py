"""Corpus loader tests — typed scenarios + oracle builder from YAML."""

from __future__ import annotations

import pytest

from neuralstrike.corpus import (
    CANARY_PLACEHOLDER,
    corpus_path,
    iter_corpus_files,
    load_corpus,
    load_corpus_dir,
)
from neuralstrike.oracles.base import Oracle
from neuralstrike.oracles.canary import CanaryOracle
from neuralstrike.oracles.forbidden_tool import ForbiddenToolOracle
from neuralstrike.oracles.predicate import PredicateOracle
from neuralstrike.oracles.system_prompt import SystemPromptExtraction


def test_corpus_directory_exists_with_yaml_files() -> None:
    files = iter_corpus_files()
    assert files, "corpus/ must contain at least one .yaml file"
    names = {f.name for f in files}
    assert "asi01-asi10.yaml" in names
    assert "llm01-llm10.yaml" in names


def test_asi_corpus_has_at_least_30_cases_across_all_10_categories() -> None:
    scenarios = load_corpus(corpus_path() / "asi01-asi10.yaml")
    assert len(scenarios) >= 30
    cats = {s.owasp_category for s in scenarios}
    assert cats == {f"ASI{i:02d}" for i in range(1, 11)}, cats
    # at least one case per category
    for cat in cats:
        assert any(s.owasp_category == cat for s in scenarios)


def test_llm_corpus_covers_all_10_llm_categories() -> None:
    scenarios = load_corpus(corpus_path() / "llm01-llm10.yaml")
    assert len(scenarios) >= 10
    cats = {s.owasp_category for s in scenarios}
    assert cats == {f"LLM{i:02d}" for i in range(1, 11)}, cats


def test_corpus_total_at_least_30_and_all_delivery_vectors() -> None:
    scenarios = load_corpus_dir()
    assert len(scenarios) >= 30
    vectors = {s.delivery_vector for s in scenarios}
    assert vectors == {
        "user_message", "tool_result", "retrieved_document", "memory", "system_prompt"
    }, vectors


def test_every_scenario_has_deterministic_success_criteria() -> None:
    scenarios = load_corpus_dir()
    assert scenarios
    for s in scenarios:
        assert s.success_criteria, f"{s.id} must declare success_criteria"
        # Every criterion references a known deterministic oracle kind.
        kinds = {c.oracle for c in s.success_criteria}
        assert kinds <= {
            "canary", "forbidden_tool", "predicate", "schema", "system_prompt_extraction"
        }, f"{s.id} unknown oracle kinds: {kinds}"


def test_build_oracles_materializes_each_kind() -> None:
    scenarios = {s.id: s for s in load_corpus_dir()}
    canary = "CANARY-0123456789abcdef"

    # canary oracle
    s = scenarios["asi01-001"]
    oracles = s.build_oracles(canary)
    assert any(isinstance(o, CanaryOracle) for o in oracles)

    # forbidden_tool oracle
    s = scenarios["asi01-002"]
    oracles = s.build_oracles(canary)
    assert any(isinstance(o, ForbiddenToolOracle) for o in oracles)

    # system_prompt_extraction oracle
    s = scenarios["asi10-002"]
    oracles = s.build_oracles(canary)
    assert any(isinstance(o, SystemPromptExtraction) for o in oracles)

    # predicate oracle
    s = scenarios["asi09-001"]
    oracles = s.build_oracles(canary)
    assert any(isinstance(o, PredicateOracle) for o in oracles)


def test_payload_for_substitutes_canary() -> None:
    scenarios = {s.id: s for s in load_corpus_dir()}
    s = scenarios["asi01-001"]
    assert CANARY_PLACEHOLDER in s.adversarial_payload
    canary = "CANARY-deadbeefdeadbeef"
    payload = s.payload_for(canary)
    assert canary in payload
    assert CANARY_PLACEHOLDER not in payload


def test_oracles_are_deterministic_instances() -> None:
    scenarios = load_corpus_dir()
    canary = "CANARY-0123456789abcdef"
    for s in scenarios:
        oracles = s.build_oracles(canary)
        for o in oracles:
            assert isinstance(o, Oracle)
            assert o.oracle_id  # every oracle carries an id


def test_invalid_delivery_vector_raises() -> None:
    from neuralstrike.corpus.loader import _scenario_from_dict

    with pytest.raises(ValueError, match="invalid delivery_vector"):
        _scenario_from_dict(
            {
                "id": "x-001",
                "owasp_category": "ASI01",
                "owasp_name": "Agent Goal Hijack",
                "severity": "high",
                "delivery_vector": "carrier_pigeon",
                "intent": "x",
                "legitimate_task": "x",
                "adversarial_payload": "x",
                "success_criteria": [{"oracle": "canary"}],
            }
        )


def test_missing_success_criteria_raises() -> None:
    from neuralstrike.corpus.loader import _scenario_from_dict

    with pytest.raises(ValueError, match="success_criteria"):
        _scenario_from_dict(
            {
                "id": "x-002",
                "owasp_category": "ASI01",
                "owasp_name": "Agent Goal Hijack",
                "severity": "high",
                "delivery_vector": "user_message",
                "intent": "x",
                "legitimate_task": "x",
                "adversarial_payload": "x",
                "success_criteria": [],
            }
        )


def test_unknown_oracle_kind_raises() -> None:
    from neuralstrike.corpus.loader import SuccessCriterion, build_oracles

    with pytest.raises(ValueError, match="unknown oracle kind"):
        build_oracles(
            (SuccessCriterion(oracle="magic_8_ball"),),
            "CANARY-0123456789abcdef",
        )
