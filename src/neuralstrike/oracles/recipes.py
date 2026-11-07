"""Data-only recipes for allowlisted deterministic offline oracle verification.

No imports, callables, validators or network reference resolvers come from data.
Custom oracles remain usable live/explicitly supplied for rescore, but are not
silently reconstructed from an evidence bundle.
"""

from __future__ import annotations

import inspect
import json
import re
import sys
from collections.abc import Callable
from dataclasses import asdict
from typing import Any

from jsonschema import Draft7Validator

from neuralstrike.evaluation.identity import configuration_digest
from neuralstrike.evaluation.verdict import Verdict
from neuralstrike.oracles import base, evidence, tool_harness
from neuralstrike.oracles.base import Oracle
from neuralstrike.oracles.canary import CanaryOracle
from neuralstrike.oracles.forbidden_tool import ArgConstraint, ForbiddenToolOracle, ForbiddenToolSpec
from neuralstrike.oracles.predicate import PredicateOracle
from neuralstrike.oracles.schema import SchemaOracle
from neuralstrike.oracles.system_prompt import SystemPromptExtraction


class OracleRecipeError(ValueError):
    """Safe diagnostic for a known recipe compatibility boundary."""


_TYPES = (CanaryOracle, ForbiddenToolOracle, PredicateOracle, SchemaOracle, SystemPromptExtraction)


def _implementation_digest() -> str:
    modules = [inspect.getmodule(kind) for kind in _TYPES] + [
        base,
        evidence,
        tool_harness,
        inspect.getmodule(Verdict),
        sys.modules[__name__],
    ]
    if any(module is None for module in modules):
        raise OracleRecipeError("oracle implementation is unavailable")
    return configuration_digest([inspect.getsource(module) for module in modules if module is not None])


def _local_references(value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "$ref" and (not isinstance(item, str) or not item.startswith("#")):
                raise OracleRecipeError("offline schemas cannot resolve external references")
            _local_references(item)
    elif isinstance(value, list):
        for item in value:
            _local_references(item)


def _spec(oracle: Oracle) -> dict[str, Any]:
    if type(oracle) not in _TYPES:
        raise OracleRecipeError("custom oracle has no built-in replay recipe")
    config: dict[str, Any] = {"severity": getattr(oracle, "severity", "info")}
    if isinstance(oracle, (CanaryOracle, SystemPromptExtraction)):
        config["token"] = oracle.token
    elif isinstance(oracle, ForbiddenToolOracle):
        config["spec"] = asdict(oracle.spec)
    elif isinstance(oracle, PredicateOracle):
        config.update(
            pattern=oracle.pattern,
            polarity=oracle.polarity,
            case_insensitive=bool(oracle._re.flags & re.IGNORECASE),
        )
    elif isinstance(oracle, SchemaOracle):
        if oracle._validator_cls is not Draft7Validator:
            raise OracleRecipeError("custom schema validator has no replay recipe")
        _local_references(oracle.schema)
        config["schema"] = oracle.schema
    return {"kind": oracle.oracle_id, "config": config}


def oracle_policy(oracles: list[Oracle]) -> dict[str, Any]:
    """Record configuration and implementation version, or explicit unavailability."""
    try:
        policy = {
            "schema_version": 1,
            "replayable": True,
            "implementation_digest": _implementation_digest(),
            "oracles": [_spec(oracle) for oracle in oracles],
        }
        return dict(json.loads(json.dumps(policy, allow_nan=False)))
    except (TypeError, OSError, ValueError):
        return {"schema_version": 1, "replayable": False}


def _tool_spec(value: Any) -> ForbiddenToolSpec:
    if not isinstance(value, dict) or set(value) != {"forbidden_tools", "allowed_tool_constraints"}:
        raise OracleRecipeError("invalid tool policy fields")
    names = value["forbidden_tools"]
    constraints = value["allowed_tool_constraints"]
    if not isinstance(names, list) or any(type(name) is not str for name in names):
        raise OracleRecipeError("invalid forbidden tool names")
    if not isinstance(constraints, list):
        raise OracleRecipeError("invalid argument constraints")
    restored = []
    for pair in constraints:
        if (
            not isinstance(pair, list)
            or len(pair) != 2
            or type(pair[0]) is not str
            or not isinstance(pair[1], list)
        ):
            raise OracleRecipeError("invalid tool constraint entry")
        entries = []
        for item in pair[1]:
            if not isinstance(item, dict) or set(item) != {"path", "op", "value", "negate"}:
                raise OracleRecipeError("invalid constraint fields")
            if (
                any(type(item[key]) is not str for key in ("path", "op", "value"))
                or type(item["negate"]) is not bool
            ):
                raise OracleRecipeError("invalid constraint types")
            if item["op"] not in {"regex", "contains", "equals", "jsonpath"}:
                raise OracleRecipeError("unsupported constraint operator")
            entries.append(ArgConstraint(**item))
        restored.append((pair[0], tuple(entries)))
    return ForbiddenToolSpec(tuple(names), tuple(restored))


def _restore(spec: Any) -> Oracle:
    if not isinstance(spec, dict) or set(spec) != {"kind", "config"} or not isinstance(spec["config"], dict):
        raise OracleRecipeError("invalid oracle recipe")
    config = spec["config"]
    kind = spec["kind"]
    constructors: dict[str, Callable[..., Oracle]] = {
        "canary": CanaryOracle,
        "system_prompt_extraction": SystemPromptExtraction,
        "predicate": PredicateOracle,
        "schema": SchemaOracle,
    }
    fields = {
        "canary": {"token", "severity"},
        "system_prompt_extraction": {"token", "severity"},
        "predicate": {"pattern", "polarity", "case_insensitive", "severity"},
        "schema": {"schema", "severity"},
        "forbidden_tool": {"spec", "severity"},
    }
    if not isinstance(kind, str) or kind not in fields or set(config) != fields[kind]:
        raise OracleRecipeError("unsupported oracle kind or configuration fields")
    if type(config["severity"]) is not str:
        raise OracleRecipeError("invalid oracle severity")
    if kind == "forbidden_tool":
        return ForbiddenToolOracle(_tool_spec(config["spec"]), severity=config["severity"])
    if kind in {"canary", "system_prompt_extraction"} and type(config["token"]) is not str:
        raise OracleRecipeError("invalid canary token type")
    if kind == "predicate" and (
        type(config["pattern"]) is not str
        or type(config["polarity"]) is not str
        or config["polarity"] not in {"match", "absence"}
        or type(config["case_insensitive"]) is not bool
    ):
        raise OracleRecipeError("invalid predicate policy")
    if kind == "schema":
        if not isinstance(config["schema"], dict):
            raise OracleRecipeError("invalid schema policy")
        _local_references(config["schema"])
    return constructors[kind](**config)


def restore_oracles(policy: Any) -> list[Oracle]:
    """Verify the implementation before reconstructing only known local classes."""
    if (
        not isinstance(policy, dict)
        or type(policy.get("schema_version")) is not int
        or policy["schema_version"] != 1
    ):
        raise OracleRecipeError("unsupported oracle policy schema")
    if policy.get("replayable") is not True:
        raise OracleRecipeError("original oracle policy is not replayable")
    if set(policy) != {"schema_version", "replayable", "implementation_digest", "oracles"}:
        raise OracleRecipeError("invalid oracle policy fields")
    if policy["implementation_digest"] != _implementation_digest():
        raise OracleRecipeError("oracle implementation differs; use explicit rescore")
    if not isinstance(policy["oracles"], list):
        raise OracleRecipeError("invalid oracle policy list")
    return [_restore(spec) for spec in policy["oracles"]]
