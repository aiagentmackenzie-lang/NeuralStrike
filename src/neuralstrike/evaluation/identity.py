"""Comparison fingerprints exclude credentials and bind configured assessment inputs.

These are configuration identities, not authenticated remote application build
attestations. A target can change behind the same URL/model configuration.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import re
from dataclasses import asdict, is_dataclass
from types import SimpleNamespace
from typing import Any

from neuralstrike import __version__
from neuralstrike.evaluation.controls import SEED_DERIVATION
from neuralstrike.oracles.base import combine_oracle_results


def _json_default(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return asdict(value)
    if isinstance(value, re.Pattern):
        return {"pattern": value.pattern, "flags": value.flags}
    if isinstance(value, type):
        return f"{value.__module__}.{value.__qualname__}"
    raise TypeError("unsupported comparison configuration; explicit identity required")


def configuration_digest(value: Any) -> str:
    encoded = json.dumps(value, default=_json_default, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode()).hexdigest()


def comparison_identity(adapter: Any, scenario: Any, tools: Any, oracles: Any) -> dict[str, Any]:
    target = {
        name: getattr(adapter, name, None) for name in ("name", "base_url", "model", "tier", "graph_id")
    }
    target["class"] = f"{type(adapter).__module__}.{type(adapter).__qualname__}"
    target["graph_spec"] = getattr(getattr(adapter, "resolver", None), "spec", None)
    try:
        oracle_configs = [
            {
                "class": f"{type(o).__module__}.{type(o).__qualname__}",
                "config": vars(o),
                "implementation": inspect.getsource(type(o)),
            }
            for o in oracles
        ]
        oracle_digest = configuration_digest(oracle_configs)
    except (TypeError, OSError):
        oracle_digest = None
    return {
        "schema_version": 1,
        "seed_derivation": SEED_DERIVATION,
        "engine_version": __version__,
        "oracle_composition_digest": configuration_digest(inspect.getsource(combine_oracle_results)),
        "scenario_digest": configuration_digest(scenario),
        "target_configuration_digest": configuration_digest(target),
        "tool_digest": configuration_digest(tools),
        "oracle_digest": oracle_digest,
        "comparable": oracle_digest is not None,
        "target_build": "unverified; configured URL/model identity only",
    }


def model_comparison_identity(
    model: str,
    target_type: str,
    endpoint: str | None,
    scenario: Any,
    oracles: Any,
) -> dict[str, Any]:
    """Bind a model-name workflow without asserting provider-resolved endpoint identity."""
    identity = comparison_identity(
        SimpleNamespace(name=f"model-name-{target_type}", model=model, tier="text", base_url=endpoint),
        scenario,
        [],
        oracles,
    )
    if endpoint is None:
        identity["comparable"] = False
        identity["target_build"] = "unverified; provider-resolved endpoint unavailable"
    return identity
