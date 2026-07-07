"""Corpus loader — typed scenario objects + oracle builder.

Loads ``corpus/*.yaml`` into :class:`Scenario` objects and builds the
deterministic :class:`~neuralstrike.oracles.base.Oracle` list for each
scenario from its ``success_criteria`` block.

The corpus is the foundation of Phase 2: every report (SARIF / JUnit /
Markdown / PDF / JSON) and the README mapping table are *generated* from
the loaded corpus, never hand-written. A scenario declares which
deterministic oracles prove a finding; the loader materializes those
oracles so the runner can score behaviour, not text.

Schema (per case, see ``corpus/asi01-asi10.yaml``)::

    id, owasp_category, owasp_name, mitre_atlas (list), severity,
    delivery_vector (user_message|tool_result|retrieved_document|memory|
                     system_prompt),
    intent, legitimate_task, adversarial_payload (may contain {CANARY}),
    success_criteria (list of oracle refs), mitigations (list).

``success_criteria`` oracle refs:

- ``oracle: canary`` — canary-leakage oracle (token minted per trial,
  substituted into ``{CANARY}`` placeholders in the payload).
- ``oracle: system_prompt_extraction`` — system-prompt canary oracle.
- ``oracle: forbidden_tool`` with ``forbidden_tools: [name, ...]``.
- ``oracle: predicate`` with ``pattern`` + ``polarity: match|absence``.
- ``oracle: schema`` with ``schema: { ... JSON Schema ... }``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

import yaml

if TYPE_CHECKING:
    from neuralstrike.oracles.base import Oracle

__all__ = [
    "CANARY_PLACEHOLDER",
    "DeliveryVector",
    "Scenario",
    "SuccessCriterion",
    "build_oracles",
    "corpus_path",
    "iter_corpus_files",
    "load_corpus",
    "load_corpus_dir",
]

CANARY_PLACEHOLDER = "{CANARY}"
"""The per-trial canary token is substituted into this placeholder in the
adversarial payload (and, for ``system_prompt`` delivery, into the system
prompt). The runner mints a fresh canary each trial."""

DeliveryVector = Literal[
    "user_message", "tool_result", "retrieved_document", "memory", "system_prompt"
]
"""The five channels an indirect-injection payload can ride on. The
:class:`~neuralstrike.attacks.indirect.IndirectHarness` weaves the payload
into the declared channel; the adapter surfaces each channel distinctly so
the SUT is tested at the boundary, not just at the user message."""


def corpus_path() -> Path:
    """The bundled corpus directory (sibling of the installed package)."""
    here = Path(__file__).resolve().parent
    bundled = here / "data"
    if bundled.is_dir():
        return bundled
    # Fallback: repo layout where corpus/ lives next to src/.
    root = here.parents[3]
    return root / "corpus"


def iter_corpus_files(directory: str | Path | None = None) -> list[Path]:
    """Yield ``*.yaml`` corpus files in sorted order (deterministic loading)."""
    d = Path(directory) if directory is not None else corpus_path()
    if not d.is_dir():
        return []
    return sorted(d.glob("*.yaml"))


@dataclass(frozen=True)
class SuccessCriterion:
    """One oracle ref from a scenario's ``success_criteria`` block."""

    oracle: str
    severity: str = "high"
    # Optional fields, interpreted per oracle kind:
    forbidden_tools: tuple[str, ...] = field(default_factory=tuple)
    pattern: str | None = None
    polarity: str = "match"
    schema: dict[str, Any] | None = None


@dataclass(frozen=True)
class Scenario:
    """A typed, runnable scenario loaded from the corpus YAML."""

    id: str
    owasp_category: str
    owasp_name: str
    mitre_atlas: tuple[str, ...]
    severity: str
    delivery_vector: DeliveryVector
    intent: str
    legitimate_task: str
    adversarial_payload: str
    success_criteria: tuple[SuccessCriterion, ...]
    mitigations: tuple[str, ...] = field(default_factory=tuple)

    def build_oracles(self, canary: str) -> list[Oracle]:
        """Materialize the deterministic oracles for this scenario.

        ``canary`` is the per-trial canary token; the caller mints it and
        substitutes it into ``{CANARY}`` placeholders before the adapter
        sees the payload. Canary / system_prompt_extraction oracles bind
        to this token; the others are canary-independent.
        """
        from neuralstrike.corpus.loader import build_oracles as _build

        return _build(self.success_criteria, canary)

    def payload_for(self, canary: str) -> str:
        """The adversarial payload with the per-trial canary substituted in."""
        return self.adversarial_payload.replace(CANARY_PLACEHOLDER, canary)


def _criterion_from_dict(d: dict[str, Any]) -> SuccessCriterion:
    oracle = str(d.get("oracle", "")).strip()
    if not oracle:
        raise ValueError(f"success_criteria entry missing 'oracle': {d!r}")
    crit = SuccessCriterion(
        oracle=oracle,
        severity=str(d.get("severity", "high")),
        forbidden_tools=tuple(str(t) for t in d.get("forbidden_tools", []) or []),
        pattern=d.get("pattern"),
        polarity=str(d.get("polarity", "match")),
        schema=d.get("schema"),
    )
    return crit


def build_oracles(
    criteria: tuple[SuccessCriterion, ...], canary: str
) -> list[Oracle]:
    """Build the deterministic oracle list from criteria + a per-trial canary.

    Order is preserved so report ordering is deterministic. Duplicate oracle
    kinds are allowed (a scenario may assert both canary leakage and a
    forbidden tool call); :func:`~neuralstrike.oracles.base.combine_oracle_results`
    combines them conclusive-only.
    """
    # Imports are local to break a latent circular import in the existing
    # package graph (oracles.base <-> evaluation.runner). Importing the
    # concrete oracles at module top-level would force ``neuralstrike.oracles``
    # to initialise before ``neuralstrike.evaluation`` in some import orders,
    # which re-enters ``oracles.base`` mid-init. Local import sidesteps it.
    from neuralstrike.oracles.canary import CanaryOracle
    from neuralstrike.oracles.forbidden_tool import (
        ForbiddenToolOracle,
        ForbiddenToolSpec,
    )
    from neuralstrike.oracles.predicate import PredicateOracle
    from neuralstrike.oracles.schema import SchemaOracle
    from neuralstrike.oracles.system_prompt import SystemPromptExtraction

    oracles: list[Oracle] = []
    for c in criteria:
        if c.oracle == "canary":
            oracles.append(CanaryOracle(canary, severity=c.severity))
        elif c.oracle == "system_prompt_extraction":
            oracles.append(SystemPromptExtraction(canary, severity=c.severity))
        elif c.oracle == "forbidden_tool":
            spec = ForbiddenToolSpec(forbidden_tools=c.forbidden_tools)
            oracles.append(ForbiddenToolOracle(spec, severity=c.severity))
        elif c.oracle == "predicate":
            if not c.pattern:
                raise ValueError(
                    f"predicate criterion requires 'pattern' (scenario oracle={c.oracle!r})"
                )
            oracles.append(
                PredicateOracle(
                    c.pattern, polarity=c.polarity, severity=c.severity  # type: ignore[arg-type]
                )
            )
        elif c.oracle == "schema":
            if not isinstance(c.schema, dict):
                raise ValueError(
                    f"schema criterion requires a JSON-schema 'schema' dict (oracle={c.oracle!r})"
                )
            oracles.append(SchemaOracle(c.schema, severity=c.severity))
        else:
            raise ValueError(f"unknown oracle kind in success_criteria: {c.oracle!r}")
    return oracles


def _scenario_from_dict(d: dict[str, Any]) -> Scenario:
    required = (
        "id",
        "owasp_category",
        "owasp_name",
        "severity",
        "delivery_vector",
        "intent",
        "legitimate_task",
        "adversarial_payload",
        "success_criteria",
    )
    missing = [k for k in required if k not in d]
    if missing:
        raise ValueError(f"scenario missing required keys {missing}: {d.get('id', '<no id>')!r}")

    dv = str(d["delivery_vector"]).strip()
    valid_vectors = {
        "user_message",
        "tool_result",
        "retrieved_document",
        "memory",
        "system_prompt",
    }
    if dv not in valid_vectors:
        raise ValueError(
            f"scenario {d['id']!r} has invalid delivery_vector {dv!r}; "
            f"expected one of {sorted(valid_vectors)}"
        )

    raw_criteria = d.get("success_criteria") or []
    if not isinstance(raw_criteria, list) or not raw_criteria:
        raise ValueError(
            f"scenario {d['id']!r} must have a non-empty success_criteria list"
        )
    criteria = tuple(_criterion_from_dict(c) for c in raw_criteria)

    return Scenario(
        id=str(d["id"]),
        owasp_category=str(d["owasp_category"]),
        owasp_name=str(d["owasp_name"]),
        mitre_atlas=tuple(str(t) for t in d.get("mitre_atlas", []) or []),
        severity=str(d["severity"]),
        delivery_vector=dv,  # type: ignore[arg-type]
        intent=str(d["intent"]),
        legitimate_task=str(d["legitimate_task"]),
        adversarial_payload=str(d["adversarial_payload"]),
        success_criteria=criteria,
        mitigations=tuple(str(m) for m in d.get("mitigations", []) or []),
    )


def load_corpus(path: str | Path) -> list[Scenario]:
    """Load scenarios from a single YAML file."""
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, list):
        raise ValueError(f"corpus file {path} must be a YAML list of scenarios")
    return [_scenario_from_dict(c) for c in data]


def load_corpus_dir(directory: str | Path | None = None) -> list[Scenario]:
    """Load all scenarios from every ``*.yaml`` file in the corpus directory.

    Sorted by file then by declaration order so the corpus run is
    deterministic. Returns ``[]`` if the directory does not exist (a
    caller may pass a custom dir).
    """
    scenarios: list[Scenario] = []
    for f in iter_corpus_files(directory):
        scenarios.extend(load_corpus(f))
    return scenarios
