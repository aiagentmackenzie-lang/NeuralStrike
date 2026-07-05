"""SARIF 2.1.0 report writer.

Emits a SARIF 2.1.0 document mapping every finding to:

- an OWASP Agentic (ASI) or OWASP LLM (LLM) ID (the ``ruleId``),
- one or more MITRE ATLAS techniques (rule metadata),
- a compliance control list (rule metadata: NIST AI RMF / EU AI Act /
  ISO 42001 / SOC 2 / CSA MAESTRO).

Result levels (the Phase 2 exit-gate requirement that inconclusive probes
be surfaced, not dropped):

- ``error``  — a Succeeded trial (the SUT was exploitable).
- ``note``   — an Inconclusive trial (a coverage gap; surfaced as a
  low-noise note result, never dropped).
- ``none``   — a Resisted trial (the SUT resisted; recorded for completeness
  with ``level: "none"`` so a reviewer sees the full picture, but not a
  finding).

One rule per scenario (ruleId = scenario.id); one result per trial-finding.
The rule's ``driver`` is NeuralStrike; the run's tool version is recorded.
"""

from __future__ import annotations

import json
from typing import Any

from neuralstrike import __version__
from neuralstrike.evaluation.verdict import Verdict
from neuralstrike.reports.compliance import framework_name
from neuralstrike.reports.model import CorpusRun, ScenarioResult

__all__ = ["to_sarif"]

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
    "Schemata/sarif-schema-2.1.0.json"
)


def _level_for(verdict: Verdict) -> str:
    if verdict is Verdict.SUCCEEDED:
        return "error"
    if verdict is Verdict.INCONCLUSIVE:
        return "note"
    return "none"


def _rule_for(scenario_result: ScenarioResult) -> dict[str, Any]:
    s = scenario_result.scenario
    # Build the compliance-control tags from the crosswalk already attached.
    owasp_framework = "OWASP_ASI" if s.owasp_category.startswith("ASI") else "OWASP_LLM"
    controls = [
        {"framework": c.framework, "id": c.control_id, "name": c.control_name, "section": c.section}
        for c in scenario_result.controls
    ]
    return {
        "id": s.id,
        "name": f"{s.owasp_category}: {s.owasp_name}",
        "shortDescription": {"text": s.intent},
        "fullDescription": {
            "text": (
                f"OWASP {s.owasp_category} ({s.owasp_name}); "
                f"MITRE ATLAS: {', '.join(s.mitre_atlas) or 'none'}. "
                f"Delivery vector: {s.delivery_vector}."
            )
        },
        "properties": {
            "owasp_category": s.owasp_category,
            "owasp_name": s.owasp_name,
            "owasp_framework": owasp_framework,
            "mitre_atlas": list(s.mitre_atlas),
            "delivery_vector": s.delivery_vector,
            "severity": s.severity,
            "mitigations": list(s.mitigations),
            "compliance_controls": controls,
            # Human-readable framework names for the SARIF viewer tooltip.
            "compliance_frameworks": [
                framework_name(c.framework) for c in scenario_result.controls
            ],
        },
    }


def _result_for(scenario_result: ScenarioResult, trial: Any) -> dict[str, Any]:
    s = scenario_result.scenario
    message_parts = [trial.reason]
    if trial.evidence_quote:
        message_parts.append(f"evidence: {trial.evidence_quote!r}")
    if trial.delivery_channels:
        message_parts.append(f"delivered via: {', '.join(trial.delivery_channels)}")
    if trial.error:
        message_parts.append(f"error: {trial.error}")
    return {
        "ruleId": s.id,
        "level": _level_for(trial.verdict),
        "message": {"text": " | ".join(message_parts)},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": f"corpus/{_corpus_file(s.id)}"},
                },
                "logicalLocations": [
                    {
                        "name": s.id,
                        "properties": {
                            "owasp_category": s.owasp_category,
                            "mitre_atlas": list(s.mitre_atlas),
                            "delivery_vector": s.delivery_vector,
                        },
                    },
                ],
            }
        ],
        "properties": {
            "verdict": trial.verdict.value,
            "fidelity": trial.fidelity.value,
            "severity": trial.severity,
            "oracle_id": trial.oracle_id,
            "advisory": trial.advisory,
            "trial_index": trial.trial_index,
            "seed": trial.seed,
            "delivery_channels": list(trial.delivery_channels),
        },
        "partialFingerprints": {
            "primary": f"{s.id}:{trial.trial_index}:{trial.oracle_id}:{trial.verdict.value}",
        },
    }


def _corpus_file(scenario_id: str) -> str:
    """The corpus file a scenario lives in (asi01-asi10.yaml or llm01-llm10.yaml)."""
    sid = scenario_id.lower()
    if sid.startswith("asi"):
        return "asi01-asi10.yaml"
    if sid.startswith("llm"):
        return "llm01-llm10.yaml"
    return "corpus.yaml"


def to_sarif(run: CorpusRun) -> str:
    """Render the corpus run as a SARIF 2.1.0 JSON document."""
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    for sr in run.scenario_results:
        rules.append(_rule_for(sr))
        for trial in sr.trials:
            results.append(_result_for(sr, trial))

    doc: dict[str, Any] = {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "NeuralStrike",
                        "version": __version__,
                        "informationUri": (
                            "https://github.com/aiagentmackenzie-lang/NeuralStrike"
                        ),
                        "rules": rules,
                        "properties": {
                            "summary": (
                                f"OWASP Agentic ASI01-10 + LLM01-10 corpus run; "
                                f"adapter={run.adapter}; target={run.target}; "
                                f"seed={run.base_seed}; "
                                f"ASR={run.asr:.4f}; coverage={run.coverage:.4f}; "
                                f"succeeded={run.overall_succeeded}; "
                                f"inconclusive={run.overall_inconclusive}; "
                                f"resisted={run.overall_resisted}."
                            ),
                        },
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": run.started_at,
                        "properties": {
                            "base_seed": run.base_seed,
                            "trials_per_scenario": run.trials_per_scenario,
                            "adapter": run.adapter,
                            "target": run.target,
                            "overall_asr": run.asr,
                            "overall_coverage": run.coverage,
                        },
                    }
                ],
            }
        ],
    }
    return json.dumps(doc, indent=2, sort_keys=False, ensure_ascii=False)
