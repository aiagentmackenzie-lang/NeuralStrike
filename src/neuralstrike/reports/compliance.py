"""Compliance crosswalk — map findings to ASI/LLM/ATLAS + control frameworks.

Phase 2 deliverable: every finding in a SARIF / JUnit / Markdown / PDF
report maps to an OWASP Agentic (ASI) or OWASP LLM (LLM) ID, one or more
MITRE ATLAS techniques, and a compliance control across:

- NIST AI RMF (GOVERN / MAP / MEASURE / MANAGE functions)
- EU AI Act (risk-tier + article)
- ISO/IEC 42001:2023 (AI management system clauses)
- SOC 2 (Trust Services Criteria: Security/Availability/Confidentiality)
- CSA MAESTRO (Model Authentication, Authorization, Secrecy, Trust,
  Runtime, Operations)

The crosswalk is a deterministic mapping (no LLM, no judgement). It is the
bridge that turns a behaviour-observed finding into an audit-grade control
reference. ``crosswalk()`` returns the full control list for an
``owasp_category`` + ``mitre_atlas`` tuple; the report formats cite the
list verbatim so a reviewer can trace a finding to a control in one step.

Framework ID conventions:
- ``OWASP_ASI``    — OWASP Top 10 for Agentic Applications (2026), ASI01—10
- ``OWASP_LLM``    — OWASP Top 10 for LLM Applications (2025), LLM01—10
- ``MITRE_ATLAS``  — MITRE ATLAS techniques (AML.Txxxx)
- ``NIST_AI_RMF``  — NIST AI Risk Management Framework (functions)
- ``EU_AI_ACT``    — EU AI Act (risk tier + article)
- ``ISO_42001``    — ISO/IEC 42001:2023 clauses
- ``SOC2``         — AICPA Trust Services Criteria
- ``CSA_MAESTRO``  — Cloud Security Alliance MAESTRO layers
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

__all__ = [
    "OWASP_ASI_INDEX",
    "OWASP_LLM_INDEX",
    "ControlRef",
    "FrameworkID",
    "crosswalk",
    "framework_name",
]

FrameworkID = Literal[
    "OWASP_ASI",
    "OWASP_LLM",
    "MITRE_ATLAS",
    "NIST_AI_RMF",
    "EU_AI_ACT",
    "ISO_42001",
    "SOC2",
    "CSA_MAESTRO",
]


@dataclass(frozen=True)
class ControlRef:
    """One compliance-control reference for a finding."""

    framework: FrameworkID
    control_id: str
    control_name: str
    section: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "framework": self.framework,
            "control_id": self.control_id,
            "control_name": self.control_name,
            "section": self.section,
        }


def framework_name(framework: FrameworkID) -> str:
    return {
        "OWASP_ASI": "OWASP Top 10 for Agentic Applications (2026)",
        "OWASP_LLM": "OWASP Top 10 for LLM Applications (2025)",
        "MITRE_ATLAS": "MITRE ATLAS",
        "NIST_AI_RMF": "NIST AI Risk Management Framework",
        "EU_AI_ACT": "EU AI Act",
        "ISO_42001": "ISO/IEC 42001:2023",
        "SOC2": "SOC 2 (TSC)",
        "CSA_MAESTRO": "CSA MAESTRO",
    }[framework]


# OWASP Agentic Top 10 (2026) index — official titles + categories.
OWASP_ASI_INDEX: dict[str, str] = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse and Exploitation",
    "ASI03": "Identity and Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory and Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}

# OWASP LLM Top 10 (2025) index — official titles.
OWASP_LLM_INDEX: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}


# Per-OWASP-category compliance crosswalk. Each entry lists the controls a
# finding in that category implicates. The mapping is conservative: it cites
# the control families that *require* a defence against the category, not
# every control in the framework.
_CATEGORY_CROSSWALK: dict[str, tuple[ControlRef, ...]] = {
    # --- ASI ---
    "ASI01": (
        ControlRef("NIST_AI_RMF", "MAP-2.2", "Impact to users and third parties"),
        ControlRef("NIST_AI_RMF", "MEASURE-2.5", "Adversarial robustness testing"),
        ControlRef("EU_AI_ACT", "Art.15", "Accuracy, robustness and cybersecurity"),
        ControlRef("ISO_42001", "Cl.8.3", "AI system development controls"),
        ControlRef("SOC2", "CC6.1", "Logical and physical access controls"),
        ControlRef("CSA_MAESTRO", "M-T1", "Threat modeling for agent goals"),
    ),
    "ASI02": (
        ControlRef("NIST_AI_RMF", "MEASURE-2.5", "Adversarial robustness testing"),
        ControlRef("EU_AI_ACT", "Art.15", "Accuracy, robustness and cybersecurity"),
        ControlRef("ISO_42001", "Cl.8.4", "AI system operation controls"),
        ControlRef("SOC2", "CC6.3", "Authorization and access restrictions"),
        ControlRef("CSA_MAESTRO", "A-Runtime", "Tool-call authorization at runtime"),
    ),
    "ASI03": (
        ControlRef("NIST_AI_RMF", "GOVERN-3.2", "Accountability and assignment"),
        ControlRef("EU_AI_ACT", "Art.14", "Human oversight"),
        ControlRef("ISO_42001", "Cl.8.2", "AI risk assessment"),
        ControlRef("SOC2", "CC6.1", "Logical and physical access controls"),
        ControlRef("CSA_MAESTRO", "A-AuthN", "Agent identity and credential scoping"),
    ),
    "ASI04": (
        ControlRef("NIST_AI_RMF", "MAP-4.1", "Third-party components and data"),
        ControlRef("EU_AI_ACT", "Art.15", "Accuracy, robustness and cybersecurity"),
        ControlRef("ISO_42001", "Cl.8.3", "AI system development controls"),
        ControlRef("SOC2", "CC7.4", "Vendor and third-party monitoring"),
        ControlRef("CSA_MAESTRO", "S-Secrecy", "Supply-chain integrity for tool descriptors"),
    ),
    "ASI05": (
        ControlRef("NIST_AI_RMF", "MEASURE-2.5", "Adversarial robustness testing"),
        ControlRef("EU_AI_ACT", "Art.15", "Accuracy, robustness and cybersecurity"),
        ControlRef("ISO_42001", "Cl.8.4", "AI system operation controls"),
        ControlRef("SOC2", "CC7.1", "System monitoring"),
        ControlRef("CSA_MAESTRO", "R-Runtime", "Sandboxing for agent-generated code"),
    ),
    "ASI06": (
        ControlRef("NIST_AI_RMF", "MEASURE-2.5", "Adversarial robustness testing"),
        ControlRef("EU_AI_ACT", "Art.10", "Data and data governance"),
        ControlRef("ISO_42001", "Cl.8.3", "AI system development controls"),
        ControlRef("SOC2", "CC6.7", "Data integrity and protection"),
        ControlRef("CSA_MAESTRO", "S-Secrecy", "Memory / context integrity controls"),
    ),
    "ASI07": (
        ControlRef("NIST_AI_RMF", "GOVERN-3.2", "Accountability and assignment"),
        ControlRef("EU_AI_ACT", "Art.14", "Human oversight"),
        ControlRef("ISO_42001", "Cl.8.4", "AI system operation controls"),
        ControlRef("SOC2", "CC6.3", "Authorization and access restrictions"),
        ControlRef("CSA_MAESTRO", "T-Trust", "Inter-agent message authentication"),
    ),
    "ASI08": (
        ControlRef("NIST_AI_RMF", "MEASURE-2.7", "Resilience and incident response"),
        ControlRef("EU_AI_ACT", "Art.15", "Accuracy, robustness and cybersecurity"),
        ControlRef("ISO_42001", "Cl.8.4", "AI system operation controls"),
        ControlRef("SOC2", "CC7.4", "Vendor and third-party monitoring"),
        ControlRef("CSA_MAESTRO", "O-Operations", "Circuit breakers and chain depth limits"),
    ),
    "ASI09": (
        ControlRef("NIST_AI_RMF", "GOVERN-1.3", "Transparency and accountability"),
        ControlRef("EU_AI_ACT", "Art.14", "Human oversight"),
        ControlRef("ISO_42001", "Cl.8.4", "AI system operation controls"),
        ControlRef("SOC2", "CC6.1", "Logical and physical access controls"),
        ControlRef("CSA_MAESTRO", "T-Trust", "Human-agent trust boundaries"),
    ),
    "ASI10": (
        ControlRef("NIST_AI_RMF", "MEASURE-2.7", "Resilience and incident response"),
        ControlRef("EU_AI_ACT", "Art.14", "Human oversight"),
        ControlRef("ISO_42001", "Cl.8.4", "AI system operation controls"),
        ControlRef("SOC2", "CC7.1", "System monitoring"),
        ControlRef("CSA_MAESTRO", "O-Operations", "Behavioral drift detection and kill switches"),
    ),
    # --- LLM ---
    "LLM01": (
        ControlRef("NIST_AI_RMF", "MEASURE-2.5", "Adversarial robustness testing"),
        ControlRef("EU_AI_ACT", "Art.15", "Accuracy, robustness and cybersecurity"),
        ControlRef("ISO_42001", "Cl.8.3", "AI system development controls"),
        ControlRef("SOC2", "CC6.1", "Logical and physical access controls"),
        ControlRef("CSA_MAESTRO", "M-T1", "Prompt-injection threat modeling"),
    ),
    "LLM02": (
        ControlRef("NIST_AI_RMF", "MAP-2.2", "Impact to users and third parties"),
        ControlRef("EU_AI_ACT", "Art.10", "Data and data governance"),
        ControlRef("ISO_42001", "Cl.8.2", "AI risk assessment"),
        ControlRef("SOC2", "CC6.7", "Data integrity and protection"),
        ControlRef("CSA_MAESTRO", "S-Secrecy", "PII / secret redaction controls"),
    ),
    "LLM03": (
        ControlRef("NIST_AI_RMF", "MAP-4.1", "Third-party components and data"),
        ControlRef("EU_AI_ACT", "Art.15", "Accuracy, robustness and cybersecurity"),
        ControlRef("ISO_42001", "Cl.8.3", "AI system development controls"),
        ControlRef("SOC2", "CC7.4", "Vendor and third-party monitoring"),
        ControlRef("CSA_MAESTRO", "S-Secrecy", "Model / component provenance"),
    ),
    "LLM04": (
        ControlRef("NIST_AI_RMF", "MEASURE-2.5", "Adversarial robustness testing"),
        ControlRef("EU_AI_ACT", "Art.10", "Data and data governance"),
        ControlRef("ISO_42001", "Cl.8.3", "AI system development controls"),
        ControlRef("SOC2", "CC6.7", "Data integrity and protection"),
        ControlRef("CSA_MAESTRO", "S-Secrecy", "Training / RAG data integrity"),
    ),
    "LLM05": (
        ControlRef("NIST_AI_RMF", "MEASURE-2.5", "Adversarial robustness testing"),
        ControlRef("EU_AI_ACT", "Art.15", "Accuracy, robustness and cybersecurity"),
        ControlRef("ISO_42001", "Cl.8.4", "AI system operation controls"),
        ControlRef("SOC2", "CC6.3", "Authorization and access restrictions"),
        ControlRef("CSA_MAESTRO", "R-Runtime", "Output validation before downstream use"),
    ),
    "LLM06": (
        ControlRef("NIST_AI_RMF", "GOVERN-3.2", "Accountability and assignment"),
        ControlRef("EU_AI_ACT", "Art.14", "Human oversight"),
        ControlRef("ISO_42001", "Cl.8.4", "AI system operation controls"),
        ControlRef("SOC2", "CC6.3", "Authorization and access restrictions"),
        ControlRef("CSA_MAESTRO", "A-AuthZ", "Least agency / scoped tool authority"),
    ),
    "LLM07": (
        ControlRef("NIST_AI_RMF", "MAP-2.2", "Impact to users and third parties"),
        ControlRef("EU_AI_ACT", "Art.15", "Accuracy, robustness and cybersecurity"),
        ControlRef("ISO_42001", "Cl.8.2", "AI risk assessment"),
        ControlRef("SOC2", "CC6.1", "Logical and physical access controls"),
        ControlRef("CSA_MAESTRO", "S-Secrecy", "No secrets in system prompts"),
    ),
    "LLM08": (
        ControlRef("NIST_AI_RMF", "MEASURE-2.5", "Adversarial robustness testing"),
        ControlRef("EU_AI_ACT", "Art.10", "Data and data governance"),
        ControlRef("ISO_42001", "Cl.8.3", "AI system development controls"),
        ControlRef("SOC2", "CC6.7", "Data integrity and protection"),
        ControlRef("CSA_MAESTRO", "S-Secrecy", "Permission-aware vector stores"),
    ),
    "LLM09": (
        ControlRef("NIST_AI_RMF", "GOVERN-1.3", "Transparency and accountability"),
        ControlRef("EU_AI_ACT", "Art.13", "Transparency obligations"),
        ControlRef("ISO_42001", "Cl.8.4", "AI system operation controls"),
        ControlRef("SOC2", "CC6.1", "Logical and physical access controls"),
        ControlRef("CSA_MAESTRO", "T-Trust", "Output reliability and provenance"),
    ),
    "LLM10": (
        ControlRef("NIST_AI_RMF", "MEASURE-2.7", "Resilience and incident response"),
        ControlRef("EU_AI_ACT", "Art.15", "Accuracy, robustness and cybersecurity"),
        ControlRef("ISO_42001", "Cl.8.4", "AI system operation controls"),
        ControlRef("SOC2", "CC7.1", "System monitoring"),
        ControlRef("CSA_MAESTRO", "O-Operations", "Rate limits / quotas / cost budgets"),
    ),
}


# ATLAS technique index — official names for the techniques the corpus
# references. Used so a report can cite the human-readable technique name
# alongside the AML.Txxxx ID.
_ATLAS_INDEX: dict[str, str] = {
    "AML.T0051.000": "LLM Prompt Injection: Direct",
    "AML.T0051.001": "LLM Prompt Injection: Indirect",
    "AML.T0054": "LLM Jailbreak Injection: Direct",
    "AML.T0010.001": "ML Supply Chain Compromise",
    "AML.T0018": "Backdoor ML Model",
    "AML.T0024.000": "Infer Training Data Membership",
    "AML.T0024.002": "Extract ML Model",
    "AML.T0029": "Denial of ML Service",
    "AML.T0034": "Cost Harvesting",
    "AML.T0048.002": "Societal Harm",
    "AML.T0080.001": "Evade ML Model / Memory Poisoning",
}


def atlas_name(technique_id: str) -> str:
    """Human-readable MITRE ATLAS technique name, or the ID if unknown."""
    return _ATLAS_INDEX.get(technique_id, technique_id)


def crosswalk(
    owasp_category: str,
    mitre_atlas: tuple[str, ...] = (),
) -> list[ControlRef]:
    """Return the full control list for a finding.

    The list always includes the OWASP category itself (ASI/LLM) plus the
    MITRE ATLAS techniques, then the per-category compliance controls. The
    order is deterministic so two runs over the same corpus produce byte-
    identical control lists.
    """
    controls: list[ControlRef] = []
    if owasp_category in OWASP_ASI_INDEX:
        controls.append(
            ControlRef(
                "OWASP_ASI", owasp_category, OWASP_ASI_INDEX[owasp_category], "Agentic Top 10 (2026)"
            )
        )
    elif owasp_category in OWASP_LLM_INDEX:
        controls.append(
            ControlRef(
                "OWASP_LLM", owasp_category, OWASP_LLM_INDEX[owasp_category], "LLM Top 10 (2025)"
            )
        )
    else:
        # Unknown category: still surface it so the report is honest.
        controls.append(ControlRef("OWASP_ASI", owasp_category, "(unknown category)", ""))

    for tid in mitre_atlas:
        controls.append(ControlRef("MITRE_ATLAS", tid, atlas_name(tid), ""))

    controls.extend(_CATEGORY_CROSSWALK.get(owasp_category, ()))
    return controls


def controls_to_dicts(controls: list[ControlRef]) -> list[dict[str, str]]:
    return [c.to_dict() for c in controls]
