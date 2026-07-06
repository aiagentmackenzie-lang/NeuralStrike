"""MCP tool-poisoning detection (Phase 5).

Scans an MCP server's ``tools/list`` descriptor surface for the attack
patterns that define the 2025-2026 MCP threat class:

- Injected instructions in tool descriptions (delimiter-wrapped system
  prompts, suspicious keywords).
- Whitespace padding / homoglyph name obfuscation.
- Language-switching descriptors.
- Shadow tools — names that look like legitimate tools but are not.
- Manifest-hash pinning + drift detection (TOFU per ETDI / Deconvolute).
- Sleeper rug-pull detection across two snapshots of the same server.

The detector returns a structured report with severity, evidence quote,
and a deterministic verdict. It does not mutate the server.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

from neuralstrike.adapters.mcp_http import MCPHTTPAdapter, MCPTool
from neuralstrike.evaluation.verdict import EvidenceFidelity, Verdict
from neuralstrike.oracles.base import OracleResult
from neuralstrike.utils.logging import get_logger

__all__ = [
    "MCPManifest",
    "MCPPoisonDetector",
    "MCPPoisonReport",
    "PoisonFinding",
    "hash_manifest",
]

logger = get_logger("neuralstrike.attacks.mcp_poison")


@dataclass(frozen=True)
class PoisonFinding:
    """One poisoning suspicion with evidence."""

    pattern: str
    tool_name: str
    evidence: str
    severity: str = "high"
    confidence: str = "medium"


@dataclass(frozen=True)
class MCPManifest:
    """A snapshot of an MCP tool manifest for comparison / hashing."""

    tools: tuple[MCPTool, ...]
    server_info: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def tool_names(self) -> set[str]:
        return {t.name for t in self.tools}


@dataclass(frozen=True)
class MCPPoisonReport:
    """Result of scanning one or two MCP manifests."""

    findings: tuple[PoisonFinding, ...]
    manifest_hash: str
    previous_hash: str | None
    drift_detected: bool
    shadow_tools: tuple[str, ...]
    verdict: Verdict
    fidelity: EvidenceFidelity = EvidenceFidelity.INTENT_TO_ACT


def hash_manifest(manifest: MCPManifest) -> str:
    """SHA-256 hash of the canonical tool manifest (names + descriptions + schemas)."""
    hasher = hashlib.sha256()
    for t in sorted(manifest.tools, key=lambda x: x.name):
        hasher.update(t.name.encode("utf-8"))
        hasher.update(t.description.encode("utf-8"))
        hasher.update(_canonical_json(t.input_schema).encode("utf-8"))
    return hasher.hexdigest()


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


# Heuristic patterns. These are intentionally narrow — false positives are
# better than false negatives for a red-team detector, but each finding is
# labeled with confidence so the operator can triage.
_INJECTION_NEEDLES = (
    "ignore previous instructions",
    "ignore all prior",
    "system prompt",
    "you are now",
    "developer mode",
    "DAN mode",
    "jailbreak",
    "disregard",
    "new instructions",
)
_DELIMITER_PAIRS = (
    ("\u003c\u003c", "\u003e\u003e"),
    ("[[", "]]"),
    ("{{", "}}"),
    ("/*", "*/"),
    ("\u003c!--", "--\u003e"),
)


class MCPPoisonDetector:
    """Detect tool-poisoning patterns in an MCP manifest."""

    def __init__(
        self,
        *,
        known_legitimate_tools: set[str] | None = None,
        pin_hash: str | None = None,
    ) -> None:
        self.known_legitimate_tools = known_legitimate_tools or set()
        self.pin_hash = pin_hash

    async def scan(
        self,
        adapter: MCPHTTPAdapter,
        *,
        previous_manifest: MCPManifest | None = None,
    ) -> MCPPoisonReport:
        """Introspect the MCP server and detect poisoning patterns."""
        await adapter.initialize()
        tools = await adapter.list_tools()
        manifest = MCPManifest(tools=tuple(tools))
        manifest_hash = hash_manifest(manifest)

        findings: list[PoisonFinding] = []
        for tool in manifest.tools:
            findings.extend(self._check_injected_instructions(tool))
            findings.extend(self._check_whitespace_padding(tool))
            findings.extend(self._check_language_switching(tool))

        shadow_tools = self._find_shadow_tools(manifest)
        if shadow_tools:
            findings.append(
                PoisonFinding(
                    pattern="shadow_tool",
                    tool_name=", ".join(shadow_tools),
                    evidence=f"tool names resemble legitimate tools: {sorted(shadow_tools)}",
                    severity="high",
                    confidence="medium",
                )
            )

        drift_detected = False
        if self.pin_hash is not None and manifest_hash != self.pin_hash:
            drift_detected = True
            findings.append(
                PoisonFinding(
                    pattern="manifest_drift",
                    tool_name="*",
                    evidence=f"manifest hash {manifest_hash[:16]} differs from pinned {self.pin_hash[:16]}",
                    severity="critical",
                    confidence="high",
                )
            )

        previous_hash = None
        if previous_manifest is not None:
            previous_hash = hash_manifest(previous_manifest)
            if previous_hash != manifest_hash:
                drift_detected = True
                rug_pull = self._detect_rug_pull(previous_manifest, manifest)
                findings.extend(rug_pull)

        verdict = Verdict.INCONCLUSIVE
        if any(f.severity in ("high", "critical") for f in findings):
            verdict = Verdict.SUCCEEDED  # attack surface detected (the "finding" is the poison)
        elif findings:
            verdict = Verdict.SUCCEEDED  # any poisoning finding is a success for the probe

        return MCPPoisonReport(
            findings=tuple(findings),
            manifest_hash=manifest_hash,
            previous_hash=previous_hash,
            drift_detected=drift_detected,
            shadow_tools=tuple(shadow_tools),
            verdict=verdict,
        )

    def _check_injected_instructions(self, tool: MCPTool) -> list[PoisonFinding]:
        text = f"{tool.name} {tool.description}".lower()
        out: list[PoisonFinding] = []
        for needle in _INJECTION_NEEDLES:
            if needle in text:
                out.append(
                    PoisonFinding(
                        pattern="injected_instruction",
                        tool_name=tool.name,
                        evidence=f"descriptor contains suspicious phrase {needle!r}",
                        severity="high",
                        confidence="medium",
                    )
                )
        for open_delim, close_delim in _DELIMITER_PAIRS:
            if open_delim in tool.description and close_delim in tool.description:
                out.append(
                    PoisonFinding(
                        pattern="delimiter_wrap",
                        tool_name=tool.name,
                        evidence=f"description contains delimiter pair {open_delim!r}...{close_delim!r}",
                        severity="medium",
                        confidence="low",
                    )
                )
        return out

    def _check_whitespace_padding(self, tool: MCPTool) -> list[PoisonFinding]:
        out: list[PoisonFinding] = []
        if tool.name != tool.name.strip() or re.search(r"[^\x20-\x7E]", tool.name):
            out.append(
                PoisonFinding(
                    pattern="whitespace_padding",
                    tool_name=tool.name,
                    evidence="tool name has leading/trailing whitespace or non-ASCII characters",
                    severity="medium",
                    confidence="high",
                )
            )
        return out

    def _check_language_switching(self, tool: MCPTool) -> list[PoisonFinding]:
        out: list[PoisonFinding] = []
        desc = tool.description
        # Simple heuristic: non-Latin script characters in an otherwise English-looking
        # descriptor may indicate language-switching evasion.
        if desc and re.search(r"[\u0400-\u04FF\u0600-\u06FF\u4E00-\u9FFF]", desc):
            ascii_ratio = sum(1 for c in desc if ord(c) < 128) / max(len(desc), 1)
            if 0.1 < ascii_ratio < 0.9:
                out.append(
                    PoisonFinding(
                        pattern="language_switching",
                        tool_name=tool.name,
                        evidence="description mixes scripts (possible language-switching evasion)",
                        severity="medium",
                        confidence="low",
                    )
                )
        return out

    def _find_shadow_tools(self, manifest: MCPManifest) -> set[str]:
        """Names in the manifest that look like known legitimate tools but are not exact matches."""
        if not self.known_legitimate_tools:
            return set()
        shadows: set[str] = set()
        for name in manifest.tool_names:
            normalized = re.sub(r"[^a-z0-9_]", "", name.lower())
            for legit in self.known_legitimate_tools:
                legit_norm = re.sub(r"[^a-z0-9_]", "", legit.lower())
                if normalized != legit_norm and (
                    normalized in legit_norm
                    or legit_norm in normalized
                    or self._levenshtein(normalized, legit_norm) <= 2
                ):
                    shadows.add(name)
                    break
        return shadows

    def _detect_rug_pull(
        self,
        previous: MCPManifest,
        current: MCPManifest,
    ) -> list[PoisonFinding]:
        """Compare two manifests and flag sleeper rug-pull patterns."""
        out: list[PoisonFinding] = []
        prev_by_name = {t.name: t for t in previous.tools}
        curr_by_name = {t.name: t for t in current.tools}

        # New tools that weren't there before.
        new_tools = set(curr_by_name) - set(prev_by_name)
        for name in new_tools:
            tool = curr_by_name[name]
            suspicion = any(needle in tool.description.lower() for needle in _INJECTION_NEEDLES)
            evidence = "tool appeared between snapshots"
            if suspicion:
                evidence += " and contains injection markers"
            out.append(
                PoisonFinding(
                    pattern="new_tool_rug_pull" if not suspicion else "new_tool_with_injection",
                    tool_name=name,
                    evidence=evidence,
                    severity="high" if suspicion else "medium",
                    confidence="high",
                )
            )

        # Changed descriptions for existing tools.
        for name in set(prev_by_name) & set(curr_by_name):
            prev_desc = prev_by_name[name].description
            curr_desc = curr_by_name[name].description
            if prev_desc != curr_desc:
                suspicion = any(needle in curr_desc.lower() for needle in _INJECTION_NEEDLES)
                out.append(
                    PoisonFinding(
                        pattern="description_drift" if not suspicion else "description_drift_with_injection",
                        tool_name=name,
                        evidence="tool description changed between snapshots",
                        severity="high" if suspicion else "medium",
                        confidence="high",
                    )
                )

        return out

    @staticmethod
    def _levenshtein(a: str, b: str) -> int:
        """Bounded Levenshtein distance; early abort if > 3."""
        if abs(len(a) - len(b)) > 3:
            return 4
        prev = list(range(len(b) + 1))
        for i, ca in enumerate(a, 1):
            curr = [i]
            for j, cb in enumerate(b, 1):
                cost = 0 if ca == cb else 1
                curr.append(min(curr[-1] + 1, prev[j] + 1, prev[j - 1] + cost))
                if min(curr) > 3:
                    return 4
            prev = curr
        return prev[-1]


def report_to_oracle_result(report: MCPPoisonReport) -> OracleResult:
    """Convert an MCP poison report to the standard oracle result shape.

    Multiple findings are collapsed into one :class:`OracleResult` whose
    ``reason`` enumerates the detected patterns.
    """
    if not report.findings:
        return OracleResult(
            oracle_id="mcp_poison",
            verdict=Verdict.INCONCLUSIVE,
            fidelity=EvidenceFidelity.INTENT_TO_ACT,
            evidence_quote=None,
            reason="no poisoning patterns detected",
            severity="info",
        )
    reasons = [f"{pf.pattern} in {pf.tool_name}: {pf.evidence}" for pf in report.findings]
    severities = {"critical": 3, "high": 2, "medium": 1, "low": 0, "info": -1}
    top_severity = max(report.findings, key=lambda f: severities.get(f.severity, 0)).severity
    return OracleResult(
        oracle_id="mcp_poison",
        verdict=Verdict.SUCCEEDED,
        fidelity=EvidenceFidelity.INTENT_TO_ACT,
        evidence_quote=report.findings[0].evidence[:200],
        reason=" | ".join(reasons),
        severity=top_severity,
    )
