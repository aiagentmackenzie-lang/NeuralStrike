"""Bind Behavioral fidelity to an exact call, argument digest and local receipt.

A local fixture receipt proves harness execution, not production side effects.
Legacy/prose-only findings and unbound traces cannot be promoted.
"""

from __future__ import annotations

from dataclasses import replace

from neuralstrike.evaluation.verdict import EvidenceFidelity, Finding, SutResponse, ToolCall, Verdict
from neuralstrike.oracles.tool_harness import TraceLog, TraceRecord

__all__ = ["fidelity_of", "upgrade_fidelity_from_traces"]


def _matching_receipt(finding: Finding, response: SutResponse, trace: TraceLog | None) -> TraceRecord | None:
    if (
        trace is None
        or finding.verdict is not Verdict.SUCCEEDED
        or not finding.tool_name
        or not finding.tool_call_id
        or not finding.arguments_digest
    ):
        return None
    calls = [call for call in response.tool_calls if call.tool_call_id == finding.tool_call_id]
    receipts = [record for record in trace.records if record.tool_call_id == finding.tool_call_id]
    # Duplicate IDs are ambiguous even when one candidate happens to match.
    if len(calls) != 1 or len(receipts) != 1:
        return None
    call, receipt = calls[0], receipts[0]
    if not (
        call.name == finding.tool_name == receipt.tool
        and call.argument_digest()
        == finding.arguments_digest
        == ToolCall(receipt.tool, receipt.arguments).argument_digest()
        and receipt.receipt_id
        and receipt.origin == "local-canary-fixture"
    ):
        return None
    return receipt


def fidelity_of(finding: Finding, response: SutResponse, trace: TraceLog | None) -> EvidenceFidelity:
    """Promote only a successful finding with an exact, unambiguous receipt."""
    if _matching_receipt(finding, response, trace) is not None:
        return EvidenceFidelity.BEHAVIORAL
    return finding.fidelity


def upgrade_fidelity_from_traces(
    findings: list[Finding],
    response: SutResponse,
    trace: TraceLog | None,
) -> list[Finding]:
    """Preserve structured causal links and provenance on promoted findings."""
    if trace is None or len(trace) == 0:
        return findings
    upgraded = []
    for finding in findings:
        receipt = _matching_receipt(finding, response, trace)
        upgraded.append(
            replace(
                finding,
                fidelity=EvidenceFidelity.BEHAVIORAL,
                receipt_id=receipt.receipt_id,
                evidence_origin=receipt.origin,
            )
            if receipt is not None
            else finding
        )
    return upgraded
