"""A2A delegation-chain abuse analyzer (Phase 5).

Analyzes A2A delegation chains for:

- Depth escalation beyond a safe limit.
- Scope widening (a delegated task asks for permissions not in the
  original scope).
- Cross-tenant delegation (issuer/recipient tenant mismatch).
- Missing / weak proof-of-delegation signatures.

This is a static analyzer of a delegation record; it does not perform
runtime enforcement.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from itertools import pairwise
from typing import Any

from neuralstrike.utils.logging import get_logger

__all__ = ["DelegationAbuseResult", "DelegationAnalyzer"]

logger = get_logger("neuralstrike.attacks.a2a.delegation")


@dataclass(frozen=True)
class DelegationAbuseResult:
    """One delegation-chain abuse finding."""

    issue: str
    severity: str
    evidence: str


@dataclass(frozen=True)
class DelegationRecord:
    """A parsed A2A delegation record."""

    issuer: str
    recipient: str
    scope: tuple[str, ...]
    depth: int
    tenant: str | None = None
    proof: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


class DelegationAnalyzer:
    """Static analyzer for A2A delegation chains."""

    def __init__(
        self,
        *,
        max_depth: int = 3,
        allowed_scope_prefixes: tuple[str, ...] = (),
    ) -> None:
        self.max_depth = max_depth
        self.allowed_scope_prefixes = allowed_scope_prefixes

    def analyze(self, chain: tuple[DelegationRecord, ...]) -> tuple[DelegationAbuseResult, ...]:
        """Analyze a delegation chain and return abuse findings."""
        findings: list[DelegationAbuseResult] = []
        if not chain:
            return ()

        # Depth escalation.
        if len(chain) > self.max_depth:
            findings.append(
                DelegationAbuseResult(
                    issue="depth_escalation",
                    severity="high",
                    evidence=f"chain depth {len(chain)} exceeds max {self.max_depth}",
                )
            )

        # Scope widening between consecutive links.
        for prev, curr in pairwise(chain):
            widened = set(curr.scope) - set(prev.scope)
            if widened:
                scopes = sorted(widened)
                evidence = f"recipient {curr.recipient} gained scopes {scopes} not held by {prev.issuer}"
                findings.append(
                    DelegationAbuseResult(
                        issue="scope_widening",
                        severity="critical",
                        evidence=evidence,
                    )
                )

        # Tenant mismatch.
        tenants = {r.tenant for r in chain if r.tenant}
        if len(tenants) > 1:
            findings.append(
                DelegationAbuseResult(
                    issue="cross_tenant_delegation",
                    severity="high",
                    evidence=f"delegation spans tenants: {sorted(tenants)}",
                )
            )

        # Missing proof-of-delegation.
        for idx, rec in enumerate(chain):
            if not rec.proof.get("signature") and not rec.proof.get("jws"):
                evidence = f"link {idx} ({rec.issuer} -> {rec.recipient}) lacks proof-of-delegation signature"
                findings.append(
                    DelegationAbuseResult(
                        issue="missing_delegation_proof",
                        severity="medium",
                        evidence=evidence,
                    )
                )

        # Scope prefix allow-list.
        if self.allowed_scope_prefixes:
            for rec in chain:
                for scope in rec.scope:
                    if not any(scope.startswith(p) for p in self.allowed_scope_prefixes):
                        findings.append(
                            DelegationAbuseResult(
                                issue="disallowed_scope",
                                severity="high",
                                evidence=f"scope {scope!r} is not in allowed prefix list",
                            )
                        )

        return tuple(findings)
