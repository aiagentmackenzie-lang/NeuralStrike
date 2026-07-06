"""A2A signed-message spoofing tests (Phase 5).

NeuralStrike tests identity-defended A2A targets by attempting common
signed-message verification bypasses:

- Missing signature headers.
- Algorithm confusion (alg=none / alg override).
- Detached payload tampering.
- Replay of a captured signature against a different body.

The harness reports which bypass attempts a target accepted, producing a
structured finding per attempt.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx

from neuralstrike.identity.signatures import verify_http_signature
from neuralstrike.utils.logging import get_logger

__all__ = ["A2ASpoofResult", "A2ASpoofScanner"]

logger = get_logger("neuralstrike.attacks.a2a.spoofing")


@dataclass(frozen=True)
class A2ASpoofResult:
    """Outcome of one spoofing attempt."""

    attempt: str
    accepted: bool
    evidence: str
    severity: str = "high"


@dataclass(frozen=True)
class A2ASpoofReport:
    """Aggregate report for a spoofing scan."""

    results: tuple[A2ASpoofResult, ...]
    raw_responses: tuple[dict[str, Any], ...] = field(default_factory=tuple)


class A2ASpoofScanner:
    """Run signed-message spoofing attempts against an A2A target."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        *,
        target_uri: str,
        valid_signature: str,
        valid_signature_input: str,
        public_key_pem: str,
    ) -> None:
        self.client = client
        self.target_uri = target_uri
        self.valid_signature = valid_signature
        self.valid_signature_input = valid_signature_input
        self.public_key_pem = public_key_pem

    async def scan(self) -> A2ASpoofReport:
        """Attempt a battery of bypasses and record the server response."""
        results: list[A2ASpoofResult] = []
        raw: list[dict[str, Any]] = []

        # 1. Missing signature entirely.
        resp = await self._send({})
        raw.append({"attempt": "missing_signature", "status": resp.status_code})
        accepted = resp.status_code < 400
        results.append(
            A2ASpoofResult(
                attempt="missing_signature",
                accepted=accepted,
                evidence=f"server returned {resp.status_code}",
                severity="critical" if accepted else "info",
            )
        )

        # 2. Algorithm confusion: declare alg=hmac-sha256 with an RSA signature.
        confused_input = self.valid_signature_input.replace('alg="rsa-v1_5-sha256"', 'alg="hmac-sha256"')
        resp = await self._send({"Signature": self.valid_signature, "Signature-Input": confused_input})
        raw.append({"attempt": "alg_confusion", "status": resp.status_code})
        accepted = resp.status_code < 400
        results.append(
            A2ASpoofResult(
                attempt="alg_confusion",
                accepted=accepted,
                evidence=f"server returned {resp.status_code} for alg confusion",
                severity="critical" if accepted else "info",
            )
        )

        # 3. Tampered body with valid signature (should fail verification locally).
        try:
            verify_http_signature(
                signature=self.valid_signature,
                signature_input=self.valid_signature_input,
                method="POST",
                target_uri=self.target_uri,
                headers={"content-type": "application/json"},
                body=b"tampered",
                public_key_pem=self.public_key_pem,
            )
            local_verdict = "verified"
        except Exception as exc:
            local_verdict = f"rejected: {exc}"
        resp = await self._send(
            {"Signature": self.valid_signature, "Signature-Input": self.valid_signature_input},
            body=b"tampered",
        )
        raw.append({"attempt": "tampered_body", "status": resp.status_code, "local_verdict": local_verdict})
        accepted = resp.status_code < 400
        results.append(
            A2ASpoofResult(
                attempt="tampered_body",
                accepted=accepted,
                evidence=f"server returned {resp.status_code}; local verify: {local_verdict}",
                severity="critical" if accepted else "info",
            )
        )

        return A2ASpoofReport(results=tuple(results), raw_responses=tuple(raw))

    async def _send(self, headers: dict[str, str], body: bytes = b"{}") -> httpx.Response:
        hdrs = {"content-type": "application/json"}
        hdrs.update(headers)
        try:
            return await self.client.post(self.target_uri, headers=hdrs, content=body)
        except httpx.HTTPError as exc:
            # Treat transport errors as a refusal (server did not accept).
            return httpx.Response(503, text=f"transport error: {exc}")
