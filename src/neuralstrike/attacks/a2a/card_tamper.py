"""A2A Agent Card tampering detection (Phase 5).

Fetches an Agent Card, verifies its JWS signature using the key material
resolved from the card's declared ``did`` or an inline public key, and
detects tampering by re-verifying after a mutation.

Per Decision D4, Phase 5 lands the full RFC 7515 JWS + RFC 8785 JCS
canonicalization layer. This module consumes
:func:`neuralstrike.identity.jws.verify_compact_jws` and
:func:`neuralstrike.identity.canonicalize`.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any

import httpx

from neuralstrike.identity import DIDResolver, JWSVerifyError, KeyResolution, resolve_did, verify_compact_jws
from neuralstrike.utils.logging import get_logger

__all__ = ["A2ACardTamperResult", "A2ACardTamperScanner"]

logger = get_logger("neuralstrike.attacks.a2a.card_tamper")


@dataclass(frozen=True)
class A2ACardTamperResult:
    """Outcome of verifying an Agent Card + a tampered copy."""

    url: str
    signature_valid: bool
    tampered_card_rejected: bool
    issuer_did: str | None
    key_resolution_warnings: tuple[str, ...]
    evidence: str
    raw_card: dict[str, Any] = field(default_factory=dict)


class A2ACardTamperScanner:
    """Fetch an Agent Card, verify its signature, and test tamper detection."""

    def __init__(
        self,
        *,
        base_url: str,
        client: httpx.AsyncClient | None = None,
        resolver: DIDResolver | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._client = client
        self._resolver = resolver

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient()
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def scan(self) -> A2ACardTamperResult:
        """Fetch the card, verify JWS, and test tampering."""
        url = f"{self.base_url}/.well-known/agent-card.json"
        try:
            resp = await self.client.get(url)
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            return A2ACardTamperResult(
                url=url,
                signature_valid=False,
                tampered_card_rejected=False,
                issuer_did=None,
                key_resolution_warnings=(f"could not fetch card: {exc}",),
                evidence=f"card fetch failed: {exc}",
            )

        if not isinstance(data, dict):
            return A2ACardTamperResult(
                url=url,
                signature_valid=False,
                tampered_card_rejected=False,
                issuer_did=None,
                key_resolution_warnings=("card is not a JSON object",),
                evidence=f"card is not a JSON object: {data!r}",
            )

        jws = data.get("signature")
        issuer_did = data.get("issuerDID") or data.get("issuer")
        public_key_pem = self._extract_public_key_pem(data)

        signature_valid = False
        key_warnings: tuple[str, ...] = ()
        if jws and isinstance(jws, str):
            if public_key_pem:
                signature_valid = self._verify_with_pem(jws, public_key_pem)
            elif issuer_did:
                signature_valid, key_warnings = await self._verify_with_did(jws, issuer_did)

        tampered_rejected = False
        if signature_valid and jws:
            tampered_jws = self._tamper_jws_payload(jws)
            try:
                if public_key_pem:
                    verify_compact_jws(tampered_jws, public_key_pem=public_key_pem)
                    tampered_rejected = False
                elif issuer_did:
                    resolution = await resolve_did(issuer_did)
                    pem = self._key_pem_from_resolution(resolution)
                    if pem:
                        verify_compact_jws(tampered_jws, public_key_pem=pem)
                        tampered_rejected = False
            except JWSVerifyError:
                tampered_rejected = True

        evidence = f"signature_valid={signature_valid}, tampered_rejected={tampered_rejected}"
        return A2ACardTamperResult(
            url=url,
            signature_valid=signature_valid,
            tampered_card_rejected=tampered_rejected,
            issuer_did=issuer_did,
            key_resolution_warnings=key_warnings,
            evidence=evidence,
            raw_card=data,
        )

    def _extract_public_key_pem(self, card: dict[str, Any]) -> str | None:
        methods = card.get("verificationMethod") or []
        if not isinstance(methods, list):
            return None
        for m in methods:
            if isinstance(m, dict):
                pem = m.get("publicKeyPem")
                if isinstance(pem, str):
                    return pem
        return None

    def _verify_with_pem(self, jws: str, pem: str) -> bool:
        try:
            verify_compact_jws(jws, public_key_pem=pem)
        except JWSVerifyError as exc:
            logger.warning("Agent Card JWS verification failed: %s", exc)
            return False
        return True

    async def _verify_with_did(self, jws: str, did: str) -> tuple[bool, tuple[str, ...]]:
        resolver = self._resolver or DIDResolver()
        resolution = await resolver.resolve(did)
        pem = self._key_pem_from_resolution(resolution)
        if pem is None:
            return False, resolution.warnings
        return self._verify_with_pem(jws, pem), resolution.warnings

    @staticmethod
    def _key_pem_from_resolution(resolution: KeyResolution) -> str | None:
        for key in resolution.keys:
            if key.public_key_pem:
                return key.public_key_pem
        return None

    @staticmethod
    def _tamper_jws_payload(jws: str) -> str:
        """Return a JWS whose payload has been mutated (name changed)."""
        parts = jws.split(".")
        if len(parts) != 3:
            return jws
        try:
            payload_json = base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
            payload = json.loads(payload_json)
        except Exception:
            return jws
        payload["name"] = f"{payload.get('name', 'card')}-tampered"
        canonical = json.dumps(payload, separators=(",", ":")).encode()
        new_payload_b64 = base64.urlsafe_b64encode(canonical).decode().rstrip("=")
        return f"{parts[0]}.{new_payload_b64}.{parts[2]}"
