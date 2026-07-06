"""did:web / did:key resolution (consume published DID documents).

NeuralStrike does not maintain a DID registry; it fetches and parses DID
documents so A2A signature verification can materialize the public key.
"""

from __future__ import annotations

import base64
import contextlib
import json
from dataclasses import dataclass
from typing import Any

import httpx

from neuralstrike.identity.base import KeyResolution, KeyResolutionSource, VerifiedKey
from neuralstrike.utils.logging import get_logger

__all__ = ["DIDResolver", "resolve_did"]

logger = get_logger("neuralstrike.identity.did")


@dataclass(frozen=True)
class DIDResolver:
    """Resolve a DID to its verification methods and public keys."""

    transport: httpx.AsyncClient | None = None
    timeout: float = 30.0

    async def resolve(self, did: str) -> KeyResolution:
        """Resolve ``did:web:<domain>:<path>`` or ``did:key:<multibase>``."""
        if did.startswith("did:web:"):
            return await self._resolve_web(did)
        if did.startswith("did:key:"):
            return self._resolve_key(did)
        return KeyResolution(
            subject=did,
            keys=(),
            source="inline",
            warnings=(f"unsupported DID method in {did!r}",),
        )

    async def _resolve_web(self, did: str) -> KeyResolution:
        # did:web:example.com:path:more -> https://example.com/path/more/did.json
        rest = did[len("did:web:"):]
        parts = rest.split(":")
        domain = parts[0]
        path = "/".join(parts[1:]) if len(parts) > 1 else ""
        url = f"https://{domain}/{path}/did.json" if path else f"https://{domain}/.well-known/did.json"
        client = self.transport or httpx.AsyncClient(timeout=self.timeout)
        try:
            resp = await client.get(url)
            resp.raise_for_status()
            doc = resp.json()
        except (httpx.HTTPError, json.JSONDecodeError) as exc:
            return KeyResolution(
                subject=did,
                keys=(),
                source="resolver",
                resolver_url=url,
                warnings=(f"could not resolve {did!r}: {exc}",),
            )
        finally:
            if self.transport is None:
                await client.aclose()
        return self._doc_to_resolution(did, doc, source="resolver", resolver_url=url)

    def _resolve_key(self, did: str) -> KeyResolution:
        """Resolve a ``did:key`` by decoding the multibase public key.

        Only ed25519-pub (multicodec 0xed01) is supported for Phase 5.
        """
        multibase = did[len("did:key:"):]
        if not multibase:
            return KeyResolution(
                subject=did,
                keys=(),
                source="inline",
                warnings=("empty did:key multibase",),
            )
        # did:key uses base58btc ('z' prefix). We do not pull a multibase
        # library; for the exit gate we rely on tests providing well-known keys.
        with contextlib.suppress(ImportError):
            import base58  # type: ignore[import-not-found]
            try:
                raw = base58.b58decode(multibase)
            except Exception as exc:
                return KeyResolution(
                    subject=did,
                    keys=(),
                    source="inline",
                    warnings=(f"could not decode did:key multibase: {exc}",),
                )
            if len(raw) >= 2 and raw[:2] == b"\xed\x01":
                public_key_bytes = raw[2:]
                x_b64 = base64.urlsafe_b64encode(public_key_bytes).decode("ascii").rstrip("=")
                return KeyResolution(
                    subject=did,
                    keys=(
                        VerifiedKey(
                            key_id=did,
                            algorithm="Ed25519",
                            public_key_bytes=public_key_bytes,
                            raw_jwk={"kty": "OKP", "crv": "Ed25519", "x": x_b64},
                            source="inline",
                        ),
                    ),
                    source="inline",
                )
            return KeyResolution(
                subject=did,
                keys=(),
                source="inline",
                warnings=("did:key is not an ed25519 public key (0xed01)",),
            )
        logger.warning("base58 not installed; did:key resolution limited")
        return KeyResolution(
            subject=did,
            keys=(),
            source="inline",
            warnings=("base58 dependency missing for did:key",),
        )

    def _doc_to_resolution(
        self,
        did: str,
        doc: dict[str, Any],
        *,
        source: KeyResolutionSource,
        resolver_url: str | None = None,
    ) -> KeyResolution:
        methods = doc.get("verificationMethod") or []
        keys: list[VerifiedKey] = []
        for m in methods:
            if not isinstance(m, dict):
                continue
            kid = str(m.get("id", ""))
            jwk = m.get("publicKeyJwk")
            if isinstance(jwk, dict):
                keys.append(
                    VerifiedKey(
                        key_id=kid,
                        algorithm=str(jwk.get("kty", "")),
                        raw_jwk=jwk,
                        source=source,
                        resolver_url=resolver_url,
                    )
                )
            elif isinstance(m.get("publicKeyPem"), str):
                keys.append(
                    VerifiedKey(
                        key_id=kid,
                        algorithm=str(m.get("type", "")),
                        public_key_pem=m["publicKeyPem"],
                        source=source,
                        resolver_url=resolver_url,
                    )
                )
        return KeyResolution(subject=did, keys=tuple(keys), source=source, resolver_url=resolver_url)


async def resolve_did(did: str, *, timeout: float = 30.0) -> KeyResolution:
    """Convenience: resolve ``did`` with a fresh resolver."""
    resolver = DIDResolver(timeout=timeout)
    return await resolver.resolve(did)
