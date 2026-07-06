"""Agent-identity awareness for NeuralStrike (Phase 5).

This package **consumes** identity standards; it does not implement an IdP.
Its purpose is to let NeuralStrike test identity-defended targets by
resolving keys and verifying signatures, not to issue credentials.

Supported surfaces:
- ``did:web`` / ``did:key`` resolution (consume published DID documents).
- SPIFFE/SPIRE SVIDs and WIMSE WITs (parse + verify chain shape).
- RFC 9421 HTTP Message Signatures verification.
- RFC 8785 JCS canonicalization (used by A2A JWS signing tests).
- OAuth 2.0 agent-identity token awareness (IETF draft-klrc-aiagent-auth).
"""

from __future__ import annotations

from neuralstrike.identity.base import KeyResolution, KeyResolver, VerifiedKey
from neuralstrike.identity.did import DIDResolver, resolve_did
from neuralstrike.identity.jcs import canonicalize
from neuralstrike.identity.jws import JWSVerifyError, verify_compact_jws
from neuralstrike.identity.signatures import HTTPMessageSignatureError, verify_http_signature

__all__ = [
    "DIDResolver",
    "HTTPMessageSignatureError",
    "JWSVerifyError",
    "KeyResolution",
    "KeyResolver",
    "VerifiedKey",
    "canonicalize",
    "resolve_did",
    "verify_compact_jws",
    "verify_http_signature",
]
