"""RFC 7515 JSON Web Signature verification using stdlib + cryptography.

NeuralStrike tests identity-defended targets; verifying a signed Agent Card
or inter-agent message is part of that testing surface. We consume JWS,
not issue it.

Supported algorithms for Phase 5:
- HS256 (HMAC-SHA256) — stdlib-only; used in tests with shared secrets.
- RS256 (RSA-PSS removed; RS256 is RSA-PKCS1-v1.5 + SHA-256) and ES256
  (ECDSA P-256 + SHA-256) via cryptography.

All verification uses RFC 8785 JCS canonicalization of the payload when
``canonicalize_payload=True`` (A2A default).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any, cast

from neuralstrike.identity.jcs import canonicalize

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding
except ImportError:  # pragma: no cover
    hashes = None  # type: ignore[assignment]
    serialization = None  # type: ignore[assignment]
    ec = None  # type: ignore[assignment]
    padding = None  # type: ignore[assignment]

__all__ = ["JWSVerifyError", "verify_compact_jws"]


class JWSVerifyError(Exception):
    """Raised when a JWS compact signature fails verification."""


def _b64url_decode(s: str) -> bytes:
    """URL-safe base64 decode with padding tolerance."""
    pad = "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s + pad)
    except Exception as exc:
        raise JWSVerifyError(f"invalid base64url segment: {exc}") from exc


def _parse_protected_header(protected_b64: str) -> dict[str, Any]:
    raw = _b64url_decode(protected_b64)
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise JWSVerifyError(f"protected header is not valid JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise JWSVerifyError("protected header is not a JSON object")
    return obj


def verify_compact_jws(
    jws: str,
    *,
    key: bytes | str | None = None,
    public_key_pem: str | None = None,
    canonicalize_payload: bool = True,
) -> tuple[dict[str, Any], bytes]:
    """Verify a compact JWS and return ``(protected_header, payload_bytes)``.

    ``key`` for HS256 is the shared secret (str or bytes).
    ``public_key_pem`` for RS256/ES256 is the PEM-encoded public key.
    """
    if not isinstance(jws, str):
        raise JWSVerifyError("JWS must be a string")
    parts = jws.split(".")
    if len(parts) != 3:
        raise JWSVerifyError(f"JWS must have 3 segments, got {len(parts)}")

    protected_b64, payload_b64, signature_b64 = parts
    header = _parse_protected_header(protected_b64)
    alg = header.get("alg")
    if not isinstance(alg, str):
        raise JWSVerifyError("JWS header missing 'alg'")

    try:
        payload_bytes = _b64url_decode(payload_b64)
    except JWSVerifyError as exc:
        raise JWSVerifyError(f"payload decode failed: {exc}") from exc

    if canonicalize_payload:
        # A2A payloads are JSON objects; re-canonicalize before verifying.
        try:
            payload_obj = json.loads(payload_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise JWSVerifyError(f"payload is not canonicalizable JSON: {exc}") from exc
        payload_bytes = canonicalize(payload_obj).encode()

    signing_input = f"{protected_b64}.{payload_b64}".encode()
    signature = _b64url_decode(signature_b64)

    if alg == "HS256":
        if key is None:
            raise JWSVerifyError("HS256 requires a shared secret key")
        secret = key.encode("utf-8") if isinstance(key, str) else key
        expected = hmac.new(secret, signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, signature):
            raise JWSVerifyError("HS256 signature mismatch")
        return header, payload_bytes

    if alg in ("RS256", "ES256"):
        if public_key_pem is None:
            raise JWSVerifyError(f"{alg} requires a PEM public key")
        return _verify_asymmetric(alg, signing_input, signature, public_key_pem), payload_bytes

    raise JWSVerifyError(f"unsupported JWS algorithm: {alg}")


def _verify_asymmetric(
    alg: str, signing_input: bytes, signature: bytes, public_key_pem: str
) -> dict[str, Any]:
    if serialization is None or hashes is None or padding is None or ec is None:
        raise JWSVerifyError(f"cryptography is required for {alg}")

    try:
        public_key = cast(Any, serialization.load_pem_public_key(public_key_pem.encode()))
    except Exception as exc:
        raise JWSVerifyError(f"could not load PEM public key: {exc}") from exc

    if alg == "RS256":
        try:
            public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
        except Exception as exc:
            raise JWSVerifyError(f"RS256 signature mismatch: {exc}") from exc
        return {"alg": alg}

    if alg == "ES256":
        if not hasattr(public_key, "verify"):
            raise JWSVerifyError("loaded key is not a verify-capable asymmetric key")
        # JWS ECDSA signatures are raw r||s, each curve-size bytes.
        try:
            public_key.verify(signature, signing_input, ec.ECDSA(hashes.SHA256()))
        except Exception as exc:
            raise JWSVerifyError(f"ES256 signature mismatch: {exc}") from exc
        return {"alg": alg}

    raise JWSVerifyError(f"unsupported JWS algorithm: {alg}")
