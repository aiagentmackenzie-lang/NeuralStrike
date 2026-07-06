"""RFC 9421 HTTP Message Signatures — minimal verifier.

NeuralStrike tests identity-defended A2A targets. This module verifies
that a request's ``Signature-Input`` and ``Signature`` headers match a
provided public key. It does not sign requests (consume, not re-implement).

Supported algorithms:
- rsa-v1_5-sha256 / rsa-pss-sha512 via cryptography.
- ed25519 via cryptography (if installed).
- hmac-sha256 via stdlib.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from typing import Any

import httpx

from neuralstrike.utils.logging import get_logger

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
except ImportError:  # pragma: no cover
    hashes = None  # type: ignore[assignment]
    serialization = None  # type: ignore[assignment]
    padding = None  # type: ignore[assignment]

__all__ = ["HTTPMessageSignatureError", "verify_http_signature"]

logger = get_logger("neuralstrike.identity.signatures")


class HTTPMessageSignatureError(Exception):
    """Raised when an HTTP Message Signature fails verification."""


def _derive_component(
    component: str,
    *,
    method: str,
    target_uri: str,
    headers: dict[str, str],
    body: bytes,
) -> str:
    """Return the value of a covered component per RFC 9421."""
    url = httpx.URL(target_uri)
    if component == "@status":
        raise HTTPMessageSignatureError("@status only valid for response signatures")

    result = ""
    if component == "@method":
        result = method.upper()
    elif component == "@target-uri":
        result = target_uri
    elif component == "@authority":
        result = url.netloc.decode("ascii")
    elif component == "@path":
        result = url.path
    elif component == "@query":
        q = url.query
        result = q.decode("ascii") if q else ""
    elif component == "@scheme":
        result = url.scheme
    elif component == "@request-target":
        path = url.path or "/"
        result = f"{method.lower()} {path}"
    else:
        # Header field; RFC 9421 lower-cases names and joins repeated values.
        result = headers.get(component.lower(), "")
    return result


def _build_signature_base(
    signature_input: str,
    *,
    method: str,
    target_uri: str,
    headers: dict[str, str],
    body: bytes,
) -> bytes:
    """Reconstruct the signature-base string from Signature-Input."""
    eq = signature_input.find("=")
    if eq == -1:
        raise HTTPMessageSignatureError("Signature-Input missing '='")
    params = signature_input[eq + 1:].strip()
    if not params.startswith("("):
        raise HTTPMessageSignatureError("Signature-Input missing covered component list")
    close = params.find(")")
    if close == -1:
        raise HTTPMessageSignatureError("Signature-Input missing closing ')'")
    components_part = params[1:close].strip()
    components: list[str] = []
    current = ""
    in_string = False
    for ch in components_part:
        if ch == '"':
            in_string = not in_string
            current += ch
        elif ch == ";" and not in_string:
            components.append(current.strip().strip('"'))
            current = ""
        else:
            current += ch
    if current.strip():
        components.append(current.strip().strip('"'))

    lines: list[str] = []
    for c in components:
        val = _derive_component(c, method=method, target_uri=target_uri, headers=headers, body=body)
        lines.append(f'"{c}": {val}')

    sig_params = params[close + 1:].strip()
    if sig_params.startswith(";"):
        sig_params = sig_params[1:].strip()
    normalized_components = "; ".join(f'"{c}"' for c in components)
    lines.append(f'"@signature-params": ({normalized_components});{sig_params}')
    return "\n".join(lines).encode("utf-8")


def _extract_alg(signature_input: str) -> str:
    """Extract ``alg="..."`` from the signature-input parameters."""
    m = re.search(r'alg="([^"]+)"', signature_input)
    if m:
        return m.group(1)
    return "hmac-sha256"  # default per draft


def _load_public_key(public_key_pem: str) -> Any:
    if serialization is None:
        raise HTTPMessageSignatureError("cryptography is required for asymmetric signature verification")
    try:
        return serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    except Exception as exc:
        raise HTTPMessageSignatureError(f"could not load PEM public key: {exc}") from exc


def verify_http_signature(
    *,
    signature: str,
    signature_input: str,
    method: str,
    target_uri: str,
    headers: dict[str, str],
    body: bytes = b"",
    key: bytes | str | None = None,
    public_key_pem: str | None = None,
) -> dict[str, Any]:
    """Verify an RFC 9421 HTTP Message Signature.

    Returns the parsed signature parameters on success; raises
    :class:`HTTPMessageSignatureError` on failure.
    """
    sig_bytes = base64.standard_b64decode(signature)
    base = _build_signature_base(
        signature_input,
        method=method,
        target_uri=target_uri,
        headers=headers,
        body=body,
    )

    alg = _extract_alg(signature_input)
    if alg == "hmac-sha256":
        if key is None:
            raise HTTPMessageSignatureError("hmac-sha256 requires a shared key")
        secret = key.encode("utf-8") if isinstance(key, str) else key
        expected = hmac.new(secret, base, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, sig_bytes):
            raise HTTPMessageSignatureError("hmac-sha256 signature mismatch")
        return {"alg": alg}

    if alg in ("rsa-v1_5-sha256", "rsa-pss-sha512", "ed25519"):
        if public_key_pem is None:
            raise HTTPMessageSignatureError(f"{alg} requires a PEM public key")
        public_key = _load_public_key(public_key_pem)
        if alg == "rsa-v1_5-sha256":
            if padding is None or hashes is None:
                raise HTTPMessageSignatureError("cryptography primitives missing")
            public_key.verify(sig_bytes, base, padding.PKCS1v15(), hashes.SHA256())
            return {"alg": alg}
        if alg == "rsa-pss-sha512":
            if padding is None or hashes is None:
                raise HTTPMessageSignatureError("cryptography primitives missing")
            mgf = padding.MGF1(hashes.SHA512())
            pss_padding = padding.PSS(mgf=mgf, salt_length=padding.PSS.MAX_LENGTH)
            public_key.verify(sig_bytes, base, pss_padding, hashes.SHA512())
            return {"alg": alg}
        if alg == "ed25519":
            public_key.verify(sig_bytes, base)
            return {"alg": alg}

    raise HTTPMessageSignatureError(f"unsupported HTTP signature algorithm: {alg}")
