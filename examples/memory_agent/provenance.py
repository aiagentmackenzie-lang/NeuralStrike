"""Authenticated write path: signed write receipts and fail-closed verification.

Why this module exists
----------------------
v5 derived retrieval trust from a *declared* origin label stamped by the recording
store. That proves "the harness labelled this record", not "a principal with authority
to write user-authorised memory produced it". This module replaces the label with an
attestation whose authority is checkable independently of the writer: a principal
registry with a pinned policy digest, per-principal Ed25519 keys, a signed receipt over
the exact ``(principal, namespace, key, value, turn)`` tuple, and verification that runs
at the store boundary and fails closed.

What a valid receipt does **not** prove (stated here so it cannot be buried):

* A signature proves *the writer held a key*. It does not prove a human approved
  anything, and it does not prove the runtime that issued it was uncompromised.
* The "runtime" issuing receipts is simulated by this harness. There is no HSM, no key
  rotation, no revocation, no external identity provider, and no attestation of the
  runtime itself. Keys are generated per observation and never persisted.
* The policy digest is pinned as a constant in this repository, so it detects drift
  between a declared plan and the code that executed it. It does not defend a
  compromised repository.

Signature primitive
-------------------
A small RFC 8032 Ed25519 implementation is vendored below. It is here because the
isolated profile environment (``examples/memory_agent/requirements.txt``) is a frozen
hash-pinned lock that does not contain ``cryptography``, and changing that lock is out of
scope for this increment; the store boundary that must verify runs inside that
environment. The implementation is cross-checked against the official RFC 8032 test
vectors and against ``cryptography`` in ``tests/test_memory_agent.py``. A production
build should use a vetted library, not this file. Verification touches only public data;
signing is not constant-time and is used here for a synthetic runtime only.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

SCHEMA_VERSION = 1
# A receipt is accepted only inside this declared window around the verifier's clock.
WINDOW_SECONDS = 300
NONCE_BYTES = 16

PRINCIPAL_SESSION = "session_user"
PRINCIPAL_FIXTURE = "harness_fixture"
PRINCIPAL_UNTRUSTED = "external_untrusted"

PAYLOAD_FIELDS = (
    "principal",
    "namespace",
    "key",
    "content_sha256",
    "turn_sha256",
    "nonce",
    "issued_at",
)
RECEIPT_FIELDS = (*PAYLOAD_FIELDS, "signature")


# --------------------------------------------------------------------------------------
# Ed25519 (RFC 8032 §5.1). Reference implementation; see the module docstring for why.
# --------------------------------------------------------------------------------------

_FIELD = 2**255 - 19
_ORDER = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _FIELD - 2, _FIELD) % _FIELD
_SQRT_M1 = pow(2, (_FIELD - 1) // 4, _FIELD)
_Point = tuple[int, int, int, int]
_IDENTITY: _Point = (0, 1, 1, 0)


def _recover_x(y: int, sign: int) -> int | None:
    """Recover the x coordinate for y, or None when y is not on the curve."""
    if y >= _FIELD:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _FIELD - 2, _FIELD) % _FIELD
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_FIELD + 3) // 8, _FIELD)
    if (x * x - x2) % _FIELD:
        x = x * _SQRT_M1 % _FIELD
    if (x * x - x2) % _FIELD:
        return None
    if (x & 1) != sign:
        x = _FIELD - x
    return x


def _decode_point(data: bytes) -> _Point | None:
    if len(data) != 32:
        return None
    raw = int.from_bytes(data, "little")
    y = raw & ((1 << 255) - 1)
    x = _recover_x(y, raw >> 255)
    if x is None:
        return None
    return (x, y, 1, x * y % _FIELD)


def _encode_point(point: _Point) -> bytes:
    inverted = pow(point[2], _FIELD - 2, _FIELD)
    x = point[0] * inverted % _FIELD
    y = point[1] * inverted % _FIELD
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _point_add(left: _Point, right: _Point) -> _Point:
    a = (left[1] - left[0]) * (right[1] - right[0]) % _FIELD
    b = (left[1] + left[0]) * (right[1] + right[0]) % _FIELD
    c = 2 * left[3] * right[3] * _D % _FIELD
    d = 2 * left[2] * right[2] % _FIELD
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _FIELD, g * h % _FIELD, f * g % _FIELD, e * h % _FIELD)


def _point_mul(scalar: int, point: _Point) -> _Point:
    result = _IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    return result


def _base_point() -> _Point:
    y = 4 * pow(5, _FIELD - 2, _FIELD) % _FIELD
    x = _recover_x(y, 0)
    if x is None:  # pragma: no cover - the base point is on the curve by construction
        raise ValueError("ed25519 base point failed to decode")
    return (x, y, 1, x * y % _FIELD)


_BASE = _base_point()


def _expand_private_key(private_key: bytes) -> tuple[int, bytes]:
    if len(private_key) != 32:
        raise ValueError("ed25519 private key must be 32 bytes")
    digest = hashlib.sha512(private_key).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return scalar, digest[32:]


def public_key(private_key: bytes) -> bytes:
    """Raw 32-byte Ed25519 public key for a 32-byte seed."""
    scalar, _ = _expand_private_key(private_key)
    return _encode_point(_point_mul(scalar, _BASE))


def sign(private_key: bytes, message: bytes) -> bytes:
    """RFC 8032 §5.1.6 signature over ``message``."""
    scalar, prefix = _expand_private_key(private_key)
    encoded_public = public_key(private_key)
    nonce = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % _ORDER
    r = _encode_point(_point_mul(nonce, _BASE))
    challenge = int.from_bytes(hashlib.sha512(r + encoded_public + message).digest(), "little") % _ORDER
    return r + ((nonce + challenge * scalar) % _ORDER).to_bytes(32, "little")


def verify(encoded_public: bytes, message: bytes, signature: bytes) -> bool:
    """RFC 8032 §5.1.7 verification. Any malformed input is a verification failure."""
    if len(encoded_public) != 32 or len(signature) != 64:
        return False
    public = _decode_point(encoded_public)
    r = _decode_point(signature[:32])
    if public is None or r is None:
        return False
    scalar = int.from_bytes(signature[32:], "little")
    if scalar >= _ORDER:
        return False
    challenge = int.from_bytes(hashlib.sha512(signature[:32] + encoded_public + message).digest(), "little")
    challenge %= _ORDER
    expected = _point_add(r, _point_mul(challenge, public))
    return _encode_point(_point_mul(scalar, _BASE)) == _encode_point(expected)


# --------------------------------------------------------------------------------------
# Canonical encoding. Receipts are canonical JSON: sorted keys, no floats, no padding.
# --------------------------------------------------------------------------------------


def _has_float(value: Any) -> bool:
    if isinstance(value, float):
        return True
    if isinstance(value, Mapping):
        return any(_has_float(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_has_float(item) for item in value)
    return False


def canonical_bytes(value: Any) -> bytes:
    """Deterministic bytes for signing. Floats are rejected, not rounded."""
    if _has_float(value):
        raise ValueError("canonical JSON forbids floats")
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def value_digest(value: Any) -> str:
    """Digest of the whole record value, not just its ``content`` field.

    ``context`` reaches the model prompt too, so binding only ``content`` would leave a
    field the attacker could swap inside an otherwise validly signed write.
    """
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def turn_digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


# --------------------------------------------------------------------------------------
# Principal registry. Authority is a declared table; public keys are per observation.
# --------------------------------------------------------------------------------------

AuthorityTable = Mapping[str, Sequence[Sequence[str]]]


@dataclass(frozen=True)
class Registry:
    """Principal set, declared authority and the public keys receipts are checked against."""

    authority: dict[str, tuple[tuple[str, ...], ...]]
    public_keys: dict[str, bytes] = field(default_factory=dict)
    schema_version: int = SCHEMA_VERSION

    @property
    def policy_digest(self) -> str:
        return registry_policy_digest(self.authority)

    def covers(self, principal: str, namespace: Sequence[str]) -> bool:
        return tuple(str(part) for part in namespace) in self.authority.get(principal, ())

    def covers_key(self, principal: str, namespace: Sequence[str], key: str) -> bool:
        """Key-level binding. Keys are record identities, so any key in a covered namespace."""
        return self.covers(principal, namespace) and isinstance(key, str) and bool(key)


def registry_policy_digest(authority: AuthorityTable) -> str:
    """Digest of the declared authority table. Independent of the ephemeral keys."""
    table = {
        principal: [list(namespace) for namespace in namespaces]
        for principal, namespaces in authority.items()
    }
    return hashlib.sha256(canonical_bytes({"authority": table, "schema_version": SCHEMA_VERSION})).hexdigest()


def build_registry(authority: AuthorityTable, public_keys: Mapping[str, bytes] | None = None) -> Registry:
    declared = {
        str(principal): tuple(tuple(str(part) for part in namespace) for namespace in namespaces)
        for principal, namespaces in authority.items()
    }
    return Registry(authority=declared, public_keys=dict(public_keys or {}))


def principal_for_write(*, attested: bool) -> str:
    """Principal a conversation-turn write is attributed to, decided by the turn handler."""
    return PRINCIPAL_SESSION if attested else PRINCIPAL_UNTRUSTED


def derive_private_key(principal: str) -> bytes:
    """Deterministic per-principal key material for scripted checks. Never used in a cycle."""
    return hashlib.sha256(f"scripted-principal-key:{principal}".encode()).digest()


class Ed25519Signer:
    """One principal's key. It can claim any payload; only the key it holds is proven."""

    def __init__(self, private_key: bytes) -> None:
        self._private = private_key

    @property
    def public_key(self) -> bytes:
        return public_key(self._private)

    def sign_receipt(
        self,
        *,
        principal: str,
        namespace: Sequence[str],
        key: str,
        value: Any,
        turn_sha256: str | None = None,
        nonce: str | None = None,
        issued_at: int | None = None,
    ) -> dict[str, Any]:
        payload = build_receipt_payload(
            principal=principal,
            namespace=namespace,
            key=key,
            value=value,
            turn_sha256=turn_sha256,
            nonce=nonce,
            issued_at=issued_at,
        )
        return {**payload, "signature": sign(self._private, canonical_bytes(payload)).hex()}


def build_receipt_payload(
    *,
    principal: str,
    namespace: Sequence[str],
    key: str,
    value: Any,
    turn_sha256: str | None = None,
    nonce: str | None = None,
    issued_at: int | None = None,
) -> dict[str, Any]:
    return {
        "principal": str(principal),
        "namespace": [str(part) for part in namespace],
        "key": str(key),
        "content_sha256": value_digest(value),
        "turn_sha256": turn_sha256,
        "nonce": nonce if nonce is not None else secrets.token_hex(NONCE_BYTES),
        "issued_at": int(issued_at if issued_at is not None else time.time()),
    }


class AttestationAuthority:
    """The simulated runtime: holds every principal key and refuses to sign out of scope.

    This object is what a real deployment would replace with the authenticated turn
    handler and tool dispatcher. It is deliberately *not* the thing that decides
    retrieval trust: the store re-verifies everything it is handed.
    """

    def __init__(
        self,
        registry: Registry,
        private_keys: Mapping[str, bytes],
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.registry = registry
        self._private = dict(private_keys)
        self._clock = clock

    @classmethod
    def generate(
        cls,
        authority: AuthorityTable,
        *,
        clock: Callable[[], float] = time.time,
        key_seed: Callable[[str], bytes] | None = None,
    ) -> AttestationAuthority:
        seed = key_seed or (lambda _principal: secrets.token_bytes(32))
        private_keys = {principal: seed(principal) for principal in sorted(authority)}
        registry = build_registry(authority, {name: public_key(raw) for name, raw in private_keys.items()})
        return cls(registry, private_keys, clock=clock)

    def now(self) -> int:
        return int(self._clock())

    def issue(
        self,
        principal: str,
        namespace: Sequence[str],
        key: str,
        value: Any,
        *,
        turn_sha256: str | None = None,
    ) -> dict[str, Any] | None:
        """Sign for ``principal`` only when the declared authority covers the write.

        A principal with no authority over the namespace gets ``None``: the runtime will
        not mint a receipt the store would have to reject, and an untrusted principal can
        never obtain a session receipt from it.
        """
        if principal not in self._private or not self.registry.covers_key(principal, namespace, key):
            return None
        turn = turn_sha256 if principal == PRINCIPAL_SESSION else None
        return Ed25519Signer(self._private[principal]).sign_receipt(
            principal=principal,
            namespace=namespace,
            key=key,
            value=value,
            turn_sha256=turn,
            issued_at=self.now(),
        )

    def issue_for_write(
        self,
        namespace: Sequence[str],
        key: str,
        value: Any,
        *,
        principal: str,
        turn_sha256: str | None,
    ) -> dict[str, Any] | None:
        return self.issue(principal, namespace, key, value, turn_sha256=turn_sha256)


def principal_registry_document(registry: Registry) -> dict[str, Any]:
    """What the observation records: the declared authority and public keys, never seeds."""
    return {
        "schema_version": registry.schema_version,
        "policy_digest": registry.policy_digest,
        "authority": {
            principal: [list(namespace) for namespace in namespaces]
            for principal, namespaces in sorted(registry.authority.items())
        },
        "public_keys": {
            principal: encoded.hex() for principal, encoded in sorted(registry.public_keys.items())
        },
    }


# --------------------------------------------------------------------------------------
# Verification at the store boundary. Every check fails closed.
# --------------------------------------------------------------------------------------

_HEX = set("0123456789abcdef")


def _is_hex(value: Any, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and set(value.lower()) <= _HEX


def _fields_ok(attestation: Any) -> bool:
    if not isinstance(attestation, Mapping):
        return False
    if set(attestation) != set(RECEIPT_FIELDS):
        return False
    namespace = attestation.get("namespace")
    return (
        isinstance(attestation.get("principal"), str)
        and isinstance(namespace, list)
        and bool(namespace)
        and all(isinstance(part, str) for part in namespace)
        and isinstance(attestation.get("key"), str)
        and _is_hex(attestation.get("content_sha256"), 64)
        and (attestation.get("turn_sha256") is None or _is_hex(attestation.get("turn_sha256"), 64))
        and isinstance(attestation.get("nonce"), str)
        and len(attestation.get("nonce") or "") >= NONCE_BYTES * 2
        and isinstance(attestation.get("issued_at"), int)
        and not isinstance(attestation.get("issued_at"), bool)
        and _is_hex(attestation.get("signature"), 128)
    )


def _payload(attestation: Mapping[str, Any]) -> dict[str, Any]:
    return {name: attestation[name] for name in PAYLOAD_FIELDS}


def _signature_ok(attestation: Any, registry: Registry) -> bool:
    if not _fields_ok(attestation):
        return False
    encoded = registry.public_keys.get(str(attestation["principal"]))
    if encoded is None:
        return False
    return verify(encoded, canonical_bytes(_payload(attestation)), bytes.fromhex(attestation["signature"]))


@dataclass(frozen=True)
class Verdict:
    """Outcome of one verification. ``reason`` names the first failed check, or None."""

    verified: bool
    reason: str | None
    principal: str | None
    receipt_sha256: str | None


def _claimed(attestation: Any, name: str) -> Any:
    return attestation.get(name) if isinstance(attestation, Mapping) else None


def verify_write(
    attestation: Mapping[str, Any] | None,
    *,
    namespace: Sequence[str],
    key: str,
    value: Any,
    registry: Registry,
    pinned_registry_digest: str,
    used_nonces: Iterable[str],
    active_turn_sha256: str | None,
    now: int,
    window_seconds: int = WINDOW_SECONDS,
) -> Verdict:
    """All checks, in declared order, fail closed.

    Order matters only for which reason is reported first; every check must pass.
    """
    fields = _fields_ok(attestation)
    principal = str(_claimed(attestation, "principal")) if fields else None
    claimed_namespace = [str(part) for part in _claimed(attestation, "namespace") or []] if fields else []
    claimed_turn = _claimed(attestation, "turn_sha256") if fields else None
    session = principal == PRINCIPAL_SESSION
    checks = [
        # Nothing below can be evaluated without a well-formed receipt, so those two come
        # first; the pin is checked next, before any key or binding is consulted.
        (attestation is not None, "attestation_absent"),
        (fields, "attestation_malformed"),
        (registry.policy_digest == pinned_registry_digest, "registry_digest_mismatch"),
        (principal in registry.authority, "principal_unregistered"),
        (principal is not None and principal in registry.public_keys, "principal_key_not_pinned"),
        (_signature_ok(attestation, registry), "signature_invalid"),
        (principal is not None and registry.covers_key(principal, namespace, key),
         "principal_has_no_write_authority"),
        (claimed_namespace == [str(part) for part in namespace], "namespace_mismatch"),
        (_claimed(attestation, "key") == key, "key_mismatch"),
        (_claimed(attestation, "content_sha256") == value_digest(value), "content_sha256_mismatch"),
        (not session or (isinstance(active_turn_sha256, str) and claimed_turn == active_turn_sha256),
         "turn_sha256_mismatch"),
        (session or claimed_turn is None, "unexpected_turn_binding"),
        (_claimed(attestation, "nonce") not in set(used_nonces), "nonce_replayed"),
        (isinstance(_claimed(attestation, "issued_at"), int)
         and abs(now - int(_claimed(attestation, "issued_at"))) <= window_seconds,
         "issued_at_outside_window"),
    ]
    failures = [reason for passed, reason in checks if not passed]
    return Verdict(
        verified=not failures,
        reason=failures[0] if failures else None,
        principal=principal,
        receipt_sha256=hashlib.sha256(canonical_bytes(attestation)).hexdigest() if fields else None,
    )


__all__ = [
    "PRINCIPAL_FIXTURE",
    "PRINCIPAL_SESSION",
    "PRINCIPAL_UNTRUSTED",
    "WINDOW_SECONDS",
    "AttestationAuthority",
    "Ed25519Signer",
    "Registry",
    "Verdict",
    "build_receipt_payload",
    "build_registry",
    "canonical_bytes",
    "derive_private_key",
    "principal_for_write",
    "principal_registry_document",
    "public_key",
    "registry_policy_digest",
    "sign",
    "turn_digest",
    "value_digest",
    "verify",
    "verify_write",
]
