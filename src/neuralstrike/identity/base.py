"""Identity-verification abstractions (consume, not re-implement)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

__all__ = ["KeyResolution", "KeyResolver", "VerifiedKey"]

KeyResolutionSource = Literal["inline", "cache", "resolver"]
"""Where a key was resolved from, per A2A WG convergence terminology."""


class KeyResolver(Protocol):
    """Protocol for an identity resolver that materializes keys."""

    async def resolve(self, subject: str) -> KeyResolution: ...


@dataclass(frozen=True)
class VerifiedKey:
    """A public key materialized from a DID / SVID / WIT / JWS."""

    key_id: str
    algorithm: str
    public_key_pem: str | None = None
    public_key_bytes: bytes = b""
    raw_jwk: dict[str, Any] = field(default_factory=dict)
    source: KeyResolutionSource = "inline"
    resolver_url: str | None = None


@dataclass(frozen=True)
class KeyResolution:
    """Result of resolving an agent identity to its key material."""

    subject: str
    keys: tuple[VerifiedKey, ...]
    source: KeyResolutionSource
    resolver_url: str | None = None
    warnings: tuple[str, ...] = field(default_factory=tuple)
