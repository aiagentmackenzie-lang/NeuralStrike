"""The 18-codec evasion transform pipeline.

A *transform* rewrites an adversarial payload so a content filter that
pattern-matches the plain payload misses the encoded form. The pipeline is
**correct-by-construction**: every transform declares whether it is
lossless or lossy, and the :func:`winnability_guard` flags a lossy
transform whose round-trip destroyed the payload so a downstream
``Resisted`` verdict is not mistaken for defense (the probe is marked
``Inconclusive`` — a coverage gap — never a fabricated pass).

The 18 transforms: atbash, ascii_art, base64, binary, caesar,
emoji_braille, hex, homoglyph, json_wrap, leetspeak, markdown, morse,
nato, reversed, rot13, url, xml_wrap, zero_width.
"""

from __future__ import annotations

from neuralstrike.transforms import codecs  # noqa: F401 (registers all 18 via decorator)
from neuralstrike.transforms.base import (
    TRANSFORMS,
    Transform,
    TransformResult,
    apply_transform,
    get_transform,
    list_transforms,
    round_trip,
    winnability_guard,
)

__all__ = [
    "TRANSFORMS",
    "Transform",
    "TransformResult",
    "apply_transform",
    "get_transform",
    "list_transforms",
    "round_trip",
    "winnability_guard",
]


def assert_18_transforms() -> None:
    """Invariant: exactly 18 transforms are registered (the roadmap contract)."""
    names = list_transforms()
    assert len(names) == 18, (
        f"Phase-4 contract: 18 transforms; registered {len(names)}: {names}"
    )
