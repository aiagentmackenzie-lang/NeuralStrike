"""Real invisible-Unicode steganography — a hidden channel, not delimiter obfuscation.

The old ``EvasionSuite.steganographic_prompt`` was delimiter obfuscation
(``--- BEGIN SYSTEM OVERRIDE ---``), not steganography. This module is the
real thing: encode an arbitrary ASCII message into **invisible** Unicode
characters appended to a cover text, so the hidden payload is not visible
to a human (or a naive content filter) but is recoverable by a decoder.

Two invisible-Unicode encodings:

- **Tag-block** (U+E0000 - U+E007F): the Unicode tag block, defined as
  invisible formatting characters. ``chr(0xE0000 + ord(c))`` encodes one
  ASCII character as one invisible tag character. This is the EchoLeak
  class (CVE-2025-32711-style) - a hidden exfiltration channel.
- **Variation-selector** (U+FE00 - U+FE0F): 16 invisible variation
  selectors; encode 4 bits each, so two selectors per byte. More compact
  per-byte but a smaller alphabet.

``zero_width`` insertion (U+200B between visible chars) lives in the
:mod:`neuralstrike.transforms` pipeline as an obfuscation codec; it is
NOT a hidden channel. This module is the hidden channel.
"""

from __future__ import annotations

__all__ = [
    "TAG_BLOCK_BASE",
    "VARIATION_SELECTOR_BASE",
    "decode_tag_block",
    "decode_variation_selectors",
    "encode_tag_block",
    "encode_variation_selectors",
]

TAG_BLOCK_BASE = 0xE0000
"""Base of the Unicode tag block. ``chr(TAG_BLOCK_BASE + ord(c))`` is invisible."""

VARIATION_SELECTOR_BASE = 0xFE00
"""Base of the 16 Unicode variation selectors (U+FE00 - U+FE0F). 4 bits each."""


def encode_tag_block(cover: str, hidden: str) -> str:
    """Append ``hidden`` (ASCII) to ``cover`` as invisible tag-block characters.

    Only ASCII characters (0-127) are encodable in the tag block; non-ASCII
    characters in ``hidden`` raise ``ValueError`` so the channel never
    silently drops data.
    """
    for c in hidden:
        if ord(c) > 0x7F:
            raise ValueError(
                f"tag-block steganography encodes ASCII only; {c!r} (U+{ord(c):04X}) is out of range"
            )
    tags = "".join(chr(TAG_BLOCK_BASE + ord(c)) for c in hidden)
    return f"{cover}{tags}"


def decode_tag_block(text: str) -> str:
    """Recover the hidden ASCII message from ``text`` (the visible cover is skipped)."""
    return "".join(
        chr(ord(c) - TAG_BLOCK_BASE)
        for c in text
        if TAG_BLOCK_BASE <= ord(c) <= TAG_BLOCK_BASE + 0x7F
    )


def encode_variation_selectors(cover: str, hidden: str) -> str:
    """Append ``hidden`` (bytes) to ``cover`` as invisible variation selectors.

    Each byte becomes two variation selectors (high nibble, low nibble), so
    the hidden payload is 2x the byte length in invisible characters.
    """
    out = [cover]
    for b in hidden.encode("utf-8"):
        out.append(chr(VARIATION_SELECTOR_BASE + (b >> 4)))
        out.append(chr(VARIATION_SELECTOR_BASE + (b & 0x0F)))
    return "".join(out)


def decode_variation_selectors(text: str) -> bytes:
    """Recover the hidden bytes from variation selectors in ``text``."""
    nibbles: list[int] = []
    for c in text:
        o = ord(c)
        if VARIATION_SELECTOR_BASE <= o <= VARIATION_SELECTOR_BASE + 0x0F:
            nibbles.append(o - VARIATION_SELECTOR_BASE)
    if len(nibbles) % 2 != 0:
        # An odd count is a corrupted channel; drop the trailing nibble
        # rather than fabricate a byte.
        nibbles = nibbles[:-1]
    return bytes((nibbles[i] << 4) | nibbles[i + 1] for i in range(0, len(nibbles), 2))
