"""The 18-codec evasion transform pipeline.

Each transform is a :class:`~neuralstrike.transforms.base.Transform`
subclass registered via :func:`register_transform`. Lossless transforms
round-trip exactly (``decode(encode(x)) == x``); lossy transforms carry a
:func:`~neuralstrike.transforms.base.winnability_guard` so a destroyed
payload is surfaced as ``Inconclusive`` (a coverage gap), never a
fabricated ``Resisted``.

The 18 transforms (alphabetical):
atbash, ascii_art, base64, binary, caesar, emoji_braille, hex, homoglyph,
json_wrap, leetspeak, markdown, morse, nato, reversed, rot13, url,
xml_wrap, zero_width.
"""

from __future__ import annotations

import base64 as _b64
import codecs as _codecs
import json as _json
import urllib.parse as _url

from neuralstrike.transforms.base import Transform, register_transform

# --- Morse + NATO tables ----------------------------------------------------

MORSE: dict[str, str] = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.",
    "G": "--.", "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..",
    "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.",
    "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-",
    "Y": "-.--", "Z": "--..",
    "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-",
    "5": ".....", "6": "-....", "7": "--...", "8": "---..", "9": "----.",
    " ": "/",
}
MORSE_REV: dict[str, str] = {v: k for k, v in MORSE.items()}

NATO: dict[str, str] = {
    "A": "Alpha", "B": "Bravo", "C": "Charlie", "D": "Delta", "E": "Echo",
    "F": "Foxtrot", "G": "Golf", "H": "Hotel", "I": "India", "J": "Juliett",
    "K": "Kilo", "L": "Lima", "M": "Mike", "N": "November", "O": "Oscar",
    "P": "Papa", "Q": "Quebec", "R": "Romeo", "S": "Sierra", "T": "Tango",
    "U": "Uniform", "V": "Victor", "W": "Whiskey", "X": "Xray", "Y": "Yankee",
    "Z": "Zulu", "0": "Zero", "1": "One", "2": "Two", "3": "Three",
    "4": "Four", "5": "Five", "6": "Six", "7": "Seven", "8": "Eight", "9": "Niner",
}

# Cyrillic homoglyphs for common Latin letters (lossy: not all letters have a lookalike).
HOMOGLYPHS: dict[str, str] = {
    "a": "а", "c": "с", "e": "е", "o": "о", "p": "р", "x": "х", "y": "у",
    "A": "А", "B": "В", "C": "С", "E": "Е", "H": "Н", "K": "К", "M": "М",
    "O": "О", "P": "Р", "T": "Т", "X": "Х", "Y": "У",
}
HOMOGLYPHS_REV: dict[str, str] = {v: k for k, v in HOMOGLYPHS.items()}

LEET: dict[str, str] = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}
LEET_REV: dict[str, str] = {v: k for k, v in LEET.items()}

# Unicode Braille patterns U+2800 (blank) .. U+283F. Map a-z to a braille
# pattern offset by its 1-based alphabet index (lossy; decode best-effort).
_BRAILLE_BASE = 0x2800

# A tiny 5-line block font for A-Z0-9 (enough to demonstrate obfuscation;
# a full font is out of scope for a red-team codec).
_ASCII_FONT: dict[str, list[str]] = {
    "A": [" ## ", "#  #", "####", "#  #", "#  #"],
    "B": ["### ", "#  #", "### ", "#  #", "### "],
    "C": [" ###", "#   ", "#   ", "#   ", " ###"],
    "N": ["#  #", "## #", "# ##", "#  #", "#  #"],
    "O": [" ## ", "#  #", "#  #", "#  #", " ## "],
    "T": ["####", " # ", " # ", " # ", " # "],
}


# --- Lossless transforms ----------------------------------------------------


@register_transform
class Base64Transform(Transform):
    name = "base64"

    def encode(self, text: str) -> str:
        return _b64.b64encode(text.encode("utf-8")).decode("ascii")

    def decode(self, text: str) -> str:
        return _b64.b64decode(text.encode("ascii")).decode("utf-8")


@register_transform
class HexTransform(Transform):
    name = "hex"

    def encode(self, text: str) -> str:
        return text.encode("utf-8").hex()

    def decode(self, text: str) -> str:
        return bytes.fromhex(text).decode("utf-8")


@register_transform
class ROT13Transform(Transform):
    name = "rot13"

    def encode(self, text: str) -> str:
        return str(_codecs.encode(text, "rot_13"))

    def decode(self, text: str) -> str:
        return str(_codecs.encode(text, "rot_13"))  # ROT13 is its own inverse


@register_transform
class UrlTransform(Transform):
    name = "url"

    def encode(self, text: str) -> str:
        return _url.quote(text, safe="")

    def decode(self, text: str) -> str:
        return _url.unquote(text)


@register_transform
class AtbashTransform(Transform):
    name = "atbash"

    def _atbash(self, text: str) -> str:
        out = []
        for c in text:
            if "a" <= c <= "z":
                out.append(chr(ord("z") - (ord(c) - ord("a"))))
            elif "A" <= c <= "Z":
                out.append(chr(ord("Z") - (ord(c) - ord("A"))))
            else:
                out.append(c)
        return "".join(out)

    def encode(self, text: str) -> str:
        return self._atbash(text)

    def decode(self, text: str) -> str:
        return self._atbash(text)  # atbash is its own inverse


@register_transform
class CaesarTransform(Transform):
    """Caesar cipher with a fixed shift of 3 (distinct from ROT13)."""

    name = "caesar"
    shift = 3

    def _caesar(self, text: str, shift: int) -> str:
        out = []
        for c in text:
            if "a" <= c <= "z":
                out.append(chr((ord(c) - ord("a") + shift) % 26 + ord("a")))
            elif "A" <= c <= "Z":
                out.append(chr((ord(c) - ord("A") + shift) % 26 + ord("A")))
            else:
                out.append(c)
        return "".join(out)

    def encode(self, text: str) -> str:
        return self._caesar(text, self.shift)

    def decode(self, text: str) -> str:
        return self._caesar(text, -self.shift)


@register_transform
class ReversedTransform(Transform):
    name = "reversed"

    def encode(self, text: str) -> str:
        return text[::-1]

    def decode(self, text: str) -> str:
        return text[::-1]


@register_transform
class BinaryTransform(Transform):
    name = "binary"

    def encode(self, text: str) -> str:
        return " ".join(format(b, "08b") for b in text.encode("utf-8"))

    def decode(self, text: str) -> str:
        bytes_list = bytes(int(b, 2) for b in text.split() if b)
        return bytes_list.decode("utf-8")


@register_transform
class MorseTransform(Transform):
    """Morse code. Lossy: morse is case-agnostic (encode upper-cases)."""

    name = "morse"
    lossy = True

    def encode(self, text: str) -> str:
        return " ".join(MORSE.get(c.upper(), c) for c in text)

    def decode(self, text: str) -> str:
        return "".join(MORSE_REV.get(tok, tok) for tok in text.split() if tok)


@register_transform
class NATOTransform(Transform):
    """NATO phonetic alphabet. Lossy: the alphabet is case-agnostic (upper-cases)."""

    name = "nato"
    lossy = True

    def encode(self, text: str) -> str:
        return " ".join(NATO.get(c.upper(), c) for c in text)

    def decode(self, text: str) -> str:
        out = []
        for tok in text.split():
            up = tok
            # Exact NATO word -> letter; else keep the token's first char.
            for k, v in NATO.items():
                if v == up:
                    out.append(k)
                    break
            else:
                low = tok.lower()
                out.append(low[0].upper() if low else tok)
        return "".join(out)


@register_transform
class JSONWrapTransform(Transform):
    name = "json_wrap"

    def encode(self, text: str) -> str:
        return _json.dumps({"payload": text}, ensure_ascii=False)

    def decode(self, text: str) -> str:
        payload = _json.loads(text)["payload"]
        return payload if isinstance(payload, str) else str(payload)


@register_transform
class XMLWrapTransform(Transform):
    name = "xml_wrap"

    def encode(self, text: str) -> str:
        return f"<payload>{text}</payload>"

    def decode(self, text: str) -> str:
        prefix = "<payload>"
        suffix = "</payload>"
        if text.startswith(prefix) and text.endswith(suffix):
            return text[len(prefix) : len(text) - len(suffix)]
        return text


@register_transform
class MarkdownTransform(Transform):
    name = "markdown"

    def encode(self, text: str) -> str:
        return f"```\n{text}\n```"

    def decode(self, text: str) -> str:
        prefix = "```\n"
        suffix = "\n```"
        if text.startswith(prefix) and text.endswith(suffix):
            return text[len(prefix) : len(text) - len(suffix)]
        return text


@register_transform
class ZeroWidthTransform(Transform):
    """Insert zero-width spaces (U+200B) between every character.

    Lossless: decode strips every zero-width space and recovers the original.
    The obfuscation value is that a naive filter splitting on whitespace
    sees one token where there were many.
    """

    name = "zero_width"

    def encode(self, text: str) -> str:
        return "\u200b".join(text)

    def decode(self, text: str) -> str:
        return text.replace("\u200b", "")


# --- Lossy transforms --------------------------------------------------------


@register_transform
class LeetspeakTransform(Transform):
    """Leetspeak substitution (a→4, e→3, i→1, o→0, s→5, t→7). Lossy."""

    name = "leetspeak"
    lossy = True

    def encode(self, text: str) -> str:
        return "".join(LEET.get(c.lower(), c) for c in text)

    def decode(self, text: str) -> str:
        # Best-effort: reverse-map digits; ambiguous so lossy.
        return "".join(LEET_REV.get(c, c) for c in text)


@register_transform
class HomoglyphTransform(Transform):
    """Replace Latin letters with Cyrillic lookalikes. Lossy (partial coverage)."""

    name = "homoglyph"
    lossy = True

    def encode(self, text: str) -> str:
        return "".join(HOMOGLYPHS.get(c, c) for c in text)

    def decode(self, text: str) -> str:
        return "".join(HOMOGLYPHS_REV.get(c, c) for c in text)


@register_transform
class ASCIITransform(Transform):
    """Render text as a block-letter ASCII banner. Lossy (decode can't recover)."""

    name = "ascii_art"
    lossy = True

    def encode(self, text: str) -> str:
        up = text.upper()
        lines = ["", "", "", "", ""]
        for c in up:
            glyph = _ASCII_FONT.get(c)
            if glyph is None:
                # Unknown char: emit a single-cell placeholder column.
                for i in range(5):
                    lines[i] += " ?  "
            else:
                for i in range(5):
                    lines[i] += glyph[i] + "  "
        return "\n".join(lines).rstrip()

    def decode(self, text: str) -> str:
        # ASCII art cannot be reliably decoded back to text; the winnability
        # guard catches the destruction and marks the probe Inconclusive.
        return text


@register_transform
class EmojiBrailleTransform(Transform):
    """Map each letter to a Unicode Braille pattern (U+2800 + index). Lossy."""

    name = "emoji_braille"
    lossy = True

    def encode(self, text: str) -> str:
        out = []
        for c in text:
            if "a" <= c <= "z":
                out.append(chr(_BRAILLE_BASE + (ord(c) - ord("a") + 1)))
            elif "A" <= c <= "Z":
                out.append(chr(_BRAILLE_BASE + (ord(c) - ord("A") + 1)))
            else:
                out.append(c)
        return "".join(out)

    def decode(self, text: str) -> str:
        out = []
        for c in text:
            o = ord(c)
            if _BRAILLE_BASE < o <= _BRAILLE_BASE + 26:
                out.append(chr(o - _BRAILLE_BASE - 1 + ord("a")))
            else:
                out.append(c)
        return "".join(out)
