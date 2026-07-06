"""Tests for the 18-codec transform pipeline (Phase-4 exit gate, bullet 2)."""

from __future__ import annotations

import pytest

from neuralstrike.transforms import (
    TRANSFORMS,
    apply_transform,
    assert_18_transforms,
    get_transform,
    list_transforms,
    round_trip,
    winnability_guard,
)

# The known-answer vector suite: a representative payload spanning letters,
# digits, spaces, and punctuation. Every transform is exercised on this.
KNOWN_ANSWER = "Attack at dawn. Code 9."


class TestRegistry:
    def test_exactly_18_transforms(self) -> None:
        assert len(list_transforms()) == 18
        assert_18_transforms()  # the invariant helper

    def test_unknown_transform_raises(self) -> None:
        with pytest.raises(KeyError):
            get_transform("bogus")

    def test_registry_is_read_only_via_public_alias(self) -> None:
        # TRANSFORMS is a MappingProxyType; item assignment is blocked, so a
        # caller cannot add/remove transforms by accident (registration is
        # via @register_transform only).
        with pytest.raises(TypeError):
            TRANSFORMS["bogus"] = get_transform("base64")  # type: ignore[index]
        with pytest.raises((TypeError, AttributeError)):
            TRANSFORMS.clear()  # type: ignore[union-attr]
        assert len(list_transforms()) == 18  # registry intact


class TestWinnabilityGuard:
    def test_surviving_decode_is_winnable(self) -> None:
        # Case-destroyed but content-identical -> winnable.
        assert winnability_guard("Attack at dawn", "ATTACK AT DAWN") is True

    def test_destroyed_decode_is_not_winnable(self) -> None:
        # ASCII-art lost every letter -> not winnable.
        assert winnability_guard("Attack", " #  #  \n # ") is False

    def test_empty_original_is_winnable(self) -> None:
        assert winnability_guard("", "") is True

    def test_empty_decode_is_not_winnable(self) -> None:
        assert winnability_guard("Attack", "") is False


class TestKnownAnswerRoundTrip:
    """Phase-4 exit gate, bullet 2: all 18 transforms round-trip on the known-answer suite.

    Lossless transforms round-trip EXACTLY (decode(encode(x)) == x).
    Lossy transforms round-trip via the winnability guard: a surviving
    payload is winnable (round_trip_ok=True); a destroyed payload is
    honestly NOT winnable (round_trip_ok=False) and a downstream probe
    would be Inconclusive, never a fabricated Resisted.
    """

    LOSSLESS = {
        "atbash", "base64", "binary", "caesar", "hex", "json_wrap",
        "markdown", "reversed", "rot13", "url", "xml_wrap", "zero_width",
    }
    LOSSY_SURVIVING = {"emoji_braille", "homoglyph", "leetspeak", "morse", "nato"}
    LOSSY_DESTROYING = {"ascii_art"}

    def test_all_18_classified(self) -> None:
        names = set(list_transforms())
        assert names == self.LOSSLESS | self.LOSSY_SURVIVING | self.LOSSY_DESTROYING

    @pytest.mark.parametrize("name", sorted(LOSSLESS))
    def test_lossless_round_trips_exactly(self, name: str) -> None:
        r = apply_transform(name, KNOWN_ANSWER)
        assert r.lossy is False
        assert r.round_trip_ok is True, (
            f"{name} is lossless but did not round-trip: {r.encoded!r} -> {get_transform(name).decode(r.encoded)!r}"
        )
        assert get_transform(name).decode(r.encoded) == KNOWN_ANSWER

    @pytest.mark.parametrize("name", sorted(LOSSY_SURVIVING))
    def test_lossy_surviving_is_winnable(self, name: str) -> None:
        r = apply_transform(name, KNOWN_ANSWER)
        assert r.lossy is True
        assert r.round_trip_ok is True, (
            f"{name} destroyed the payload (not winnable); a downstream Resisted "
            f"would be an artifact, not defense."
        )

    @pytest.mark.parametrize("name", sorted(LOSSY_DESTROYING))
    def test_lossy_destroying_is_honestly_not_winnable(self, name: str) -> None:
        r = apply_transform(name, KNOWN_ANSWER)
        assert r.lossy is True
        assert r.round_trip_ok is False, (
            f"{name} should destroy the payload (honestly Inconclusive), not "
            f"silently win."
        )

    def test_round_trip_helper_matches_apply(self) -> None:
        for name in list_transforms():
            assert round_trip(name, KNOWN_ANSWER) == apply_transform(name, KNOWN_ANSWER).round_trip_ok


class TestProvenance:
    def test_provenance_describes_transform(self) -> None:
        r = apply_transform("base64", "hi")
        assert "base64" in r.provenance
        assert "lossless" in r.provenance
        assert "round-trip ok" in r.provenance

    def test_provenance_flags_destroyed_payload(self) -> None:
        r = apply_transform("ascii_art", "Attack")
        assert "lossy" in r.provenance
        assert "payload destroyed" in r.provenance


class TestSpecificCodecs:
    """Spot-checks that the encoders produce the documented form."""

    def test_base64(self) -> None:
        assert apply_transform("base64", "hi").encoded == "aGk="

    def test_hex(self) -> None:
        assert apply_transform("hex", "A").encoded == "41"

    def test_rot13(self) -> None:
        assert apply_transform("rot13", "hello").encoded == "uryyb"

    def test_caesar_shift3(self) -> None:
        # Caesar(3) is distinct from ROT13.
        assert apply_transform("caesar", "abc").encoded == "def"

    def test_atbash(self) -> None:
        assert apply_transform("atbash", "abc").encoded == "zyx"

    def test_reversed(self) -> None:
        assert apply_transform("reversed", "abc").encoded == "cba"

    def test_url(self) -> None:
        assert apply_transform("url", "a b").encoded == "a%20b"

    def test_json_wrap(self) -> None:
        assert apply_transform("json_wrap", "x").encoded == '{"payload": "x"}'

    def test_xml_wrap(self) -> None:
        assert apply_transform("xml_wrap", "x").encoded == "<payload>x</payload>"

    def test_zero_width_inserts_u200b(self) -> None:
        assert "\u200b" in apply_transform("zero_width", "ab").encoded

    def test_leetspeak(self) -> None:
        assert apply_transform("leetspeak", "aeiost").encoded == "431057"

    def test_homoglyph_uses_cyrillic(self) -> None:
        # 'a' (Latin) -> its Cyrillic lookalike U+0430, distinct from Latin U+0061.
        assert apply_transform("homoglyph", "a").encoded == "\u0430"

    def test_emoji_braille_maps_to_braille(self) -> None:
        # 'a' -> braille pattern U+2801.
        assert apply_transform("emoji_braille", "a").encoded == "\u2801"

    def test_morse(self) -> None:
        assert apply_transform("morse", "SOS").encoded == "... --- ..."

    def test_nato(self) -> None:
        assert apply_transform("nato", "A").encoded == "Alpha"

    def test_binary(self) -> None:
        assert apply_transform("binary", "A").encoded == "01000001"

    def test_markdown_codeblock(self) -> None:
        assert apply_transform("markdown", "x").encoded == "```\nx\n```"

    def test_ascii_art_renders_banner(self) -> None:
        enc = apply_transform("ascii_art", "A").encoded
        assert "##" in enc  # the A glyph
