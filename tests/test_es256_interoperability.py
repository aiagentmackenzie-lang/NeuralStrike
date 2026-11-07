"""Independent RFC 7515 Appendix A.3 fixture (not signed by our verifier)."""

import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from neuralstrike.identity.jws import JWSVerifyError, verify_compact_jws

# Public test material from https://www.rfc-editor.org/rfc/rfc7515#appendix-A.3
# RFC code components: Copyright (c) 2015 IETF Trust and the persons identified
# as authors. Redistribution under the Simplified BSD License; provided AS IS.
HEADER = "eyJhbGciOiJFUzI1NiJ9"
PAYLOAD = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
SIGNATURE = "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"


def decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def encode(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


@pytest.fixture
def public_pem():
    x = int.from_bytes(decode("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"), "big")
    y = int.from_bytes(decode("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"), "big")
    key = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    return key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def test_independent_raw_jose_vector_verifies(public_pem):
    header, payload = verify_compact_jws(
        f"{HEADER}.{PAYLOAD}.{SIGNATURE}", public_key_pem=public_pem, canonicalize_payload=False
    )
    assert header == {"alg": "ES256"}
    assert payload == decode(PAYLOAD)


def test_nonstandard_der_wire_encoding_is_rejected(public_pem):
    raw = decode(SIGNATURE)
    der = utils.encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    with pytest.raises(JWSVerifyError):
        verify_compact_jws(
            f"{HEADER}.{PAYLOAD}.{encode(der)}", public_key_pem=public_pem, canonicalize_payload=False
        )


@pytest.mark.parametrize("signature", [b"", b"\x00" * 64, decode(SIGNATURE)[:-1], decode(SIGNATURE) + b"x"])
def test_malformed_raw_signature_rejected(public_pem, signature):
    with pytest.raises(JWSVerifyError):
        verify_compact_jws(
            f"{HEADER}.{PAYLOAD}.{encode(signature)}", public_key_pem=public_pem, canonicalize_payload=False
        )
