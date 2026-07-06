"""Tests for NeuralStrike identity layer (Phase 5)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json

import httpx
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from neuralstrike.identity import (
    DIDResolver,
    HTTPMessageSignatureError,
    JWSVerifyError,
    canonicalize,
    resolve_did,
    verify_compact_jws,
    verify_http_signature,
)
from neuralstrike.identity.jcs import _canonical_number


class TestJCS:
    def test_canonicalizes_object_with_sorted_keys(self) -> None:
        obj = {"b": 2, "a": {"d": 4, "c": 3}}
        assert canonicalize(obj) == '{"a":{"c":3,"d":4},"b":2}'

    def test_integer_like_float_becomes_int(self) -> None:
        assert canonicalize({"n": 1.0}) == '{"n":1}'

    def test_true_float_stays_float(self) -> None:
        assert canonicalize({"n": 1.5}) == '{"n":1.5}'

    def test_canonical_number(self) -> None:
        assert _canonical_number(2.0) == 2
        assert _canonical_number(1.5) == 1.5
        assert _canonical_number(1 << 53) == 1 << 53

    def test_list_and_nested(self) -> None:
        assert canonicalize([{"z": 1, "a": 2}]) == '[{"a":2,"z":1}]'


class TestJWSVerify:
    def test_hs256_valid(self) -> None:
        payload = {"sub": "agent-1"}
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        header = {"alg": "HS256", "typ": "JWT"}
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        signing_input = f"{header_b64}.{payload_b64}".encode()
        signature = base64.urlsafe_b64encode(hmac.new(b"secret", signing_input, hashlib.sha256).digest()).decode().rstrip("=")
        jws = f"{header_b64}.{payload_b64}.{signature}"
        out_header, out_payload = verify_compact_jws(jws, key=b"secret", canonicalize_payload=False)
        assert out_header["alg"] == "HS256"
        assert json.loads(out_payload.decode()) == payload

    def test_hs256_invalid_secret(self) -> None:
        payload = {"sub": "agent-1"}
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        header = {"alg": "HS256"}
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        signing_input = f"{header_b64}.{payload_b64}".encode()
        signature = base64.urlsafe_b64encode(hmac.new(b"secret", signing_input, hashlib.sha256).digest()).decode().rstrip("=")
        jws = f"{header_b64}.{payload_b64}.{signature}"
        with pytest.raises(JWSVerifyError, match="HS256 signature mismatch"):
            verify_compact_jws(jws, key=b"wrong", canonicalize_payload=False)

    def test_invalid_jws_format(self) -> None:
        with pytest.raises(JWSVerifyError, match="JWS must have 3 segments"):
            verify_compact_jws("a.b")

    def test_rs256_valid(self) -> None:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        payload = {"sub": "agent-1"}
        canonical_payload = canonicalize(payload)
        payload_b64 = base64.urlsafe_b64encode(canonical_payload.encode()).decode().rstrip("=")
        header = {"alg": "RS256"}
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        signing_input = f"{header_b64}.{payload_b64}".encode()
        from cryptography.hazmat.primitives.asymmetric import padding
        sig = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        signature_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")
        jws = f"{header_b64}.{payload_b64}.{signature_b64}"
        out_header, out_payload = verify_compact_jws(jws, public_key_pem=public_pem)
        assert out_header["alg"] == "RS256"
        assert json.loads(out_payload.decode()) == payload

    def test_es256_valid(self) -> None:
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        payload = {"sub": "agent-1"}
        canonical_payload = canonicalize(payload)
        payload_b64 = base64.urlsafe_b64encode(canonical_payload.encode()).decode().rstrip("=")
        header = {"alg": "ES256"}
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        signing_input = f"{header_b64}.{payload_b64}".encode()
        from cryptography.hazmat.primitives.asymmetric import ec as ec_crypto
        sig = private_key.sign(signing_input, ec_crypto.ECDSA(hashes.SHA256()))
        signature_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")
        jws = f"{header_b64}.{payload_b64}.{signature_b64}"
        out_header, _out_payload = verify_compact_jws(jws, public_key_pem=public_pem)
        assert out_header["alg"] == "ES256"

    def test_tampered_payload_fails(self) -> None:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        header = {"alg": "RS256"}
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(b"tampered").decode().rstrip("=")
        signing_input = f"{header_b64}.{payload_b64}".encode()
        from cryptography.hazmat.primitives.asymmetric import padding
        sig = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        signature_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")
        jws = f"{header_b64}.{payload_b64}.{signature_b64}"
        # With canonicalize_payload=True, payload is not JSON object -> error
        with pytest.raises(JWSVerifyError, match="canonicalizable JSON"):
            verify_compact_jws(jws, public_key_pem=public_pem)


class TestHTTPMessageSignatures:
    def test_hmac_sha256_valid(self) -> None:
        headers = {"host": "example.com"}
        sig_input = 'sig1=("@method"; "@authority"; "host");created=1700000000;keyid="k1";alg="hmac-sha256"'
        sig = _sign_http_hmac(sig_input, b"secret", "POST", "https://example.com/tasks", headers)
        result = verify_http_signature(
            signature=sig,
            signature_input=sig_input,
            method="POST",
            target_uri="https://example.com/tasks",
            headers=headers,
            key=b"secret",
        )
        assert result["alg"] == "hmac-sha256"

    def test_hmac_sha256_invalid(self) -> None:
        headers = {"host": "example.com"}
        sig_input = 'sig1=("host");alg="hmac-sha256"'
        sig = base64.standard_b64encode(b"wrong").decode()
        with pytest.raises(HTTPMessageSignatureError, match="signature mismatch"):
            verify_http_signature(
                signature=sig,
                signature_input=sig_input,
                method="GET",
                target_uri="https://example.com/",
                headers=headers,
                key=b"secret",
            )

    def test_rsa_v1_5_sha256_valid(self) -> None:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        headers = {"host": "example.com"}
        sig_input = 'sig1=("@method");created=1;keyid="k1";alg="rsa-v1_5-sha256"'
        sig = _sign_http_rsa(sig_input, private_key, "POST", "https://example.com/", headers)
        result = verify_http_signature(
            signature=sig,
            signature_input=sig_input,
            method="POST",
            target_uri="https://example.com/",
            headers=headers,
            public_key_pem=public_pem,
        )
        assert result["alg"] == "rsa-v1_5-sha256"

    def test_ed25519_valid(self) -> None:
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        headers = {"host": "example.com"}
        sig_input = 'sig1=("@method");created=1;keyid="k1";alg="ed25519"'
        sig = _sign_http_ed25519(sig_input, private_key, "POST", "https://example.com/", headers)
        result = verify_http_signature(
            signature=sig,
            signature_input=sig_input,
            method="POST",
            target_uri="https://example.com/",
            headers=headers,
            public_key_pem=public_pem,
        )
        assert result["alg"] == "ed25519"


def _sign_http_hmac(sig_input: str, secret: bytes, method: str, uri: str, headers: dict[str, str]) -> str:
    from neuralstrike.identity.signatures import _build_signature_base
    base = _build_signature_base(sig_input, method=method, target_uri=uri, headers=headers, body=b"")
    sig = hmac.new(secret, base, hashlib.sha256).digest()
    return base64.standard_b64encode(sig).decode()


def _sign_http_rsa(sig_input: str, private_key: rsa.RSAPrivateKey, method: str, uri: str, headers: dict[str, str]) -> str:
    from cryptography.hazmat.primitives.asymmetric import padding

    from neuralstrike.identity.signatures import _build_signature_base
    base = _build_signature_base(sig_input, method=method, target_uri=uri, headers=headers, body=b"")
    sig = private_key.sign(base, padding.PKCS1v15(), hashes.SHA256())
    return base64.standard_b64encode(sig).decode()


def _sign_http_ed25519(sig_input: str, private_key: ed25519.Ed25519PrivateKey, method: str, uri: str, headers: dict[str, str]) -> str:
    from neuralstrike.identity.signatures import _build_signature_base
    base = _build_signature_base(sig_input, method=method, target_uri=uri, headers=headers, body=b"")
    sig = private_key.sign(base)
    return base64.standard_b64encode(sig).decode()


class TestDIDResolution:
    async def test_did_web_resolution(self) -> None:
        did_doc = {
            "verificationMethod": [
                {
                    "id": "did:web:example.com#keys-1",
                    "type": "RsaVerificationKey2018",
                    "publicKeyJwk": {"kty": "RSA", "n": "abc"},
                }
            ]
        }
        mock_transport = httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(200, json=did_doc)))
        resolver = DIDResolver(transport=mock_transport)
        result = await resolver.resolve("did:web:example.com")
        assert result.subject == "did:web:example.com"
        assert result.source == "resolver"
        assert len(result.keys) == 1
        assert result.keys[0].key_id == "did:web:example.com#keys-1"
        await mock_transport.aclose()

    async def test_did_web_fetch_failure(self) -> None:
        mock_transport = httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(404)))
        resolver = DIDResolver(transport=mock_transport)
        result = await resolver.resolve("did:web:missing.example")
        assert result.keys == ()
        assert result.warnings
        await mock_transport.aclose()

    async def test_did_key_ed25519(self) -> None:
        pytest.importorskip("base58")
        import base58
        raw = b"\xed\x01" + b"a" * 32
        mb = "z" + base58.b58encode(raw).decode()
        result = await resolve_did(f"did:key:{mb}")
        assert result.subject == f"did:key:{mb}"
        assert result.keys[0].algorithm == "Ed25519"

    async def test_did_key_unsupported_method(self) -> None:
        result = await resolve_did("did:foo:bar")
        assert result.keys == ()
        assert "unsupported DID method" in result.warnings[0]
