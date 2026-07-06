"""Tests for A2A inter-agent attack surface (Phase 5)."""

from __future__ import annotations

import base64
import json

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from neuralstrike.attacks.a2a.card_tamper import A2ACardTamperScanner
from neuralstrike.attacks.a2a.delegation import DelegationAnalyzer, DelegationRecord
from neuralstrike.attacks.a2a.spoofing import A2ASpoofScanner
from neuralstrike.identity import canonicalize


class TestA2ACardTamper:
    async def test_valid_card_verifies_and_tampered_rejected(self) -> None:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

        card = {"name": "TestAgent", "url": "https://example.com/a2a", "version": "1.0"}
        canonical_card = canonicalize(card)
        payload_b64 = base64.urlsafe_b64encode(canonical_card.encode()).decode().rstrip("=")
        header = {"alg": "RS256"}
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        signing_input = f"{header_b64}.{payload_b64}".encode()
        from cryptography.hazmat.primitives.asymmetric import padding
        sig = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")
        jws = f"{header_b64}.{payload_b64}.{sig_b64}"

        agent_card = {
            **card,
            "verificationMethod": [{"id": "#keys-1", "publicKeyPem": public_pem}],
            "signature": jws,
        }
        mock_transport = httpx.MockTransport(lambda request: httpx.Response(200, json=agent_card))
        client = httpx.AsyncClient(transport=mock_transport)
        scanner = A2ACardTamperScanner(base_url="https://example.com", client=client)
        result = await scanner.scan()
        assert result.signature_valid
        assert result.tampered_card_rejected
        await scanner.close()

    async def test_fetch_failure(self) -> None:
        mock_transport = httpx.MockTransport(lambda request: httpx.Response(404))
        client = httpx.AsyncClient(transport=mock_transport)
        scanner = A2ACardTamperScanner(base_url="https://missing.example", client=client)
        result = await scanner.scan()
        assert not result.signature_valid
        assert "card fetch failed" in result.evidence
        await scanner.close()


class TestDelegationAnalyzer:
    def test_depth_escalation(self) -> None:
        chain = tuple(DelegationRecord(issuer=f"a{i}", recipient=f"a{i+1}", scope=("read",), depth=i) for i in range(5))
        analyzer = DelegationAnalyzer(max_depth=3)
        findings = analyzer.analyze(chain)
        assert any(f.issue == "depth_escalation" for f in findings)

    def test_scope_widening(self) -> None:
        chain = (
            DelegationRecord(issuer="user", recipient="agent-a", scope=("read",), depth=0),
            DelegationRecord(issuer="agent-a", recipient="agent-b", scope=("read", "write"), depth=1),
        )
        analyzer = DelegationAnalyzer()
        findings = analyzer.analyze(chain)
        assert any(f.issue == "scope_widening" for f in findings)

    def test_cross_tenant(self) -> None:
        chain = (
            DelegationRecord(issuer="a", recipient="b", scope=("read",), depth=0, tenant="t1"),
            DelegationRecord(issuer="b", recipient="c", scope=("read",), depth=1, tenant="t2"),
        )
        findings = DelegationAnalyzer().analyze(chain)
        assert any(f.issue == "cross_tenant_delegation" for f in findings)

    def test_missing_proof(self) -> None:
        chain = (DelegationRecord(issuer="a", recipient="b", scope=("read",), depth=0),)
        findings = DelegationAnalyzer().analyze(chain)
        assert any(f.issue == "missing_delegation_proof" for f in findings)


class TestA2ASpoofScanner:
    async def test_missing_signature_accepted_is_critical(self) -> None:
        responses = {"missing_signature": 200, "alg_confusion": 401, "tampered_body": 401}
        call_count = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            call_count["n"] += 1
            if call_count["n"] == 1:
                return httpx.Response(responses["missing_signature"])
            if call_count["n"] == 2:
                return httpx.Response(responses["alg_confusion"])
            return httpx.Response(responses["tampered_body"])

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        scanner = A2ASpoofScanner(
            client=client,
            target_uri="https://example.com/a2a/message/send",
            valid_signature=base64.standard_b64encode(b"dummy").decode(),
            valid_signature_input='sig1=("@method");created=1;keyid="k1";alg="rsa-v1_5-sha256"',
            public_key_pem="",
        )
        report = await scanner.scan()
        missing = next(r for r in report.results if r.attempt == "missing_signature")
        assert missing.accepted
        assert missing.severity == "critical"
        await client.aclose()

    async def test_all_rejected_is_clean(self) -> None:
        client = httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(401)))
        scanner = A2ASpoofScanner(
            client=client,
            target_uri="https://example.com/a2a/message/send",
            valid_signature=base64.standard_b64encode(b"dummy").decode(),
            valid_signature_input='sig1=("@method");created=1;keyid="k1";alg="rsa-v1_5-sha256"',
            public_key_pem="",
        )
        report = await scanner.scan()
        assert not any(r.accepted for r in report.results)
        await client.aclose()
