"""The SecurityScarletAI exercise-telemetry producer (fleet Wave 2).

Pins the verified IngestEvent contract (Scarlet src/api/ingest.py +
src/ingestion/schemas.py, read 2026-09-20), the closed exercise vocabulary,
the severity ladder, the fail-soft delivery doctrine, and the
never-log-the-token contract.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from neuralstrike.core.exceptions import ValidationError
from neuralstrike.integrations.attack_chain import run_attack_chain_delta
from neuralstrike.integrations.neuralguard import BundledNeuralGuardFixture
from neuralstrike.integrations.scarletai import (
    SCARLETAI_SOURCE,
    ExerciseTelemetry,
    build_exercise_end_event,
    build_exercise_events,
    build_exercise_start_event,
    build_probe_event,
    post_events,
)

# The closed red-team exercise vocabulary (Scarlet Wave-1 token block).
EXERCISE_TOKENS = {
    "exercise_start",
    "exercise_end",
    "probe_succeeded",
    "probe_resisted",
    "probe_inconclusive",
}


def _config(**overrides: Any) -> ExerciseTelemetry:
    base: dict[str, Any] = {
        "ingest_url": "http://localhost:8000/api/v1/ingest",
        "token": "ingest-secret-token-value",
        "run_host": "neuralstrike-20260920abcd1234",
        "actor": "purple-operator",
    }
    base.update(overrides)
    return ExerciseTelemetry(**base)


# ── Mapping purity ──────────────────────────────────────────────────────────


class TestMappingContract:
    def test_start_event_shape(self) -> None:
        event = build_exercise_start_event(_config(), target="echo", screen="s", n_payloads=8, seed=1)
        assert event["source"] == SCARLETAI_SOURCE
        assert event["event_category"] == "ai"
        assert event["event_type"] == "start"
        assert event["event_action"] == "exercise_start"
        assert event["event_action"] in EXERCISE_TOKENS
        assert event["severity"] == "info"
        assert event["user_name"] == "purple-operator"
        assert event["process_name"] is None
        assert event["host_name"].startswith("neuralstrike-")
        assert event["host_name"] == event["host_name"][:253]
        assert event["raw_data"]["neuralstrike"]["kind"] == "exercise_start"

    def test_end_event_carries_summary(self) -> None:
        event = build_exercise_end_event(_config(), summary={"delta": 0.5})
        assert event["event_type"] == "end"
        assert event["event_action"] == "exercise_end"
        assert event["raw_data"]["neuralstrike"]["summary"] == {"delta": 0.5}

    def test_probe_severity_ladder(self) -> None:
        # Only a SUCCEEDED probe is alert-grade (defense-gap evidence); the
        # coverage data (resisted/inconclusive) is never an incident.
        assert (
            build_probe_event(
                _config(),
                payload_id="AC-RECON-001",
                phase="recon",
                module="LLMRecon",
                family="T-EXT",
                verdict="succeeded",
            )["severity"]
            == "high"
        )
        assert (
            build_probe_event(
                _config(),
                payload_id="x",
                phase="recon",
                module="LLMRecon",
                family="T-EXT",
                verdict="resisted",
            )["severity"]
            == "info"
        )
        assert (
            build_probe_event(
                _config(),
                payload_id="x",
                phase="recon",
                module="LLMRecon",
                family="T-EXT",
                verdict="inconclusive",
            )["severity"]
            == "info"
        )
        succeeded = build_probe_event(
            _config(),
            payload_id="AC-RECON-001",
            phase="recon",
            module="LLMRecon",
            family="T-EXT",
            verdict="succeeded",
        )
        assert succeeded["event_action"] == "probe_succeeded"
        assert succeeded["process_name"] == "LLMRecon"  # the grouping dimension
        assert succeeded["raw_data"]["neuralstrike"]["neuralguard_family"] == "T-EXT"

    def test_unknown_verdict_fails_closed(self) -> None:
        # An unknown verdict must not silently become a guessed token.
        with pytest.raises(ValueError, match="unknown probe verdict"):
            build_probe_event(
                _config(), payload_id="x", phase="recon", module="m", family="f", verdict="BANANA"
            )

    def test_actor_and_host_caps(self) -> None:
        long_actor = "A" * 400
        cfg = _config(actor=long_actor)
        event = build_probe_event(
            cfg, payload_id="x", phase="recon", module="M" * 400, family="f", verdict="resisted"
        )
        assert event["user_name"] == "A" * 256
        assert event["process_name"] == "M" * 256

    def test_host_sanitized_like_scarlet(self) -> None:
        # Scarlet's own hostname sanitizer strips control characters.
        cfg = _config()
        object.__setattr__(cfg, "run_host", "neuralstrike-bad\n\r\tchar")
        event = build_exercise_start_event(cfg)
        assert (
            "\n" not in event["host_name"]
            and "\r" not in event["host_name"]
            and "\t" not in event["host_name"]
        )

    def test_telemetry_requires_https_url_and_token(self) -> None:
        with pytest.raises(ValueError, match="http"):
            ExerciseTelemetry(ingest_url="ftp://bad", token="t", run_host="h")
        with pytest.raises(ValueError, match="token"):
            ExerciseTelemetry(ingest_url="http://ok", token="", run_host="h")


# ── The exercise batch ──────────────────────────────────────────────────────


class TestExerciseEvents:
    @pytest.mark.asyncio
    async def test_full_batch_from_real_delta(self) -> None:
        screen = BundledNeuralGuardFixture()

        async def echo_victim(prompt: str) -> str:
            return prompt

        delta = await run_attack_chain_delta(screen, echo_victim, seed=42)
        events = build_exercise_events(_config(), delta, started_at=None, target="echo", seed=42)
        # 8 probes + 1 end bookend (the start rides its own POST).
        assert len(events) == 9
        actions = {e["event_action"] for e in events}
        assert "exercise_end" in actions
        # The fixture catches all 8 -> all probe events are probe_inconclusive
        # (blocked => victim never saw the canary => honest coverage gap).
        probe_actions = actions - {"exercise_end"}
        assert probe_actions == {"probe_inconclusive"}
        # Every event is a closed-vocabulary member with the actor slot.
        for e in events:
            assert e["event_action"] in EXERCISE_TOKENS
            assert e["source"] == SCARLETAI_SOURCE
            assert e["user_name"] == "purple-operator"
            assert e["raw_data"]["neuralstrike"]["actor"] == "purple-operator"

    def test_end_summary_includes_catch_rate(self) -> None:
        class _FakeDelta:
            screen = "s"
            victim = "v"
            n = 2
            payloads = ()
            baseline_asr = 1.0
            defended_asr = 0.0
            delta = 1.0
            firewall_caught = 1
            catch_rate = 0.5

        events = build_exercise_events(_config(), _FakeDelta(), started_at=None)
        summary = events[-1]["raw_data"]["neuralstrike"]["summary"]
        assert summary["firewall_caught"] == 1 and summary["catch_rate"] == 0.5


# ── Delivery (fail-soft doctrine) ───────────────────────────────────────────


class TestDelivery:
    @pytest.mark.asyncio
    async def test_delivers_202_and_reports_true(self) -> None:
        seen: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["auth"] = request.headers.get("Authorization")
            seen["body"] = json.loads(request.content.decode())
            return httpx.Response(202, json={"accepted": len(json.loads(request.content.decode()))})

        ok = await post_events(
            "http://siem.test/api/v1/ingest",
            "ingest-secret-token-value",
            [{"@timestamp": "x", "host_name": "h"}],
            transport=httpx.MockTransport(handler),
        )
        assert ok is True
        assert seen["auth"] == "Bearer ingest-secret-token-value"
        assert seen["body"][0]["host_name"] == "h"

    @pytest.mark.asyncio
    async def test_non_202_is_fail_soft(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(503, json={"detail": "quarantine"})

        ok = await post_events(
            "http://siem.test/api/v1/ingest",
            "t",
            [{"@timestamp": "x", "host_name": "h"}],
            transport=httpx.MockTransport(handler),
        )
        assert ok is False  # logged + counted, never raised

    @pytest.mark.asyncio
    async def test_transport_error_is_fail_soft(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("siem down")

        ok = await post_events(
            "http://siem.test/api/v1/ingest",
            "t",
            [{"@timestamp": "x", "host_name": "h"}],
            transport=httpx.MockTransport(handler),
        )
        assert ok is False

    @pytest.mark.asyncio
    async def test_empty_batch_is_noop_success(self) -> None:
        ok = await post_events(
            "http://siem.test/api/v1/ingest",
            "t",
            [],
            transport=httpx.MockTransport(lambda request: httpx.Response(500)),
        )
        assert ok is True

    @pytest.mark.asyncio
    async def test_token_never_logged(self, caplog: pytest.LogCaptureFixture) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(503)

        with caplog.at_level("DEBUG", logger="neuralstrike.integrations.scarletai"):
            await post_events(
                "http://siem.test/api/v1/ingest",
                "ingest-secret-token-value",
                [{"@timestamp": "x", "host_name": "h"}],
                transport=httpx.MockTransport(handler),
            )
        assert "ingest-secret-token-value" not in caplog.text

    @pytest.mark.asyncio
    async def test_malformed_response_body_is_fail_soft(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(202, content=b"not-json")

        ok = await post_events(
            "http://siem.test/api/v1/ingest",
            "t",
            [{"@timestamp": "x", "host_name": "h"}],
            transport=httpx.MockTransport(handler),
        )
        assert ok is True  # 202 accepted; a body we cannot parse is not a failure


# ── Opt-in plumbing ────────────────────────────────────────────────────────


class TestOptInPlumbing:
    def test_no_config_is_none(self) -> None:
        from neuralstrike.main import _build_telemetry

        assert _build_telemetry(None, None, None) is None

    def test_partial_config_refused(self) -> None:
        from neuralstrike.main import _build_telemetry

        with pytest.raises(ValidationError, match="must be set together"):
            _build_telemetry("http://localhost:8000/api/v1/ingest", None, None)
        with pytest.raises(ValidationError, match="must be set together"):
            _build_telemetry(None, "t", None)

    def test_flags_build_run_stamped_host(self) -> None:
        from neuralstrike.main import _build_telemetry

        cfg = _build_telemetry("http://localhost:8000/api/v1/ingest", "tok", "op")
        assert cfg is not None
        assert cfg.run_host.startswith("neuralstrike-")
        assert cfg.actor == "op"
        assert cfg.ingest_url == "http://localhost:8000/api/v1/ingest"

    def test_canary_values_never_in_events(self) -> None:
        # The mapping surface never receives canary VALUES by design; pin that
        # the raw_data chain of custody has no canary-shaped field at all.
        cfg = _config()
        for verdict in ("succeeded", "resisted", "inconclusive"):
            event = build_probe_event(
                cfg,
                payload_id="AC-RECON-001",
                phase="recon",
                module="LLMRecon",
                family="T-EXT",
                verdict=verdict,
            )
            flat = json.dumps(event)
            assert "CANARY" not in flat
