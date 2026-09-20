"""The purple-report (fleet Wave 3): read-path + join + receipt identity.

Pins the verified Scarlet READ contracts (GET /api/v1/alerts, GET /api/v1/logs
— read fully 2026-09-20: /alerts host_name ILIKE + limit ≤1000, /logs
time_minutes + limit ≤500, NO user_name filter client-side), the LOUD failure
contract (a report is not telemetry — a partial report is a failure, the
opposite of the producer's fail-soft), the per-payload status taxonomy, the
receipt run-identity block (the join keys, additive to Wave 2's summary), and
the never-log-the-token contract.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import pytest

from neuralstrike.integrations.purple_report import (
    PurpleReadConfig,
    build_purple_report,
    classify_payload_status,
    fetch_alerts_for_run,
    fetch_alerts_window,
    fetch_logs_window,
    partition_logs,
    window_minutes_for,
)

RUN_HOST = "neuralstrike-20260920abcd1234"


def _config(**overrides: Any) -> PurpleReadConfig:
    base: dict[str, Any] = {
        "base_url": "http://localhost:8000",
        "api_token": "admin-api-token-value",
        "timeout": 5.0,
    }
    base.update(overrides)
    return PurpleReadConfig(**base)


def _receipt(**run_overrides: Any) -> dict[str, Any]:
    run: dict[str, Any] = {
        "run_id": "20260920abcd1234",
        "run_host": RUN_HOST,
        "actor": "purple-operator",
        "started_at": "2026-09-20T12:00:00+00:00",
        "ng_tenant": "default",
        "telemetry": {
            "ingest_url": "http://localhost:8000/api/v1/ingest",
            "start_delivered": True,
            "post_delivered": True,
        },
    }
    run.update(run_overrides)
    return {
        "screen": "neuralguard-http",
        "victim": "openai:mistral",
        "n": 8,
        "baseline_asr": 1.0,
        "defended_asr": 0.5,
        "delta": 0.5,
        "firewall_caught": 6,
        "catch_rate": 0.75,
        "baseline_succeeded": 8,
        "baseline_conclusive": 8,
        "defended_succeeded": 1,
        "defended_conclusive": 2,
        "run": run,
        "payloads": [
            {
                "id": "AC-RECON-001",
                "phase": "recon",
                "baseline_verdict": "SUCCEEDED",
                "defended_verdict": "INCONCLUSIVE",
                "firewall_verdict": "block",
                "firewall_rule_ids": ["PI-D-001"],
            },
            {
                "id": "AC-WEAP-001",
                "phase": "weaponize",
                "baseline_verdict": "SUCCEEDED",
                "defended_verdict": "INCONCLUSIVE",
                "firewall_verdict": "block",
                "firewall_rule_ids": ["JB-001"],
            },
            {
                "id": "AC-EXPL-001",
                "phase": "exploit",
                "baseline_verdict": "SUCCEEDED",
                "defended_verdict": "SUCCEEDED",
                "firewall_verdict": "allow",
                "firewall_rule_ids": [],
            },
            {
                "id": "AC-POST-001",
                "phase": "post_ex",
                "baseline_verdict": "SUCCEEDED",
                "defended_verdict": "RESISTED",
                "firewall_verdict": "allow",
                "firewall_rule_ids": [],
            },
        ],
    }


def _log_row(**overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "time": "2026-09-20T12:00:05+00:00",
        "host_name": RUN_HOST,
        "source": "neuralstrike",
        "event_category": "ai",
        "event_type": "info",
        "event_action": "probe_succeeded",
        "severity": "high",
        "user_name": "purple-operator",
        "raw_data": {"neuralstrike": {"kind": "probe_succeeded", "payload_id": "AC-EXPL-001"}},
    }
    row.update(overrides)
    return row


def _ng_row(**overrides: Any) -> Any:
    row: dict[str, Any] = {
        "time": "2026-09-20T12:00:05+00:00",
        "host_name": "neuralguard-fleet",
        "source": "neuralguard",
        "event_category": "intrusion_detection",
        "event_type": "info",
        "event_action": "verdict_block",
        "severity": "high",
        "user_name": "default",
        "raw_data": {"neuralguard": {"tenant_id": "default"}},
    }
    row.update(overrides)
    return row


def _alert_row(idx: int, **overrides: Any) -> Any:
    row: dict[str, Any] = {
        "id": idx,
        "time": "2026-09-20T12:00:10+00:00",
        "rule_name": "NeuralStrike Probe Succeeded",
        "severity": "high",
        "status": "new",
        "host_name": RUN_HOST,
        "evidence": [],
    }
    row.update(overrides)
    return row


def _handler(pages: dict[str, list[Any]], requests: list[str]):
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        for path, rows in pages.items():
            if f"{path}" in url:
                requests.append(url)
                offset = int(request.url.params.get("offset", 0))
                limit = int(request.url.params["limit"])
                return httpx.Response(200, json=rows[offset : offset + limit])
        requests.append(url)
        return httpx.Response(404, json={"detail": "not found"})

    return handler


# ── Config validation ───────────────────────────────────────────────────────


class TestPurpleReadConfig:
    def test_rejects_non_http_base(self) -> None:
        with pytest.raises(ValueError, match="http"):
            PurpleReadConfig(base_url="ftp://x", api_token="t")

    def test_rejects_empty_token(self) -> None:
        with pytest.raises(ValueError, match="api_token"):
            PurpleReadConfig(base_url="http://localhost:8000", api_token="")


# ── Loud failure contract (the OPPOSITE of the telemetry pipe) ─────────────


class TestLoudFailure:
    async def test_transport_error_raises(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("boom", request=request)

        transport = httpx.MockTransport(handler)
        with pytest.raises(RuntimeError, match="transport error"):
            await fetch_alerts_for_run(_config(), RUN_HOST, transport=transport)

    async def test_non_200_raises(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(503, json={"detail": "quarantine enforcement unavailable"})

        transport = httpx.MockTransport(handler)
        with pytest.raises(RuntimeError, match="503"):
            await fetch_alerts_for_run(_config(), RUN_HOST, transport=transport)

    async def test_malformed_body_raises(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=b"not-json")

        transport = httpx.MockTransport(handler)
        with pytest.raises(RuntimeError, match="malformed JSON"):
            await fetch_logs_window(_config(), minutes=5, transport=transport)

    async def test_non_array_body_raises(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"detail": "oops"})

        transport = httpx.MockTransport(handler)
        with pytest.raises(RuntimeError, match="expected a JSON array"):
            await fetch_logs_window(_config(), minutes=5, transport=transport)


# ── Pagination + window walk ───────────────────────────────────────────────


class TestPagination:
    async def test_alerts_pagination_walks_all_pages(self) -> None:
        full = [_alert_row(i) for i in range(1001)]  # > one /alerts page
        requests: list[str] = []
        transport = httpx.MockTransport(_handler_for(full, requests))
        rows = await fetch_alerts_for_run(_config(), RUN_HOST, transport=transport)
        assert len(rows) == 1001
        assert len(requests) == 2  # 1000 + 1 (short page)

    async def test_alerts_window_stops_at_since(self) -> None:
        # window: (12:00 - 5min grace) .. now → rows at 12:01 and 11:58 are in;
        # 11:00 is before the edge (rows are time-DESC; the walk STOPS there).
        now = datetime(2026, 9, 20, 12, 0, tzinfo=timezone.utc)
        rows = [
            _alert_row(1, time="2026-09-20T11:59:00+00:00"),
            _alert_row(2, time="2026-09-20T11:58:00+00:00"),
            _alert_row(3, time="2026-09-20T11:00:00+00:00"),
        ]
        transport = httpx.MockTransport(_static(rows))
        window = await fetch_alerts_window(
            _config(),
            since=now - timedelta(minutes=5),
            until=now,
            transport=transport,
        )
        assert [r["id"] for r in window] == [1, 2]

    async def test_window_minutes_covers_grace(self) -> None:
        started = datetime(2026, 9, 20, 12, 0)
        now = started + timedelta(minutes=3)
        # delta = now - (started - 5min) = 8 min → 8 // 60-min → 8 + 1
        minutes = window_minutes_for(started, grace_minutes=5, now=now)
        assert minutes == 9


def _handler(pages: dict[str, list[Any]], requests: list[str]):
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        for path, rows in pages.items():
            if f"{path}" in url:
                requests.append(url)
                offset = int(request.url.params.get("offset", 0))
                limit = int(request.url.params["limit"])
                return httpx.Response(200, json=rows[offset : offset + limit])
        requests.append(url)
        return httpx.Response(404, json={"detail": "not found"})

    return handler


def _handler_for(rows: list[Any], requests: list[str]):
    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        offset = int(request.url.params.get("offset", 0))
        limit = int(request.url.params["limit"])
        return httpx.Response(200, json=rows[offset : offset + limit])

    return handler


def _static(rows: list[Any]):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=rows)

    return handler


# ── Log partitioning (the join predicates) ───────────────────────────────


class TestPartitionLogs:
    def test_exercise_events_exact_host_and_source(self) -> None:
        rows = [
            _log_row(),
            _log_row(host_name=RUN_HOST + "-other"),
            _log_row(source="neuralguard"),
            _ng_row(),
        ]
        exercise, ng = partition_logs(rows, run_host=RUN_HOST, ng_tenant="default")
        assert len(exercise) == 1
        assert exercise[0]["event_action"] == "probe_succeeded"
        assert len(ng) == 1
        assert ng[0]["event_action"] == "verdict_block"

    def test_ng_tenant_filter(self) -> None:
        rows = [_ng_row(), _ng_row(user_name="other-tenant")]
        exercise, ng = partition_logs(rows, run_host=RUN_HOST, ng_tenant="default")
        assert not exercise
        assert len(ng) == 1

    def test_ng_tenant_none_passes_all_ng_rows(self) -> None:
        rows = [_ng_row(), _ng_row(user_name="anything")]
        _, ng = partition_logs(rows, run_host=RUN_HOST, ng_tenant=None)
        assert len(ng) == 2


# ── Status taxonomy (the honest four) ────────────────────────────────────


class TestClassifyStatus:
    def test_caught(self) -> None:
        assert classify_payload_status("block", "INCONCLUSIVE") == "caught"
        assert classify_payload_status("sanitize", "INCONCLUSIVE") == "caught"
        assert classify_payload_status("quarantine", "INCONCLUSIVE") == "caught"

    def test_gap(self) -> None:
        assert classify_payload_status("allow", "SUCCEEDED") == "gap"

    def test_resisted(self) -> None:
        assert classify_payload_status("allow", "RESISTED") == "resisted"

    def test_screen_error_is_never_a_catch(self) -> None:
        # A screen ERROR is unknown state: never counted as a catch, never as
        # a gap — it is honestly unscorable (the runner marks those INCONCLUSIVE).
        assert classify_payload_status("error", "SUCCEEDED") == "inconclusive"
        assert classify_payload_status("error", "INCONCLUSIVE") == "inconclusive"


# ── The report join ───────────────────────────────────────────────────────


class TestBuildPurpleReport:
    def _joined(self, receipt: dict, previous: dict | None = None) -> dict:
        exercise_rows = [
            _log_row(
                event_action="exercise_start",
                event_type="start",
                severity="info",
                raw_data={"neuralstrike": {"kind": "exercise_start", "actor": "purple-operator"}},
            ),
            _log_row(event_action="probe_succeeded"),
            _log_row(
                event_action="probe_inconclusive",
                severity="info",
                raw_data={"neuralstrike": {"kind": "probe_inconclusive", "payload_id": "AC-RECON-001"}},
            ),
            _log_row(
                event_action="exercise_end",
                event_type="end",
                severity="info",
                raw_data={"neuralstrike": {"kind": "exercise_end", "actor": "purple-operator"}},
            ),
        ]
        ng_rows = [_ng_row(event_action="verdict_block"), _ng_row(event_action="verdict_block")]
        return build_purple_report(
            receipt,
            exercise_events=exercise_rows,
            ng_events=ng_rows,
            run_alerts=[_alert_row(1)],
            window_alerts=[
                _alert_row(
                    2,
                    rule_name="NeuralGuard Confirmed AI Attack Block",
                    host_name="neuralguard-fleet",
                ),
                _alert_row(1),  # dedup with the run alert
            ],
            ng_tenant="default",
            previous_receipt=previous,
        )

    def test_requires_run_identity(self) -> None:
        receipt = _receipt()
        receipt.pop("run")
        with pytest.raises(ValueError, match="run identity"):
            build_purple_report(receipt, exercise_events=[], ng_events=[], run_alerts=[], window_alerts=[])

    def test_counts_and_alert_join(self) -> None:
        report = self._joined(_receipt())
        assert report["scarlet"]["exercise_events"] == {
            "exercise_start": 1,
            "probe_succeeded": 1,
            "probe_inconclusive": 1,
            "exercise_end": 1,
        }
        assert report["scarlet"]["firewall_events"] == {"verdict_block": 2}
        # Dedup: the run alert appears twice in the inputs (run + window walk).
        assert report["scarlet"]["alert_count"] == 2
        names = rule_names(report)
        assert "NeuralStrike Probe Succeeded" in names
        assert "NeuralGuard Confirmed AI Attack Block" in names

    def test_per_payload_status_and_probe_join(self) -> None:
        report = self._joined(_receipt())
        by_id = {p["payload_id"]: p for p in report["payloads"]}
        assert by_id["AC-RECON-001"]["status"] == "caught"
        assert by_id["AC-RECON-001"]["firewall_rule_ids"] == ["PI-D-001"]
        assert by_id["AC-RECON-001"]["scarlet_probe_action"] == "probe_inconclusive"
        assert by_id["AC-EXPL-001"]["status"] == "gap"
        assert by_id["AC-EXPL-001"]["scarlet_probe_action"] == "probe_succeeded"
        assert by_id["AC-POST-001"]["status"] == "resisted"
        assert report["defense_gaps"] == ["AC-EXPL-001"]
        assert "1/4" in report["gap_headline"]

    def test_trend_against_previous(self) -> None:
        previous = _receipt()
        previous["catch_rate"] = 0.25
        previous["firewall_caught"] = 2
        report = self._joined(_receipt(), previous=previous)
        trend = report["trend"]
        assert trend["catch_rate"] == 0.75
        assert trend["catch_rate_previous"] == 0.25
        assert trend["catch_rate_delta"] == pytest.approx(0.5)
        assert trend["firewall_caught_previous"] == 2

    def test_run_block_carries_join_keys(self) -> None:
        report = self._joined(_receipt())
        assert report["run"]["run_host"] == RUN_HOST
        assert report["run"]["actor"] == "purple-operator"
        assert report["run"]["ng_tenant"] == "default"


def rule_names(report: dict) -> set[str]:
    return {a["rule_name"] for a in report["scarlet"]["alerts"]}


# ── Receipt run-identity block (additive, join keys, no tokens) ──────────


class TestReceiptRunIdentity:
    def test_run_block_shape(self) -> None:
        run = _receipt()["run"]
        assert run["run_host"].startswith("neuralstrike-")
        assert run["actor"]
        assert datetime.fromisoformat(run["started_at"]) is not None
        assert run["telemetry"]["ingest_url"].endswith("/api/v1/ingest")

    def test_no_token_anywhere_in_receipt(self) -> None:
        text = json.dumps(_receipt())
        assert "ingest-secret-token-value" not in text
        assert "admin-api-token-value" not in text


# ── Token never logged (the pinned contract) ─────────────────────────────


class TestTokenNeverLogged:
    async def test_fetches_never_log_the_token(self, caplog: pytest.LogCaptureFixture) -> None:
        rows = [_alert_row(1)]
        transport = httpx.MockTransport(_static(rows))
        with caplog.at_level(logging.DEBUG, logger="neuralstrike.integrations.purple_report"):
            await fetch_alerts_for_run(_config(), RUN_HOST, transport=transport)
        assert caplog.records, "the read client must log request lines (never the token)"
        serialized = " ".join(r.getMessage() for r in caplog.records) + str(
            [r.__dict__ for r in caplog.records]
        )
        assert "admin-api-token-value" not in serialized


# ── Window math ───────────────────────────────────────────────────────────


class TestWindowMath:
    def test_window_minutes_includes_grace(self) -> None:
        started = datetime(2026, 9, 20, 12, 0)
        now = started + timedelta(minutes=2)
        # delta = now - (started - 5min) = 7 min → 7 + 1 (inclusive edge)
        minutes = window_minutes_for(started, grace_minutes=5, now=now)
        assert minutes == 8
