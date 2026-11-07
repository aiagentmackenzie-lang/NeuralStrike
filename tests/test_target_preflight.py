"""Preflight checks observed capabilities, never security resistance."""

import asyncio
import json

import httpx
import pytest

from neuralstrike.adapters.preflight import check_openai_target


@pytest.mark.parametrize("mode", ["tools", "text", "auth", "timeout"])
async def test_preflight_records_observed_capability_and_closes(mode):
    requests = []

    class Transport(httpx.AsyncBaseTransport):
        closed = False

        async def handle_async_request(self, request):
            requests.append(request)
            assert request.headers["Authorization"] == "Bearer synthetic"
            payload = json.loads(request.content)
            assert payload["model"] == "fixture"
            if mode == "timeout":
                await asyncio.Event().wait()
            if mode == "auth":
                return httpx.Response(401, json={"error": "unauthorized"})
            if mode == "tools" and len(requests) == 1:
                message = {
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "probe-1",
                            "type": "function",
                            "function": {
                                "name": "neuralstrike_preflight",
                                "arguments": '{"value":"probe"}',
                            },
                        }
                    ],
                }
            else:
                message = {"content": "ok"}
            return httpx.Response(200, json={"model": "fixture-build-1", "choices": [{"message": message}]})

        async def aclose(self):
            self.closed = True

    transport = Transport()
    receipt = await check_openai_target(
        "http://local",
        model="fixture",
        api_key="synthetic",
        timeout=0.05,
        require_tools=True,
        transport=transport,
    )
    assert transport.closed
    assert receipt["security_assessment"] is False
    assert receipt["ready"] is (mode == "tools")
    assert receipt["tool_call_observed"] is (mode == "tools")
    assert receipt["status"] == ("ready" if mode == "tools" else "incomplete")
    assert receipt["versions"]["httpx"]
    assert len(requests) == (2 if mode == "tools" else 1)
    assert "Bearer synthetic" not in json.dumps(receipt)
    if mode == "timeout":
        assert receipt["error"] == "preflight timed out"
    if mode == "text":
        assert receipt["error"] == "requested tool capability was not demonstrated"


@pytest.mark.parametrize("status", [200, 401])
async def test_preflight_close_failure_retains_capability_receipt_as_incomplete(status):
    class Transport(httpx.AsyncBaseTransport):
        closed_attempts = 0

        async def handle_async_request(self, request):
            return httpx.Response(status, json={"choices": [{"message": {"content": "ok"}}]})

        async def aclose(self):
            self.closed_attempts += 1
            raise RuntimeError("synthetic close failure")

    transport = Transport()
    receipt = await check_openai_target(
        "http://fixture", model="fixture", require_tools=False, transport=transport
    )
    assert receipt["ready"] is False
    assert receipt["status"] == "incomplete"
    assert receipt["http_statuses"] == [status]
    assert receipt["cleanup"] == {"status": "failed", "error_type": "RuntimeError"}
    assert "cleanup failed" in receipt["error"]
    if status == 401:
        assert "401" in receipt["error"]
    assert transport.closed_attempts == 1


def test_doctor_persists_incomplete_receipt_when_client_close_fails(tmp_path, monkeypatch):
    from unittest.mock import AsyncMock

    from typer.testing import CliRunner

    from neuralstrike.adapters.openai_endpoint import OpenAIEndpointAdapter
    from neuralstrike.evaluation.verdict import SutResponse
    from neuralstrike.main import app

    monkeypatch.setattr(
        OpenAIEndpointAdapter,
        "query",
        AsyncMock(
            return_value=SutResponse(
                text="ok",
                exchanges=({"status_code": 200},),
            )
        ),
    )
    monkeypatch.setattr(
        OpenAIEndpointAdapter, "close", AsyncMock(side_effect=RuntimeError("synthetic close"))
    )
    output = tmp_path / "preflight.json"
    result = CliRunner().invoke(
        app, ["doctor", "--url", "http://fixture", "--model", "fixture", "--text-only", "--out", str(output)]
    )
    assert result.exit_code == 3, result.output
    receipt = json.loads(output.read_text())
    assert receipt["ready"] is False
    assert receipt["cleanup"]["status"] == "failed"
    assert receipt["http_statuses"] == [200]
    assert output.stat().st_mode & 0o777 == 0o600
