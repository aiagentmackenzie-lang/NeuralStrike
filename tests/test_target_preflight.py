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
