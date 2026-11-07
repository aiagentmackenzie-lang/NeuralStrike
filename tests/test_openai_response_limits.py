"""Controlled protocol failures must stop before local tool execution."""

import json

import httpx
import pytest

from neuralstrike.adapters.openai_endpoint import OpenAIEndpointAdapter


class Chunks(httpx.AsyncByteStream):
    def __init__(self, chunks):
        self.chunks = chunks
        self.reads = 0
        self.closed = False

    async def __aiter__(self):
        for chunk in self.chunks:
            self.reads += 1
            yield chunk

    async def aclose(self):
        self.closed = True


async def test_oversized_stream_stops_reading_and_closes_without_retry():
    stream = Chunks([b"x" * 65, b"never read"])
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, stream=stream)

    adapter = OpenAIEndpointAdapter(
        "http://local", model="fixture", max_response_bytes=64, transport=httpx.MockTransport(handler)
    )
    try:
        response = await adapter.query("test")
        assert response.error == "response exceeded max_response_bytes=64"
        assert stream.reads == 1
        assert stream.closed
        assert len(calls) == 1
        assert "response_text" not in response.exchanges[0]
        assert response.exchanges[0]["capture_complete"] is False
    finally:
        await adapter.close()


@pytest.mark.parametrize(
    "message",
    [
        None,
        [],
        {"content": []},
        {"tool_calls": [None]},
        {
            "tool_calls": [
                {"id": "x", "type": "function", "function": {"name": "x", "arguments": "{}"}},
                {"id": "x", "type": "function", "function": {"name": "x", "arguments": "{}"}},
            ]
        },
        {"tool_calls": [{"id": "x", "type": "function", "function": {"name": "x", "arguments": "broken"}}]},
    ],
)
async def test_malformed_message_is_explicit_error_not_exception(message):
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, json={"choices": [{"message": message}]})
    )
    adapter = OpenAIEndpointAdapter("http://local", model="fixture", transport=transport)
    try:
        response = await adapter.query("test")
        assert response.error and response.error.startswith("invalid chat completion:")
        assert not response.tool_calls
    finally:
        await adapter.close()


async def test_exact_limit_preserves_private_body_and_response():
    body = json.dumps({"choices": [{"message": {"content": "ok"}}]}).encode()
    adapter = OpenAIEndpointAdapter(
        "http://local",
        model="fixture",
        max_response_bytes=len(body),
        transport=httpx.MockTransport(lambda request: httpx.Response(200, content=body)),
    )
    try:
        response = await adapter.query("test")
        assert response.error is None
        assert response.text == "ok"
        assert response.exchanges[0]["response_text"] == body.decode()
        assert response.exchanges[0]["capture_complete"] is True
    finally:
        await adapter.close()


async def test_compressed_body_is_limited_after_decompression():
    import gzip

    stream = Chunks([gzip.compress(b"x" * 1000)])
    adapter = OpenAIEndpointAdapter(
        "http://local",
        model="fixture",
        max_response_bytes=100,
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, stream=stream, headers={"content-encoding": "gzip"})
        ),
    )
    try:
        response = await adapter.query("test")
        assert response.error == "response exceeded max_response_bytes=100"
        assert stream.closed
    finally:
        await adapter.close()


async def test_cancellation_closes_inflight_stream_without_retry():
    import asyncio

    started = asyncio.Event()

    class BlockingStream(Chunks):
        async def __aiter__(self):
            started.set()
            await asyncio.Event().wait()
            yield b""

    stream = BlockingStream([])
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, stream=stream)

    adapter = OpenAIEndpointAdapter("http://local", model="fixture", transport=httpx.MockTransport(handler))
    task = asyncio.create_task(adapter.query("test"))
    try:
        await asyncio.wait_for(started.wait(), timeout=1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert stream.closed
        assert len(calls) == 1
    finally:
        task.cancel()
        await adapter.close()


@pytest.mark.parametrize("limit", [0, -1, True, 1.5])
def test_invalid_limits_rejected_before_network(limit):
    with pytest.raises(ValueError, match="positive integer"):
        OpenAIEndpointAdapter("http://local", model="fixture", max_response_bytes=limit)


@pytest.mark.parametrize("status", [429, 503])
async def test_rate_limit_and_outage_are_errors_without_retry(status):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(status, json={"error": "unavailable"}, headers={"retry-after": "0"})

    adapter = OpenAIEndpointAdapter("http://local", model="fixture", transport=httpx.MockTransport(handler))
    try:
        response = await adapter.query("test")
        assert f"HTTP {status}" in response.error
        assert len(calls) == 1
        assert response.exchanges[0]["capture_complete"] is True
    finally:
        await adapter.close()


async def test_malformed_batch_never_executes_valid_prefix():
    from neuralstrike.oracles.tool_harness import TraceLog, make_canary_tools

    canaries = make_canary_tools()
    message = {
        "tool_calls": [
            {"id": "one", "type": "function", "function": {"name": canaries[0].name, "arguments": "{}"}},
            None,
        ]
    }
    adapter = OpenAIEndpointAdapter(
        "http://local",
        model="fixture",
        tier="instrumented",
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json={"choices": [{"message": message}]})
        ),
    )
    trace = TraceLog()
    try:
        response = await adapter.query("test", canary_tools=canaries, trace=trace)
        assert response.error.startswith("invalid chat completion:")
        assert trace.to_list() == []
        assert response.exchanges[0]["response"]["choices"][0]["message"] == message
    finally:
        await adapter.close()
