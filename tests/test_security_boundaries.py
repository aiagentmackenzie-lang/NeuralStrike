"""NS-06/07/08 controlled regressions using synthetic credentials only."""

import io
import logging

import httpx
import pytest

from neuralstrike.adapters.a2a import A2AAdapter, A2AError
from neuralstrike.adapters.mcp_http import MCPHTTPAdapter
from neuralstrike.utils.logging import RedactingFilter


@pytest.mark.parametrize("style", ["positional", "mapping", "exception"])
def test_rendered_logs_redact_format_arguments_and_exceptions(style):
    sentinel = "sk-SYNTHETIC_LOCAL_ONLY_1234567890"
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.addFilter(RedactingFilter())
    logger = logging.Logger("fixture")
    logger.addHandler(handler)
    if style == "positional":
        logger.warning("credential=%s", sentinel)
    elif style == "mapping":
        logger.warning("credential=%(value)s", {"value": sentinel})
    else:
        try:
            raise ValueError(sentinel)
        except ValueError:
            logger.exception("controlled failure")
    assert sentinel not in stream.getvalue()
    assert "[REDACTED]" in stream.getvalue()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "destination",
    ["https://elsewhere.invalid/rpc", "http://authorized.invalid/rpc", "https://authorized.invalid.evil/rpc"],
)
async def test_a2a_rejects_changed_destination_before_request(destination):
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(
            200,
            json={
                "url": destination,
                "security": [["bearer"]],
                "securitySchemes": {"bearer": {"type": "http"}},
            },
        )

    adapter = A2AAdapter(
        "https://authorized.invalid", bearer_token="SYNTHETIC_TOKEN", transport=httpx.MockTransport(handler)
    )
    try:
        with pytest.raises(A2AError):
            await adapter.send_message("fixture")
        assert len(requests) == 1
    finally:
        await adapter.close()


@pytest.mark.asyncio
async def test_mcp_discovery_never_calls_tools():
    methods = []

    def handler(request):
        import json

        body = json.loads(request.content)
        methods.append(body["method"])
        if body["method"] == "tools/list":
            result = {"tools": [{"name": "delete_all_records", "inputSchema": {}}]}
        else:
            result = {}
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body.get("id"), "result": result})

    adapter = MCPHTTPAdapter("http://fixture/mcp", transport=httpx.MockTransport(handler))
    try:
        report = await adapter.scan()
        assert report["canary_calls"] == []
        assert "tools/call" not in methods
    finally:
        await adapter.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "destination,allowed,authorized",
    [
        ("https://AUTHORIZED.invalid:443/rpc", (), True),
        ("https://authorized.invalid:444/rpc", (), False),
        ("https://user:pass@authorized.invalid/rpc", (), False),
        ("https://elsewhere.invalid/rpc", ("https://elsewhere.invalid",), False),
    ],
)
async def test_a2a_credential_origin_and_legitimate_controls(destination, allowed, authorized):
    requests = []

    def handler(request):
        requests.append(request)
        if request.method == "GET":
            return httpx.Response(
                200,
                json={
                    "url": destination,
                    "security": [["bearer"]],
                    "securitySchemes": {"bearer": {"type": "http"}},
                },
            )
        return httpx.Response(200, json={"result": {"ok": True}})

    adapter = A2AAdapter(
        "https://authorized.invalid",
        bearer_token="SYNTHETIC_TOKEN",
        allowed_origins=allowed,
        transport=httpx.MockTransport(handler),
    )
    try:
        if authorized or allowed:
            assert await adapter.send_message("fixture") == {"ok": True}
            assert ("authorization" in requests[-1].headers) is authorized
        else:
            with pytest.raises(A2AError):
                await adapter.send_message("fixture")
            assert len(requests) == 1
    finally:
        await adapter.close()


@pytest.mark.asyncio
async def test_mcp_name_heuristic_opt_in_is_insufficient():
    from neuralstrike.adapters.mcp_http import MCPError

    adapter = MCPHTTPAdapter("http://fixture/mcp")
    try:
        with pytest.raises(MCPError, match="authorized_tool_calls"):
            await adapter.scan(call_canaries=True)
    finally:
        await adapter.close()


def test_redaction_preserves_ordinary_formatting_and_disabled_mode():
    record = logging.LogRecord("fixture", logging.INFO, "file", 1, "hello %s", ("world",), None)
    assert RedactingFilter().filter(record)
    assert record.getMessage() == "hello world"
    secret_record = logging.LogRecord(
        "fixture", logging.INFO, "file", 1, "sk-SYNTHETIC_LOCAL_ONLY_1234567890", (), None
    )
    assert RedactingFilter(enabled=False).filter(secret_record)
    assert "SYNTHETIC" in secret_record.getMessage()


@pytest.mark.asyncio
async def test_a2a_redirect_is_not_followed_before_destination_authorization():
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(302, headers={"Location": "https://elsewhere.invalid/agent-card.json"})

    adapter = A2AAdapter(
        "https://authorized.invalid",
        bearer_token="SYNTHETIC_ORIGIN_TOKEN",
        transport=httpx.MockTransport(handler),
    )
    try:
        with pytest.raises(A2AError):
            await adapter.send_message("fixture")
        assert len(requests) == 1
        assert requests[0].url.host == "authorized.invalid"
    finally:
        await adapter.close()


@pytest.mark.asyncio
async def test_a2a_cached_card_is_reauthorized_for_every_rpc():
    from dataclasses import replace

    requests = []

    def handler(request):
        requests.append(request)
        if request.method == "GET":
            return httpx.Response(
                200,
                json={
                    "url": "https://authorized.invalid/rpc",
                    "security": [["bearer"]],
                    "securitySchemes": {"bearer": {"type": "http"}},
                },
            )
        return httpx.Response(200, json={"result": {"ok": True}})

    adapter = A2AAdapter(
        "https://authorized.invalid",
        bearer_token="SYNTHETIC_ORIGIN_TOKEN",
        transport=httpx.MockTransport(handler),
    )
    try:
        assert await adapter.send_message("fixture") == {"ok": True}
        assert requests[-1].headers["Authorization"] == "Bearer SYNTHETIC_ORIGIN_TOKEN"
        assert adapter.card is not None
        adapter._card = replace(adapter.card, url="https://elsewhere.invalid/rpc")
        with pytest.raises(A2AError, match="not authorized"):
            await adapter.send_message("fixture")
        assert len(requests) == 2
    finally:
        await adapter.close()


@pytest.mark.asyncio
async def test_a2a_client_cert_remains_origin_bound_even_when_destination_allowed():
    from neuralstrike.adapters.a2a import AgentCard

    requests = []
    adapter = A2AAdapter(
        "https://authorized.invalid",
        client_cert=("synthetic-cert.pem", "synthetic-key.pem"),
        allowed_origins=("https://elsewhere.invalid",),
        transport=httpx.MockTransport(lambda request: requests.append(request) or httpx.Response(200)),
    )
    adapter._card = AgentCard(url="https://elsewhere.invalid/rpc")
    try:
        with pytest.raises(A2AError, match="client certificate"):
            await adapter.send_message("fixture")
        assert not requests
        assert adapter._client is None  # rejected before TLS/client construction
    finally:
        await adapter.close()
