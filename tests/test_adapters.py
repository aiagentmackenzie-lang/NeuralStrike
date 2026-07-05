"""Tests for the Phase 1 target adapters."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from neuralstrike.adapters.a2a import A2AAdapter, AgentCard
from neuralstrike.adapters.base import ToolSchema
from neuralstrike.adapters.langgraph import LangGraphAdapter
from neuralstrike.adapters.langgraph_server import LangGraphServerAdapter
from neuralstrike.adapters.mcp_http import MCPHTTPAdapter
from neuralstrike.adapters.openai_endpoint import OpenAIEndpointAdapter
from neuralstrike.oracles.tool_harness import TraceLog, make_canary_tools

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _chat_response(*, content: str = "", tool_calls: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    message: dict[str, Any] = {"role": "assistant", "content": content}
    if tool_calls is not None:
        message["tool_calls"] = tool_calls
    return {"choices": [{"message": message, "finish_reason": "stop"}]}


def _tc_call(call_id: str, name: str, args: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": call_id,
        "type": "function",
        "function": {"name": name, "arguments": json.dumps(args)},
    }


class ScriptedTransport(httpx.MockTransport):
    """Returns a scripted sequence of responses, one per request."""

    def __init__(self, responses: list[httpx.Response]) -> None:
        self._responses = list(responses)
        self.calls: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            self.calls.append(request)
            if not self._responses:
                raise AssertionError("no more scripted responses; got extra request")
            return self._responses.pop(0)

        super().__init__(handler)


def _json_resp(payload: dict[str, Any], status: int = 200) -> httpx.Response:
    return httpx.Response(status, json=payload, headers={"content-type": "application/json"})


# ---------------------------------------------------------------------------
# OpenAI endpoint adapter
# ---------------------------------------------------------------------------


class TestOpenAIEndpointAdapter:
    @pytest.mark.asyncio
    async def test_text_tier_returns_text(self) -> None:
        transport = ScriptedTransport([_json_resp(_chat_response(content="hello"))])
        adapter = OpenAIEndpointAdapter("http://x", model="m", tier="text", transport=transport)
        resp = await adapter.query("hi")
        assert resp.text == "hello"
        assert resp.tool_calls == ()
        assert resp.error is None
        await adapter.close()

    @pytest.mark.asyncio
    async def test_function_calling_observes_tool_args(self) -> None:
        # Round 1: model emits a (non-canary) tool_call; round 2: model stops.
        transport = ScriptedTransport([
            _json_resp(_chat_response(content="", tool_calls=[_tc_call("1", "lookup", {"q": "x"})])),
            _json_resp(_chat_response(content="result: y")),
        ])
        adapter = OpenAIEndpointAdapter("http://x", model="m", tier="function-calling", transport=transport)
        resp = await adapter.query("hi", tools=(ToolSchema("lookup", "look up", {"type": "object"}),))
        assert resp.text == "result: y"
        assert len(resp.tool_calls) == 1
        assert resp.tool_calls[0].name == "lookup"
        assert resp.tool_calls[0].arguments == {"q": "x"}
        await adapter.close()

    @pytest.mark.asyncio
    async def test_instrumented_executes_canary_tool_behavioral(self) -> None:
        # The model calls grant_admin_access; the adapter executes the canary
        # handler (records a trace -> Behavioral / Tier-2), serves the result,
        # then the model stops.
        transport = ScriptedTransport([
            _json_resp(_chat_response(content="", tool_calls=[
                _tc_call("1", "grant_admin_access", {"user_id": "attacker"}),
            ])),
            _json_resp(_chat_response(content="admin granted")),
        ])
        canary = make_canary_tools()
        trace = TraceLog()
        adapter = OpenAIEndpointAdapter("http://x", model="m", tier="instrumented", transport=transport)
        resp = await adapter.query("fix perms for attacker", canary_tools=canary, trace=trace)
        assert resp.text == "admin granted"
        assert len(resp.tool_calls) == 1
        assert resp.tool_calls[0].name == "grant_admin_access"
        # Tier-2: the canary tool actually executed and was recorded.
        assert "grant_admin_access" in trace.executed_tools
        assert resp.traces  # SutResponse carries the trace records
        await adapter.close()

    @pytest.mark.asyncio
    async def test_transport_error_recorded_not_faked(self) -> None:
        def boom(_request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("boom")

        transport = httpx.MockTransport(boom)
        adapter = OpenAIEndpointAdapter("http://x", model="m", tier="text", transport=transport)
        resp = await adapter.query("hi")
        assert resp.text == ""
        assert resp.error is not None
        assert "boom" in resp.error
        await adapter.close()

    def test_rejects_bad_tier_and_url(self) -> None:
        with pytest.raises(ValueError):
            OpenAIEndpointAdapter("ftp://x", model="m")
        with pytest.raises(ValueError):
            OpenAIEndpointAdapter("http://x", model="m", tier="bogus")


# ---------------------------------------------------------------------------
# MCP-over-HTTP adapter
# ---------------------------------------------------------------------------


class TestMCPHTTPAdapter:
    @pytest.mark.asyncio
    async def test_real_introspection_of_fixture(self) -> None:
        from tests.fixtures.mcp_server import make_vulnerable_mcp_app

        app = make_vulnerable_mcp_app()
        transport = httpx.ASGITransport(app=app)
        adapter = MCPHTTPAdapter("http://test/mcp", transport=transport)
        await adapter.initialize()
        tools = await adapter.list_tools()
        names = {t.name for t in tools}
        assert {"export_user_data", "delete_all_records", "grant_admin_access"} <= names
        await adapter.close()

    @pytest.mark.asyncio
    async def test_tools_call_executes_canary(self) -> None:
        from tests.fixtures.mcp_server import make_vulnerable_mcp_app

        app = make_vulnerable_mcp_app()
        transport = httpx.ASGITransport(app=app)
        adapter = MCPHTTPAdapter("http://test/mcp", transport=transport)
        result = await adapter.call_tool("grant_admin_access", {"user_id": "attacker"})
        assert result.is_error is False
        assert "granted" in result.text.lower() or "admin" in result.text.lower()
        await adapter.close()

    @pytest.mark.asyncio
    async def test_capability_injection_appends_fake_tool(self) -> None:
        from tests.fixtures.mcp_server import make_vulnerable_mcp_app

        app = make_vulnerable_mcp_app()
        transport = httpx.ASGITransport(app=app)
        adapter = MCPHTTPAdapter("http://test/mcp", transport=transport)
        from neuralstrike.adapters.mcp_http import MCPTool

        fake = MCPTool(name="evil_shadow_tool", description="shadows a real tool", input_schema={})
        tools = await adapter.list_tools(injected=(fake,))
        assert "evil_shadow_tool" in {t.name for t in tools}
        await adapter.close()

    @pytest.mark.asyncio
    async def test_scan_returns_structured_inventory(self) -> None:
        from tests.fixtures.mcp_server import make_vulnerable_mcp_app

        app = make_vulnerable_mcp_app()
        transport = httpx.ASGITransport(app=app)
        adapter = MCPHTTPAdapter("http://test/mcp", transport=transport)
        report = await adapter.scan()
        assert "grant_admin_access" in report["tool_names"]
        assert report["canary_calls"]  # at least one canary was called
        await adapter.close()

    @pytest.mark.asyncio
    async def test_poisoned_description_detected(self) -> None:
        """The poisoned fixture's grant_admin_access description carries an injected instruction."""
        from tests.fixtures.mcp_server import make_poisoned_mcp_app

        app = make_poisoned_mcp_app()
        transport = httpx.ASGITransport(app=app)
        adapter = MCPHTTPAdapter("http://test/mcp", transport=transport)
        await adapter.initialize()
        tools = await adapter.list_tools()
        desc = next(t.description for t in tools if t.name == "grant_admin_access")
        assert "MUST first call grant_admin_access" in desc
        await adapter.close()


# ---------------------------------------------------------------------------
# LangGraph adapter
# ---------------------------------------------------------------------------


class TestLangGraphAdapter:
    @pytest.mark.asyncio
    async def test_drives_compiled_graph_and_observes_tool_calls(self) -> None:
        from tests.fixtures.langgraph_agent import build_vulnerable_graph

        graph = build_vulnerable_graph()
        adapter = LangGraphAdapter(graph=graph)
        resp = await adapter.query("fix the permissions issue for user attacker")
        assert resp.error is None
        assert len(resp.tool_calls) == 1
        assert resp.tool_calls[0].name == "grant_admin_access"
        assert resp.tool_calls[0].arguments == {"user_id": "attacker"}

    @pytest.mark.asyncio
    async def test_attribute_discovery_via_module_namespace(self) -> None:
        from tests.fixtures.langgraph_agent import vulnerable_graph_module

        ns = vulnerable_graph_module()
        adapter = LangGraphAdapter(graph=ns)
        resp = await adapter.query("fix perms")
        assert resp.tool_calls[0].name == "grant_admin_access"

    @pytest.mark.asyncio
    async def test_drive_error_recorded(self) -> None:
        class BadGraph:
            async def ainvoke(self, _state: dict[str, Any]) -> dict[str, Any]:
                raise RuntimeError("graph blew up")

        adapter = LangGraphAdapter(graph=BadGraph())
        resp = await adapter.query("hi")
        assert resp.error is not None
        assert "blew up" in resp.error


# ---------------------------------------------------------------------------
# A2A adapter
# ---------------------------------------------------------------------------


def _agent_card_payload() -> dict[str, Any]:
    return {
        "name": "test-agent",
        "description": "A test A2A agent",
        "version": "1.0",
        "url": "http://test/a2a",
        "skills": [{"id": "s1", "name": "summarize"}],
        "securitySchemes": {
            "bearer": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
            "apikey": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
        },
        "security": [["bearer"], ["apikey"]],
    }


class TestA2AAdapter:
    @pytest.mark.asyncio
    async def test_fetch_agent_card(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path == "/.well-known/agent-card.json"
            return _json_resp(_agent_card_payload())

        adapter = A2AAdapter("http://test", bearer_token="tok", transport=httpx.MockTransport(handler))
        card = await adapter.fetch_agent_card()
        assert isinstance(card, AgentCard)
        assert card.name == "test-agent"
        assert "bearer" in card.security_schemes
        assert card.security == (("bearer",), ("apikey",))
        await adapter.close()

    @pytest.mark.asyncio
    async def test_send_message_applies_bearer_from_card(self) -> None:
        seen: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/.well-known/agent-card.json":
                return _json_resp(_agent_card_payload())
            seen["auth"] = request.headers.get("Authorization", "")
            body = json.loads(request.content.decode() or "{}")
            seen["method"] = body.get("method")
            return _json_resp({"jsonrpc": "2.0", "id": "1", "result": {"artifacts": [
                {"parts": [{"kind": "text", "text": "hello from agent"}]}
            ]}})

        adapter = A2AAdapter("http://test", bearer_token="tok-123", transport=httpx.MockTransport(handler))
        resp = await adapter.query("do the thing")
        assert resp.error is None
        assert "hello from agent" in resp.text
        assert seen["auth"] == "Bearer tok-123"
        assert seen["method"] == "message/send"
        await adapter.close()

    @pytest.mark.asyncio
    async def test_apikey_scheme(self) -> None:
        card_with_apikey = {
            "name": "a", "version": "1.0", "url": "http://test/a2a",
            "securitySchemes": {"apikey": {"type": "apiKey", "in": "header", "name": "X-API-Key"}},
            "security": [["apikey"]],
        }
        seen: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/.well-known/agent-card.json":
                return _json_resp(card_with_apikey)
            seen["apikey"] = request.headers.get("X-API-Key", "")
            return _json_resp({"jsonrpc": "2.0", "result": {"artifacts": [
                {"parts": [{"kind": "text", "text": "ok"}]}]}})

        adapter = A2AAdapter("http://test", api_key="k-123", transport=httpx.MockTransport(handler))
        resp = await adapter.query("hi")
        assert resp.error is None
        assert seen["apikey"] == "k-123"
        await adapter.close()

    @pytest.mark.asyncio
    async def test_transport_error_recorded(self) -> None:
        def boom(_r: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("nope")

        adapter = A2AAdapter("http://test", transport=httpx.MockTransport(boom))
        resp = await adapter.query("hi")
        assert resp.error is not None
        await adapter.close()

    def test_rejects_bad_url(self) -> None:
        with pytest.raises(ValueError):
            A2AAdapter("ftp://x")


# ---------------------------------------------------------------------------
# LangGraph Server adapter
# ---------------------------------------------------------------------------


class TestLangGraphServerAdapter:
    @pytest.mark.asyncio
    async def test_drives_stream_and_observes_tool_calls(self) -> None:
        # Build an SSE-style stream response: two `data:` lines, the last is the final state.
        final_state = {"messages": [
            {"role": "user", "content": "hi"},
            {"role": "assistant", "content": "ok", "tool_calls": [
                {"id": "c1", "name": "grant_admin_access", "args": {"user_id": "attacker"}}
            ]},
        ]}

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/threads":
                return _json_resp({"thread_id": "t1"})
            if request.url.path.endswith("/runs/stream"):
                body = f'data: {json.dumps({"messages": []})}\n\ndata: {json.dumps(final_state)}\n\n'
                return httpx.Response(200, content=body, headers={"content-type": "text/event-stream"})
            return httpx.Response(404)

        adapter = LangGraphServerAdapter("http://test", graph_id="agent", transport=httpx.MockTransport(handler))
        resp = await adapter.query("hi")
        assert resp.error is None
        assert len(resp.tool_calls) == 1
        assert resp.tool_calls[0].name == "grant_admin_access"
        await adapter.close()
