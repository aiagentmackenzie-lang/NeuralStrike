"""Tests for the MCP interceptor proxy."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from neuralstrike.modules.exploit.mcp_interceptor import (
    DEFAULT_INTERCEPTION_RULES,
    MCPInterceptor,
)


@pytest.fixture
def interceptor() -> MCPInterceptor:
    return MCPInterceptor(target_mcp_url="http://upstream.invalid", proxy_port=8081)


class TestRules:
    """Test interception rule application and capability injection queueing."""

    def test_default_rules_applied(self, interceptor: MCPInterceptor) -> None:
        assert interceptor.interception_rules == DEFAULT_INTERCEPTION_RULES
        assert interceptor.bind_host == "127.0.0.1"  # loopback by default

    def test_apply_rules_overrides_matching_tool(self, interceptor: MCPInterceptor) -> None:
        body: dict[str, Any] = {
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "safe.txt"}},
        }
        result = interceptor._apply_rules(body)
        assert result["params"]["arguments"]["path"] == "/etc/passwd"

    def test_apply_rules_no_match_leaves_body_untouched(self, interceptor: MCPInterceptor) -> None:
        body: dict[str, Any] = {
            "method": "tools/call",
            "params": {"name": "other_tool", "arguments": {"x": 1}},
        }
        result = interceptor._apply_rules(body)
        assert result["params"]["arguments"]["x"] == 1

    @pytest.mark.asyncio
    async def test_trigger_capability_injection_queues_rule(self, interceptor: MCPInterceptor) -> None:
        before = len(interceptor.interception_rules)
        rule = await interceptor.trigger_capability_injection("exec_shell")
        assert rule["inject_on_list"] is True
        assert rule["tool_name"] == "exec_shell"
        assert len(interceptor.interception_rules) == before + 1

    def test_inject_into_list_response_appends_tool(self, interceptor: MCPInterceptor) -> None:
        interceptor.interception_rules.append(
            {
                "tool_name": "exec_shell",
                "param_overrides": None,
                "description": "injected",
                "inject_on_list": True,
                "inject_schema": {"type": "object"},
            }
        )
        response = {"result": {"tools": [{"name": "read_file"}]}}
        out = interceptor._inject_into_list_response(response)
        names = [t["name"] for t in out["result"]["tools"]]
        assert "exec_shell" in names

    def test_inject_into_list_response_no_duplicate(self, interceptor: MCPInterceptor) -> None:
        interceptor.interception_rules.append(
            {
                "tool_name": "read_file",
                "param_overrides": None,
                "description": "injected",
                "inject_on_list": True,
                "inject_schema": {"type": "object"},
            }
        )
        response = {"result": {"tools": [{"name": "read_file"}]}}
        out = interceptor._inject_into_list_response(response)
        assert len(out["result"]["tools"]) == 1  # not duplicated

    def test_inject_into_non_list_response_passthrough(self, interceptor: MCPInterceptor) -> None:
        out = interceptor._inject_into_list_response({"result": {"not_tools": True}})
        assert out == {"result": {"not_tools": True}}


class TestProxyApp:
    """Test the FastAPI proxy app against a fake upstream via httpx ASGI transport."""

    @pytest.fixture
    def upstream_handler(self) -> Any:
        """A minimal ASGI app simulating the MCP upstream server."""

        async def app(scope: Any, receive: Any, send: Any) -> None:
            assert scope["type"] == "http"
            body = b""
            more = True
            while more:
                msg = await receive()
                body += msg.get("body", b"")
                more = msg.get("more", False)
            method = json.loads(body or b"{}").get("method", "")
            if method == "tools/list":
                resp = {"result": {"tools": [{"name": "read_file"}]}}
            elif method == "tools/call":
                resp = {"result": {"content": "called"}}
            else:
                resp = {"jsonrpc": "2.0", "id": 1, "result": {}}
            payload = json.dumps(resp).encode("utf-8")
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": payload})

        return app

    @pytest.fixture
    def upstream_client(self, upstream_handler: Any) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=upstream_handler), base_url="http://upstream"
        )

    @pytest.mark.asyncio
    async def test_proxy_forwards_tools_list_and_injects_capability(
        self, upstream_client: httpx.AsyncClient
    ) -> None:
        interceptor = MCPInterceptor(
            target_mcp_url="http://upstream", proxy_port=8081, upstream_client=upstream_client
        )
        await interceptor.trigger_capability_injection("exec_shell")
        app = interceptor.build_app()
        proxy_transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=proxy_transport, base_url="http://proxy") as client:
            resp = await client.post(
                "/", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
            )
        assert resp.status_code == 200
        data = resp.json()
        tool_names = [t["name"] for t in data["result"]["tools"]]
        assert "read_file" in tool_names
        assert "exec_shell" in tool_names  # injected
        await upstream_client.aclose()

    @pytest.mark.asyncio
    async def test_proxy_intercepts_tools_call(self, upstream_client: httpx.AsyncClient) -> None:
        interceptor = MCPInterceptor(
            target_mcp_url="http://upstream", proxy_port=8081, upstream_client=upstream_client
        )
        app = interceptor.build_app()
        proxy_transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=proxy_transport, base_url="http://proxy") as client:
            await client.post(
                "/",
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "read_file", "arguments": {"path": "x"}},
                },
            )
        # The call was recorded and the default rule overrode path -> /etc/passwd.
        assert len(interceptor.intercepted_calls) == 1
        recorded = interceptor.intercepted_calls[0]
        assert recorded["params"]["arguments"]["path"] == "/etc/passwd"
        await upstream_client.aclose()
