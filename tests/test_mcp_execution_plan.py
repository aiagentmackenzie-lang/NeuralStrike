"""Explicit MCP fixture execution follows a unique, exact argument plan."""

import json

import httpx
import pytest

from neuralstrike.adapters.mcp_http import MCPError, MCPHTTPAdapter, MCPTool


def transport_for(tools, calls):
    def handler(request):
        body = json.loads(request.content)
        if body["method"] == "tools/list":
            result = {"tools": tools}
        elif body["method"] == "tools/call":
            calls.append(body["params"])
            result = {"content": [{"type": "text", "text": "simulated fixture call"}]}
        else:
            result = {}
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body.get("id"), "result": result})

    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_only_exact_selected_tool_and_arguments_are_executed():
    calls = []
    tools = [
        {"name": name, "inputSchema": {}}
        for name in ["grant_admin_access", "grant_admin_access_extra", "delete_all_records"]
    ]
    adapter = MCPHTTPAdapter("http://fixture/mcp", transport=transport_for(tools, calls))
    try:
        await adapter.scan(
            call_canaries=True, authorized_tool_calls={"grant_admin_access": {"user_id": "synthetic-user"}}
        )
        assert calls == [{"name": "grant_admin_access", "arguments": {"user_id": "synthetic-user"}}]
    finally:
        await adapter.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("injected_duplicate", [False, True])
async def test_ambiguous_inventory_never_amplifies_selected_execution(injected_duplicate):
    calls = []
    tool = {"name": "selected_fixture", "inputSchema": {}}
    tools = [tool] if injected_duplicate else [tool, tool]
    injected = (
        (MCPTool(name="selected_fixture", description="synthetic duplicate"),) if injected_duplicate else ()
    )
    adapter = MCPHTTPAdapter("http://fixture/mcp", transport=transport_for(tools, calls))
    try:
        with pytest.raises(MCPError, match="duplicate"):
            await adapter.scan(
                call_canaries=True,
                injected=injected,
                authorized_tool_calls={"selected_fixture": {"id": "synthetic"}},
            )
        assert not calls
    finally:
        await adapter.close()
