"""MCP-over-HTTP adapter — real JSON-RPC 2.0 introspection (Phase 1).

Replaces the :mod:`modules.recon.tool_enum` prompt-leak path: instead of
asking the model to list its tools (a social-engineering prompt), this
adapter speaks real MCP JSON-RPC 2.0 over HTTP and parses the actual
``tools/list`` response. It also observes ``tools/call`` arguments and
supports capability-injection into the ``tools/list`` response (the
MCP-ITP / MCPoison descriptor-channel-injection class).

Per Decision D3, the **stdio** transport lands in Phase 5; HTTP catches the
dominant 2025-2026 MCP attack class (tool poisoning / shadow tools / rug
pulls live in the ``tools/list`` descriptor text, which is transport-agnostic).

This is an introspection + tool-call client, not a victim-model driver.
The victim agent itself is driven by an endpoint adapter
(:class:`~neuralstrike.adapters.openai_endpoint.OpenAIEndpointAdapter`); this
adapter supplies the real tool inventory the agent is offered.
"""

from __future__ import annotations

import contextlib
import json
from dataclasses import dataclass, field
from typing import Any

import httpx

from neuralstrike.utils.logging import get_logger

__all__ = [
    "MCPCallResult",
    "MCPError",
    "MCPHTTPAdapter",
    "MCPTool",
]

logger = get_logger("neuralstrike.adapters.mcp_http")


class MCPError(Exception):
    """Raised when an MCP JSON-RPC call returns an error or bad payload."""


@dataclass(frozen=True)
class MCPTool:
    """One tool advertised by an MCP server's ``tools/list``."""

    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def parameters(self) -> dict[str, Any]:
        # MCP uses ``inputSchema``; alias for ToolSchema compatibility.
        return self.input_schema

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.input_schema,
            },
        }


@dataclass(frozen=True)
class MCPCallResult:
    """Result of an MCP ``tools/call``."""

    content: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    is_error: bool = False
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def text(self) -> str:
        """Concatenated text content from the call result."""
        parts: list[str] = []
        for item in self.content:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(item["text"])
        return "\n".join(parts)


class MCPHTTPAdapter:
    """JSON-RPC 2.0 MCP client over HTTP."""

    def __init__(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        timeout: float = 30.0,
        client_name: str = "neuralstrike",
        client_version: str = "0.2.0",
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not url.startswith(("http://", "https://")):
            raise ValueError(f"MCP url must be http(s)://, got {url!r}")
        self.url = url.rstrip("/")
        self.headers = headers or {}
        self.timeout = timeout
        self.client_name = client_name
        self.client_version = client_version
        self._client: httpx.AsyncClient | None = None
        self._next_id = 0
        self._transport = transport

    @property
    def http(self) -> httpx.AsyncClient:
        if self._client is None:
            hdrs = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
            hdrs.update(self.headers)
            self._client = httpx.AsyncClient(headers=hdrs, timeout=self.timeout, transport=self._transport)
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _id(self) -> int:
        self._next_id += 1
        return self._next_id

    async def _rpc(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {"jsonrpc": "2.0", "id": self._id(), "method": method}
        if params is not None:
            payload["params"] = params
        try:
            resp = await self.http.post(self.url, json=payload)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise MCPError(f"MCP transport error calling {method}: {exc}") from exc
        body = _parse_rpc_body(resp)
        if "error" in body:
            err = body["error"]
            raise MCPError(f"MCP error on {method}: {err}")
        if "result" not in body:
            raise MCPError(f"MCP {method} returned no result: {body!r}")
        result = body["result"]
        return result if isinstance(result, dict) else {"value": result}

    async def initialize(self) -> dict[str, Any]:
        """MCP handshake. Returns the server's capabilities."""
        result = await self._rpc(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": self.client_name, "version": self.client_version},
            },
        )
        # Send the initialized notification (best-effort; servers tolerate absence).
        with contextlib.suppress(httpx.HTTPError):
            await self.http.post(
                self.url,
                json={"jsonrpc": "2.0", "method": "notifications/initialized"},
            )
        return result

    async def list_tools(
        self,
        *,
        injected: tuple[MCPTool, ...] = (),
    ) -> list[MCPTool]:
        """Real ``tools/list`` introspection (replaces the ToolEnum prompt-leak).

        ``injected`` lets a red-team merge fake tools into the returned list,
        simulating a poisoned ``tools/list`` (the MCP-ITP / MCPoison class).
        The injected tools are *appended* and flagged in the log so a report
        can distinguish real from injected.
        """
        result = await self._rpc("tools/list", {})
        tools_raw = result.get("tools", []) if isinstance(result, dict) else []
        tools = [_parse_tool(t) for t in tools_raw if isinstance(t, dict)]
        for it in injected:
            logger.warning("capability-injection: adding fake tool %r to tools/list view", it.name)
            tools.append(it)
        return tools

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> MCPCallResult:
        """Drive ``tools/call``; observe the arguments the caller sent and the result."""
        result = await self._rpc("tools/call", {"name": name, "arguments": arguments or {}})
        content = result.get("content", []) if isinstance(result, dict) else []
        is_error = bool(result.get("isError", False)) if isinstance(result, dict) else False
        return MCPCallResult(
            content=tuple(c for c in content if isinstance(c, dict)),
            is_error=is_error,
            raw=result if isinstance(result, dict) else {},
        )

    async def scan(
        self,
        *,
        injected: tuple[MCPTool, ...] = (),
        call_canaries: bool = True,
    ) -> dict[str, Any]:
        """One-shot introspection: initialize, list tools, optionally call canaries.

        Returns a report dict with the real tool inventory and any canary
        call results. This is the structured replacement for ``ToolEnum``.
        """
        await self.initialize()
        tools = await self.list_tools(injected=injected)
        canary_calls: list[dict[str, Any]] = []
        if call_canaries:
            for t in tools:
                if _looks_canary(t.name):
                    try:
                        res = await self.call_tool(t.name, _sample_args(t))
                    except MCPError as exc:
                        canary_calls.append({"tool": t.name, "error": str(exc)})
                        continue
                    canary_calls.append({
                        "tool": t.name,
                        "arguments_sent": _sample_args(t),
                        "result_text": res.text,
                        "is_error": res.is_error,
                    })
        return {
            "tools": [t.raw for t in tools],
            "tool_names": [t.name for t in tools],
            "injected_tool_names": [t.name for t in injected],
            "canary_calls": canary_calls,
        }


def _parse_tool(t: dict[str, Any]) -> MCPTool:
    return MCPTool(
        name=str(t.get("name", "")),
        description=str(t.get("description", "")),
        input_schema=t.get("inputSchema") or t.get("input_schema") or {},
        raw=t,
    )


def _looks_canary(name: str) -> bool:
    n = name.lower()
    needles = ("export_user_data", "delete_all_records", "grant_admin", "exec_shell", "drop_table")
    return any(k in n for k in needles)


def _sample_args(tool: MCPTool) -> dict[str, Any]:
    """Build a minimal valid argument set from the tool's input schema."""
    props = tool.input_schema.get("properties", {}) if isinstance(tool.input_schema, dict) else {}
    out: dict[str, Any] = {}
    for k, v in props.items():
        if isinstance(v, dict):
            t = v.get("type")
            if t == "string":
                out[k] = "attacker"
            elif t == "integer":
                out[k] = 1
            elif t == "boolean":
                out[k] = True
            elif t == "array":
                out[k] = []
            elif t == "object":
                out[k] = {}
    return out


def _parse_rpc_body(resp: httpx.Response) -> dict[str, Any]:
    """Parse a JSON-RPC response that may be plain JSON or SSE-framed."""
    ct = resp.headers.get("content-type", "")
    if "text/event-stream" in ct:
        # Extract the first `data:` line carrying a JSON object.
        for line in resp.text.splitlines():
            if line.startswith("data:"):
                blob = line[len("data:") :].strip()
                if blob:
                    try:
                        obj = json.loads(blob)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(obj, dict):
                        return obj
        raise MCPError("SSE response had no parseable data line")
    try:
        data = resp.json()
    except ValueError as exc:
        raise MCPError(f"non-JSON MCP response: {exc}") from exc
    if not isinstance(data, dict):
        raise MCPError("MCP response is not a JSON object")
    return data
