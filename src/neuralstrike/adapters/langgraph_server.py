"""LangGraph Server HTTP adapter — drives a deployed graph via the REST API.

Targets `langgraph dev` / a deployed LangGraph Server. The LangGraph Server
API exposes ``/threads/{thread_id}/runs`` (and ``/runs/stream``) to drive a
graph remotely. This adapter creates a thread, starts a run, and reads the
final state — observing tool calls the agent emitted.

Uses httpx; no langgraph SDK required. The graph name is the deployed
assistant/graph id (LangGraph Server routes by ``assistant_id``).
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from neuralstrike.adapters.base import Message, TargetAdapter, ToolSchema
from neuralstrike.adapters.langgraph import build_default_state, extract_default
from neuralstrike.evaluation.verdict import SutResponse
from neuralstrike.utils.logging import get_logger

__all__ = ["LangGraphServerAdapter"]

logger = get_logger("neuralstrike.adapters.langgraph_server")


class LangGraphServerAdapter(TargetAdapter):
    """Drives a graph deployed on a LangGraph Server via HTTP."""

    name = "langgraph_server"
    tier = "function-calling"

    def __init__(
        self,
        base_url: str,
        *,
        graph_id: str = "agent",
        api_key: str | None = None,
        timeout: float = 60.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not base_url.startswith(("http://", "https://")):
            raise ValueError(f"base_url must be http(s)://, got {base_url!r}")
        self.base_url = base_url.rstrip("/")
        self.graph_id = graph_id
        self.api_key = api_key
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None
        self._transport = transport

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            headers = {"Content-Type": "application/json", "Accept": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            self._client = httpx.AsyncClient(headers=headers, timeout=self.timeout, transport=self._transport)
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _create_thread(self) -> str:
        resp = await self.client.post(f"{self.base_url}/threads", json={})
        resp.raise_for_status()
        return resp.json().get("thread_id") or resp.json().get("id") or ""

    async def query(
        self,
        prompt: str,
        *,
        system_prompt: str | None = None,
        tools: tuple[ToolSchema, ...] = (),
        history: tuple[Message, ...] = (),
        canary_tools: tuple[Any, ...] = (),
        trace: Any = None,
    ) -> SutResponse:
        _ = tools, canary_tools, trace
        try:
            thread_id = await self._create_thread()
        except httpx.HTTPError as exc:
            return SutResponse(text="", error=f"create_thread failed: {exc}")
        state = build_default_state(prompt, system_prompt, history)
        payload: dict[str, Any] = {
            "assistant_id": self.graph_id,
            "input": state,
            "stream_mode": "values",
        }
        try:
            # Stream the run to completion; collect the last values chunk.
            resp = await self.client.post(
                f"{self.base_url}/threads/{thread_id}/runs/stream",
                json=payload,
            )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            return SutResponse(text="", error=f"run failed: {exc}")

        final = _consume_stream(resp.text)
        text, tool_calls, traces = extract_default(final)
        return SutResponse(text=text, tool_calls=tuple(tool_calls), traces=tuple(traces))


def _consume_stream(body: str) -> dict[str, Any]:
    """Parse a LangGraph Server SSE stream; return the last `values:` payload."""
    last: dict[str, Any] = {}
    for line in body.splitlines():
        if line.startswith("data:"):
            blob = line[len("data:") :].strip()
            if not blob:
                continue
            try:
                obj = json.loads(blob)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                last = obj
    return last
