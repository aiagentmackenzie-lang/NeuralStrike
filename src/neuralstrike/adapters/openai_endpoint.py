"""OpenAI-compatible endpoint adapter — drives ``/v1/chat/completions``.

The adapter sends a tool schema to the SUT and **serves the tool results
itself**, so oracles observe the arguments the SUT tried to use. Three tiers:

- ``text``            — no tools; observes the model's words only (Verbal).
- ``function-calling``— advertises ``tools``; observes emitted tool_calls
                        (IntentToAct) and serves canned results so the
                        conversation continues.
- ``instrumented``     — advertises the canary tools from
                        :mod:`neuralstrike.oracles.tool_harness`; when the SUT
                        calls one, the adapter **executes** the handler
                        (recording a trace -> Behavioral / Tier-2) and returns
                        the canned result.

Works against any OpenAI-compatible endpoint (OpenAI, Ollama's
``/v1/chat/completions``, vLLM, LM Studio). Uses httpx, no SDK lock-in.

Fail-closed: a transport error is recorded as ``error`` on the
:class:`SutResponse`, never faked into a "response."
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from neuralstrike.adapters.base import Message, TargetAdapter, ToolSchema
from neuralstrike.evaluation.verdict import SutResponse, ToolCall
from neuralstrike.oracles.tool_harness import CanaryTool, TraceLog
from neuralstrike.utils.logging import get_logger

__all__ = ["OpenAIEndpointAdapter"]

logger = get_logger("neuralstrike.adapters.openai_endpoint")

_MAX_TOOL_ROUNDS = 4


class OpenAIEndpointAdapter(TargetAdapter):
    """Drives an OpenAI-compatible ``/v1/chat/completions`` endpoint."""

    def __init__(
        self,
        base_url: str,
        *,
        model: str,
        api_key: str | None = None,
        tier: str = "function-calling",
        timeout: float = 30.0,
        max_tool_rounds: int = _MAX_TOOL_ROUNDS,
        seed: int | None = None,
        temperature: float = 0.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if tier not in {"text", "function-calling", "instrumented"}:
            raise ValueError(f"tier must be text|function-calling|instrumented, got {tier!r}")
        if not base_url.startswith(("http://", "https://")):
            raise ValueError(f"base_url must be http(s)://, got {base_url!r}")
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.tier = tier
        self.timeout = timeout
        self.max_tool_rounds = max(1, int(max_tool_rounds))
        self.seed = seed
        self.temperature = temperature
        self.name = "openai_endpoint"
        self._transport = transport
        self._client: httpx.AsyncClient | None = None

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            headers: dict[str, str] = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            self._client = httpx.AsyncClient(headers=headers, timeout=self.timeout, transport=self._transport)
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _endpoint(self) -> str:
        path = "/v1/chat/completions"
        # Allow callers to pass a base URL that already includes /v1.
        if self.base_url.endswith("/v1"):
            return f"{self.base_url}/chat/completions"
        return f"{self.base_url}{path}"

    def _build_tools_payload(
        self,
        tools: tuple[ToolSchema, ...],
        canary_tools: tuple[CanaryTool, ...],
    ) -> list[dict[str, Any]] | None:
        if self.tier == "text":
            return None
        fns: list[dict[str, Any]] = []
        for t in tools:
            fns.append({"type": "function", "function": {
                "name": t.name, "description": t.description, "parameters": t.parameters,
            }})
        for ct in canary_tools:
            fns.append({"type": "function", "function": {
                "name": ct.name, "description": ct.description, "parameters": ct.parameters,
            }})
        return fns or None

    def _messages(
        self,
        prompt: str,
        system_prompt: str | None,
        history: tuple[Message, ...],
    ) -> list[dict[str, Any]]:
        msgs: list[dict[str, Any]] = []
        if system_prompt:
            msgs.append({"role": "system", "content": system_prompt})
        for m in history:
            d: dict[str, Any] = {"role": m.role, "content": m.content}
            if m.tool_call_id is not None:
                d["tool_call_id"] = m.tool_call_id
            if m.name is not None:
                d["name"] = m.name
            msgs.append(d)
        msgs.append({"role": "user", "content": prompt})
        return msgs

    async def _complete(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        if self.seed is not None:
            payload["seed"] = self.seed
        try:
            resp = await self.client.post(self._endpoint(), json=payload)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise AdapterTransportError(str(exc)) from exc
        try:
            data = resp.json()
        except ValueError as exc:
            raise AdapterTransportError(f"non-JSON response: {exc}") from exc
        if not isinstance(data, dict):
            raise AdapterTransportError("response is not a JSON object")
        return data

    async def query(
        self,
        prompt: str,
        *,
        system_prompt: str | None = None,
        tools: tuple[ToolSchema, ...] = (),
        history: tuple[Message, ...] = (),
        canary_tools: tuple[CanaryTool, ...] = (),
        trace: TraceLog | None = None,
    ) -> SutResponse:
        messages = self._messages(prompt, system_prompt, history)
        tools_payload = self._build_tools_payload(tools, canary_tools)
        canary_by_name = {ct.name: ct for ct in canary_tools}
        all_tool_calls: list[ToolCall] = []
        last_text = ""
        error: str | None = None

        for _round in range(self.max_tool_rounds):
            try:
                data = await self._complete(messages, tools_payload)
            except AdapterTransportError as exc:
                error = str(exc)
                logger.error("OpenAI endpoint transport error: %s", exc)
                break

            choice = _first_choice(data)
            if choice is None:
                error = "response had no choices"
                break
            msg = choice.get("message", {})
            last_text = msg.get("content") or ""
            tool_calls = msg.get("tool_calls") or []

            if not tool_calls:
                break

            # Append the assistant message (with its tool_calls) to the conversation.
            messages.append({"role": "assistant", "content": last_text, "tool_calls": tool_calls})

            # Serve each tool_call: execute canary tools (Behavioral), else canned result.
            for tc in tool_calls:
                fn = tc.get("function", {}) if isinstance(tc, dict) else {}
                name = fn.get("name", "")
                raw_args = fn.get("arguments", "{}")
                args = _parse_args(raw_args)
                all_tool_calls.append(ToolCall(name=name, arguments=args, tool_call_id=tc.get("id")))
                result_content = _canned_tool_result(name)
                if name in canary_by_name and trace is not None:
                    try:
                        result_content = canary_by_name[name].execute(args, trace)
                    except Exception as exc:
                        result_content = f'{{"error":"{exc}"}}'
                        logger.error("canary tool %s handler raised: %s", name, exc)
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.get("id"),
                    "name": name,
                    "content": result_content,
                })
            # Loop again to let the SUT react to the tool results.
        else:
            # Loop exhausted without the SUT stopping tool-calls.
            error = f"tool-call loop did not terminate within {self.max_tool_rounds} rounds"

        return SutResponse(
            text=last_text,
            tool_calls=tuple(all_tool_calls),
            traces=tuple(trace.to_list()) if trace is not None else (),
            error=error,
        )


class AdapterTransportError(Exception):
    """Raised when an adapter transport call fails (recorded, not faked)."""


def _first_choice(data: dict[str, Any]) -> dict[str, Any] | None:
    choices = data.get("choices")
    if isinstance(choices, list) and choices:
        c = choices[0]
        return c if isinstance(c, dict) else None
    return None


def _parse_args(raw: Any) -> Any:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"_raw": raw}
    return raw


def _canned_tool_result(name: str) -> str:
    """A generic acknowledgement for non-canary tools so the conversation continues."""
    return json.dumps({"ok": True, "tool": name, "result": "served by NeuralStrike adapter"})
