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

import asyncio
import base64
import copy
import json
import uuid
from typing import Any
from urllib.parse import unquote

import httpx

from neuralstrike.adapters.base import Message, TargetAdapter, ToolSchema
from neuralstrike.evaluation.checkpoint import capture_response
from neuralstrike.evaluation.controls import current_trial_controls
from neuralstrike.evaluation.verdict import SutResponse, ToolCall
from neuralstrike.oracles.tool_harness import CanaryTool, TraceLog
from neuralstrike.runtime.budget import BudgetExceeded
from neuralstrike.runtime.outbound import OutboundPolicy
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
        max_response_bytes: int = 16 * 1024 * 1024,
        outbound: OutboundPolicy | None = None,
        seed: int | None = None,
        temperature: float = 0.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if tier not in {"text", "function-calling", "instrumented"}:
            raise ValueError(f"tier must be text|function-calling|instrumented, got {tier!r}")
        if not base_url.startswith(("http://", "https://")):
            raise ValueError(f"base_url must be http(s)://, got {base_url!r}")
        if type(max_response_bytes) is not int or max_response_bytes < 1:
            raise ValueError("max_response_bytes must be a positive integer")
        self.max_response_bytes = max_response_bytes
        self.outbound = outbound
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
            fns.append(
                {
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.parameters,
                    },
                }
            )
        for ct in canary_tools:
            fns.append(
                {
                    "type": "function",
                    "function": {
                        "name": ct.name,
                        "description": ct.description,
                        "parameters": ct.parameters,
                    },
                }
            )
        unique: dict[str, dict[str, Any]] = {}
        for definition in fns:
            name = definition["function"]["name"]
            if name in unique and unique[name] != definition:
                raise ValueError(f"conflicting definitions for tool {name!r}")
            unique[name] = definition
        return list(unique.values()) or None

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
            if m.tool_calls:
                d["tool_calls"] = list(m.tool_calls)
            if m.tool_call_id is not None:
                d["tool_call_id"] = m.tool_call_id
            if m.name is not None:
                d["name"] = m.name
            msgs.append(d)
        msgs.append({"role": "user", "content": prompt})
        return msgs

    async def _complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        exchanges: list[dict[str, Any]],
    ) -> dict[str, Any]:
        controls = current_trial_controls()
        seed = controls.seed if controls else self.seed
        temperature = controls.temperature if controls else self.temperature
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        if seed is not None:
            payload["seed"] = seed
        endpoint_url = httpx.URL(self._endpoint())
        safe_endpoint = str(endpoint_url.copy_with(username=None, password=None, query=None, fragment=None))
        credentials_configured = bool(
            self.api_key
            or endpoint_url.username
            or endpoint_url.password
            or endpoint_url.query
            or endpoint_url.fragment
        )
        exchange: dict[str, Any] = {
            "exchange_id": uuid.uuid4().hex,
            "method": "POST",
            "request_status": "planned",
            "endpoint": safe_endpoint,
            "request": copy.deepcopy(payload),
            "capture": "private HTTP JSON bodies; headers and URL userinfo/query/fragment excluded",
            "seed_semantics": "sent best-effort; provider support and determinism not asserted",
        }
        exchanges.append(exchange)
        try:
            if self.outbound is not None:
                async with self.outbound.request() as receipt:
                    exchange["runtime"] = receipt
                    data = await self._exchange(payload, exchange, safe_endpoint, credentials_configured)
                    self.outbound.account(receipt, payload, data)
                    return data
            return await self._exchange(payload, exchange, safe_endpoint, credentials_configured)
        except asyncio.CancelledError:
            exchange["capture_complete"] = False
            exchange["error_type"] = "CancelledError"
            raise
        except BudgetExceeded as exc:
            exchange["error"] = str(exc)
            exchange["error_type"] = type(exc).__name__
            raise AdapterTransportError(str(exc)) from None

    async def _exchange(
        self,
        payload: dict[str, Any],
        exchange: dict[str, Any],
        safe_endpoint: str,
        credentials_configured: bool,
    ) -> dict[str, Any]:
        exchange["request_status"] = "attempted"
        body = bytearray()
        try:
            async with self.client.stream("POST", self._endpoint(), json=payload) as resp:
                exchange["status_code"] = resp.status_code
                exchange["capture_complete"] = False
                # Count decoded bytes, including compressed responses. Do not trust
                # Content-Length, which may be absent or refer to compressed data.
                async for chunk in resp.aiter_bytes():
                    if len(body) + len(chunk) > self.max_response_bytes:
                        diagnostic = f"response exceeded max_response_bytes={self.max_response_bytes}"
                        exchange["error"] = diagnostic
                        exchange["error_type"] = "ResponseLimitExceeded"
                        raise AdapterTransportError(diagnostic)
                    body.extend(chunk)
                # aiter_bytes already decoded Content-Encoding; avoid decoding it
                # a second time when constructing the bounded buffered response.
                buffered = httpx.Response(
                    resp.status_code,
                    headers={k: v for k, v in resp.headers.items() if k.lower() != "content-encoding"},
                    content=bytes(body),
                    request=resp.request,
                )
                exchange["capture_complete"] = True
                exchange["response_text"] = buffered.text
                buffered.raise_for_status()
        except asyncio.CancelledError:
            # A bounded decoded prefix is private evidence, never a complete
            # JSON response and never input to tool execution or the oracles.
            exchange["response_prefix_base64"] = base64.b64encode(body).decode("ascii")
            raise
        except httpx.HTTPError as exc:
            diagnostic = _http_error_diagnostic(exc, safe_endpoint, credentials_configured)
            exchange["error"] = diagnostic
            exchange["error_type"] = type(exc).__name__
            raise AdapterTransportError(diagnostic) from None
        try:
            data = buffered.json()
            exchange["response"] = copy.deepcopy(data)
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
        delivery_channel: str | None = None,
        delivery_marker: str | None = None,
    ) -> SutResponse:
        messages = self._messages(prompt, system_prompt, history)
        # Phase 2: surface the indirect-injection channel via adapter trace.
        # The adapter scans each role-tagged message for the marker and records
        # a DeliveryRecord. The exit gate asserts the marker is present in the
        # declared channel (and absent elsewhere) by reading this trace — never
        # by reading the prompt.
        if delivery_channel is not None and delivery_marker:
            self._record_delivery(messages, trace, delivery_channel, delivery_marker)
        tools_payload = self._build_tools_payload(tools, canary_tools)
        canary_by_name = {ct.name: ct for ct in canary_tools}
        all_tool_calls: list[ToolCall] = []
        last_text = ""
        error: str | None = None
        exchanges: list[dict[str, Any]] = []

        capture_response(lambda: SutResponse(
            text=last_text,
            tool_calls=tuple(all_tool_calls),
            traces=tuple(trace.to_list()) if trace is not None else (),
            exchanges=tuple(exchanges),
        ))

        for _round in range(self.max_tool_rounds):
            try:
                data = await self._complete(messages, tools_payload, exchanges)
            except AdapterTransportError as exc:
                error = str(exc)
                logger.error("OpenAI endpoint transport error: %s", exc)
                break

            choice = _first_choice(data)
            if choice is None:
                error = "response had no choices"
                break
            msg = choice.get("message")
            problem = _message_problem(msg)
            if problem is not None:
                error = f"invalid chat completion: {problem}"
                break
            assert isinstance(msg, dict)  # validated above
            last_text = msg.get("content") or ""
            tool_calls = msg.get("tool_calls") or []
            # These complete, validated call objects are observed intent even
            # when generation subsequently reports truncation/filtering. Never
            # execute handlers or continue such a completion.
            all_tool_calls.extend(_observed_calls(tool_calls))
            error = _completion_problem(choice)
            if error is None and tool_calls and self.tier == "text":
                error = "tool calls unsupported in text tier"
            if error is not None or not tool_calls:
                break

            # Append the assistant message (with its tool_calls) to the conversation.
            messages.append({"role": "assistant", "content": last_text, "tool_calls": tool_calls})

            error = self._serve_calls(tool_calls, messages, canary_by_name, trace, exchanges[-1])
            if error is not None:
                break
            # Loop again to let the SUT react to the tool results.
        else:
            # Loop exhausted without the SUT stopping tool-calls.
            error = f"tool-call loop did not terminate within {self.max_tool_rounds} rounds"

        return SutResponse(
            text=last_text,
            tool_calls=tuple(all_tool_calls),
            traces=tuple(trace.to_list()) if trace is not None else (),
            error=error,
            exchanges=tuple(exchanges),
        )

    def _serve_calls(
        self,
        calls: list[dict[str, Any]],
        messages: list[dict[str, Any]],
        canary_by_name: dict[str, CanaryTool],
        trace: TraceLog | None,
        exchange: dict[str, Any],
    ) -> str | None:
        for call in calls:
            name = call["function"]["name"]
            args = _parse_args(call["function"]["arguments"])
            result_content = _canned_tool_result(name)
            if self.tier == "instrumented" and name in canary_by_name and trace is not None:
                try:
                    result_content = canary_by_name[name].execute(args, trace, tool_call_id=call["id"])
                except Exception as exc:
                    exchange["tool_execution_error"] = {
                        "tool_name": name, "tool_call_id": call["id"], "error_type": type(exc).__name__,
                    }
                    error = f"canary tool handler failed ({type(exc).__name__})"
                    logger.error("canary tool handler failed (%s)", type(exc).__name__)
                    return error
            messages.append({
                "role": "tool", "tool_call_id": call["id"], "name": name, "content": result_content,
            })
        return None

    @staticmethod
    def _record_delivery(
        messages: list[dict[str, Any]],
        trace: TraceLog | None,
        declared_channel: str,
        marker: str,
    ) -> None:
        """Scan role-tagged messages for the marker; record one DeliveryRecord
        per channel so the trace shows where the marker landed.

        Role -> channel mapping:
          system -> system_prompt
          user   -> user_message
          tool   -> tool_result  (a tool-result channel; the adapter also
                    distinguishes a retrieved_document tool-result by the
                    tool ``name`` when the message carries one)
          assistant (with tool_calls) -> memory (assistant-stored context)
        """
        if trace is None:
            return
        for m in messages:
            role = m.get("role", "")
            content = m.get("content") or ""
            if not isinstance(content, str):
                content = str(content)
            channel = {
                "system": "system_prompt",
                "user": "user_message",
                "tool": "tool_result",
                "assistant": "memory",
            }.get(role, role)
            # Distinguish a retrieved_document tool-result from a plain one
            # by the tool name carried on the message (the indirect harness
            # names the retrieval tool ``search_docs``).
            if role == "tool":
                name = m.get("name", "")
                if name == "search_docs":
                    channel = "retrieved_document"
            present = marker in content
            trace.record_delivery(channel, marker, present=present)


def _http_error_diagnostic(exc: httpx.HTTPError, endpoint: str, credentials_configured: bool) -> str:
    """Do not copy authentication material from exception messages into evidence/logs.

    Status errors use structured metadata, including redirects whose Location may
    contain independent secrets. Authenticated or URL-bearing transport messages
    are opaque: encoded/decoded credential echoes are not safe to pattern-scrub.
    Ordinary credential-free connection diagnostics remain useful (e.g. 'boom').
    """
    if isinstance(exc, httpx.HTTPStatusError):
        return f"{type(exc).__name__}: HTTP {exc.response.status_code} at {endpoint}"
    try:
        request = exc.request
    except (AttributeError, RuntimeError):
        request = None
    if request is not None:
        url = request.url
        ordinary_headers = {
            "accept",
            "accept-encoding",
            "connection",
            "content-length",
            "content-type",
            "host",
            "user-agent",
        }
        credentials_configured |= bool(url.username or url.password or url.query or url.fragment)
        credentials_configured |= bool(set(request.headers) - ordinary_headers)
    detail = str(exc)
    decoded = detail
    # Decode until stable within a bounded diagnostic, not an arbitrary nesting
    # depth that could expose credentials after another percent-encoding layer.
    oversized = len(detail) > 4096
    if not oversized:
        while True:
            previous = decoded
            decoded = unquote(decoded)
            if previous == decoded:
                break
    if credentials_configured or oversized or "://" in decoded:
        detail = "transport detail omitted (credential-bearing or URL-bearing diagnostic)"
    return f"{type(exc).__name__}: {detail} at {endpoint}"


class AdapterTransportError(Exception):
    """Raised when an adapter transport call fails (recorded, not faked)."""


def _first_choice(data: dict[str, Any]) -> dict[str, Any] | None:
    choices = data.get("choices")
    if isinstance(choices, list) and choices:
        c = choices[0]
        return c if isinstance(c, dict) else None
    return None


def _message_problem(message: Any) -> str | None:  # noqa: PLR0911 - explicit protocol checks
    """Validate the whole tool batch before any local handler can run."""
    if not isinstance(message, dict):
        return "message must be an object"
    if message.get("content") is not None and not isinstance(message["content"], str):
        return "content must be text or null"
    calls = message.get("tool_calls", [])
    if calls is None:
        return None
    if not isinstance(calls, list):
        return "tool_calls must be an array"
    ids: set[str] = set()
    for call in calls:
        if not isinstance(call, dict) or call.get("type") != "function":
            return "tool call must be a function object"
        call_id = call.get("id")
        if not isinstance(call_id, str) or not call_id or call_id in ids:
            return "tool call IDs must be nonempty and unique"
        ids.add(call_id)
        fn = call.get("function")
        if not isinstance(fn, dict) or not isinstance(fn.get("name"), str) or not fn["name"]:
            return "function name must be nonempty text"
        arguments = fn.get("arguments")
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except ValueError:
                return "function arguments must be a JSON object"
        if not isinstance(arguments, dict):
            return "function arguments must be a JSON object"
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


def _observed_calls(calls: list[dict[str, Any]]) -> list[ToolCall]:
    return [
        ToolCall(
            name=call["function"]["name"],
            arguments=_parse_args(call["function"]["arguments"]),
            tool_call_id=call["id"],
        )
        for call in calls
    ]


def _completion_problem(choice: dict[str, Any]) -> str | None:
    # Some compatible endpoints omit this optional metadata. Preserve that
    # legacy shape; when supplied, do not ignore an explicit incomplete state.
    if "finish_reason" not in choice:
        return None
    reason = choice["finish_reason"]
    if reason in ("stop", "tool_calls"):
        return None
    if reason == "length":
        return "incomplete chat completion: generation token limit reached"
    if reason == "content_filter":
        return "incomplete chat completion: generation stopped by content filter"
    return "incomplete chat completion: unsupported or unfinished finish_reason"
