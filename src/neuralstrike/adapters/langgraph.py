"""LangGraph adapter — drives a real compiled graph end-to-end.

Discovers the compiled graph via attribute lookup (`graph` / `app` / `agent`
/ `build_graph()`) on a module or object, then drives it with ``ainvoke``
or explicit values-mode ``astream``. Synchronous-only graphs fail explicitly
because a detached worker could continue tool execution after a timeout. Newly
emitted assistant actions are read across the output transcript.

langgraph is an **optional** extra: when installed, the adapter drives a real
``langgraph.graph.StateGraph``-compiled graph; when not, it drives any
duck-typed object exposing ``ainvoke``/``invoke`` (the bundled fixture does
this). The adapter code is identical either way, so the exit gate passes on a
fresh clone without forcing a heavy install.
"""

from __future__ import annotations

import asyncio
import copy
import importlib
import inspect
import json
import math
import uuid
from collections.abc import Awaitable, Callable
from contextlib import nullcontext, suppress
from dataclasses import dataclass, replace
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from neuralstrike.adapters.base import Message, TargetAdapter, ToolSchema
from neuralstrike.evaluation.checkpoint import capture_response
from neuralstrike.evaluation.verdict import SutResponse, ToolCall
from neuralstrike.utils.logging import get_logger

__all__ = ["GraphResolver", "LangGraphAdapter", "build_default_state", "extract_default"]

logger = get_logger("neuralstrike.adapters.langgraph")


StateBuilder = Callable[[str, str | None, tuple[Message, ...]], dict[str, Any]]
LifecycleHook = Callable[[Any, str | None], Awaitable[None]]


ResultExtractor = Callable[[Any], tuple[str, list[ToolCall], list[dict[str, Any]]]]


def build_default_state(
    prompt: str, system_prompt: str | None, history: tuple[Message, ...]
) -> dict[str, Any]:
    """Default state shape: ``{"messages": [...]}`` (the LangGraph convention).

    Preserves ``name`` and ``tool_call_id`` on tool messages so the indirect-
    injection delivery recorder can distinguish a ``retrieved_document``
    tool result (named ``search_docs``) from a plain ``tool_result``.
    """
    msgs: list[dict[str, Any]] = []
    if system_prompt:
        msgs.append({"role": "system", "content": system_prompt})
    for m in history:
        d: dict[str, Any] = {"role": m.role, "content": m.content}
        if m.tool_calls:
            d["tool_calls"] = list(m.tool_calls)
        if m.name:
            d["name"] = m.name
        if m.tool_call_id:
            d["tool_call_id"] = m.tool_call_id
        msgs.append(d)
    msgs.append({"role": "user", "content": prompt})
    return {"messages": msgs}


def extract_default(final_state: Any) -> tuple[str, list[ToolCall], list[dict[str, Any]]]:
    """Extract all newly emitted assistant actions, including before a final reply.

    The adapter first removes the verified input prefix. Calling this helper
    directly treats all supplied messages as outputs; callers own that boundary.
    """
    messages = [_message_snapshot(message) for message in _messages_of(final_state)]
    assistants = [message for message in messages if message["role"] == "assistant"]
    if not assistants:
        raise ValueError("graph produced no assistant output")
    calls = [
        ToolCall(call["name"], call["arguments"], call["id"])
        for message in assistants
        for call in message.get("tool_calls", [])
    ]
    return assistants[-1]["content"], calls, []


def _messages_of(state: Any) -> list[Any]:
    messages = state.get("messages") if isinstance(state, dict) else getattr(state, "messages", None)
    if not isinstance(messages, (list, tuple)):
        raise ValueError("graph state must contain a messages list")
    return list(messages)


def _message_snapshot(message: Any) -> dict[str, Any]:
    """Normalize the declared text-message profile without importing LangChain."""
    role = _attr(message, "role") or _attr(message, "type")
    role = {"human": "user", "ai": "assistant"}.get(role, role)
    if role not in {"user", "assistant", "system", "tool"}:
        raise ValueError("unsupported graph message role")
    content = _attr(message, "content", default="")
    if content is None:
        content = ""
    if not isinstance(content, str):
        raise ValueError("graph text-message profile cannot capture non-text content")
    result: dict[str, Any] = {"role": role, "content": content}
    for field in ("name", "tool_call_id"):
        value = _attr(message, field)
        if value is not None:
            if not isinstance(value, str):
                raise ValueError("invalid graph message identity")
            result[field] = value
    if _attr(message, "invalid_tool_calls"):
        raise ValueError("graph returned invalid tool calls")
    calls = _attr(message, "tool_calls") or []
    if not isinstance(calls, (list, tuple)):
        raise ValueError("graph tool calls must be a list")
    if calls:
        result["tool_calls"] = [_call_snapshot(call) for call in calls]
    return result


def _call_snapshot(call: Any) -> dict[str, Any]:
    # OpenAI history uses function/name/arguments; LangChain uses name/args.
    fn = _attr(call, "function")
    source = fn if fn is not None else call
    name = _attr(source, "name")
    arguments = _attr(source, "arguments") if fn is not None else _attr(source, "args")
    if isinstance(arguments, str):
        arguments = json.loads(arguments)
    call_id = _attr(call, "id")
    if not isinstance(name, str) or not name or not isinstance(arguments, dict):
        raise ValueError("invalid graph tool name or arguments")
    if not isinstance(call_id, str) or not call_id:
        raise ValueError("graph tool call requires a nonempty ID")
    return {"id": call_id, "name": name, "arguments": arguments}


def _attr(obj: Any, name: str, *, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


@dataclass(frozen=True)
class GraphResolver:
    """Resolves a compiled graph from a module path ``pkg.mod:attr`` or object."""

    spec: str | None = None
    obj: Any = None

    def resolve(self) -> Any:
        if self.obj is not None:
            return self._discover(self.obj)
        if self.spec is None:
            raise ValueError("GraphResolver needs either a spec or an obj")
        module_path, _, attr = self.spec.partition(":")
        mod = importlib.import_module(module_path)
        target = mod if not attr else getattr(mod, attr)
        return self._discover(target)

    def _discover(self, target: Any) -> Any:
        for name in ("graph", "app", "agent"):
            obj = _lookup(target, name)
            if obj is not None and _is_drivable(obj):
                return obj
        # build_graph() factory (attribute or dict key)
        factory = _lookup(target, "build_graph")
        if callable(factory) and not _is_drivable(factory):
            built = factory()
            if _is_drivable(built):
                return built
        if _is_drivable(target):
            return target
        raise ValueError("could not discover a compiled graph (looked for graph/app/agent/build_graph())")


def _is_drivable(obj: Any) -> bool:
    return hasattr(obj, "ainvoke") or hasattr(obj, "invoke") or hasattr(obj, "astream")


def _lookup(target: Any, name: str) -> Any:
    """Attribute access for modules/objects; key access for dict namespaces."""
    if isinstance(target, dict):
        return target.get(name)
    return getattr(target, name, None)


class LangGraphAdapter(TargetAdapter):
    """Drives a compiled LangGraph (or duck-typed equivalent) end-to-end."""

    name = "langgraph"
    tier = "function-calling"

    def __init__(
        self,
        *,
        spec: str | None = None,
        graph: Any | None = None,
        state_builder: StateBuilder = build_default_state,
        result_extractor: ResultExtractor = extract_default,
        target_id: str | None = None,
        messages_mode: str = "append",
        delivery_channels: frozenset[str] | None = None,
        thread_mode: str = "none",
        reset: LifecycleHook | str | None = None,
        cleanup: LifecycleHook | str | None = None,
        lifecycle_id: str | None = None,
        cleanup_timeout: float = 5.0,
    ) -> None:
        if messages_mode not in {"append", "output"}:
            raise ValueError("messages_mode must be append|output")
        if target_id is not None and (not isinstance(target_id, str) or not target_id.strip()):
            raise ValueError("target_id must be a nonempty application identity")
        if thread_mode not in {"none", "isolated"}:
            raise ValueError("thread_mode must be none|isolated")
        if not math.isfinite(cleanup_timeout) or cleanup_timeout <= 0:
            raise ValueError("cleanup_timeout must be finite and positive")
        self.thread_mode = thread_mode
        self.reset = reset
        self.cleanup = cleanup
        self.lifecycle_id = lifecycle_id
        self.cleanup_timeout = cleanup_timeout
        # Reset and cleanup may operate on application-wide state. Serialize
        # this adapter's queries; other adapters/processes remain caller-owned.
        self._lifecycle_lock = asyncio.Lock()
        self.target_id = target_id
        self.messages_mode = messages_mode
        self.delivery_channels = delivery_channels
        self.resolver = GraphResolver(spec=spec, obj=graph)
        self.state_builder = state_builder
        self.result_extractor = result_extractor
        self._graph: Any = None

    @property
    def graph(self) -> Any:
        if self._graph is None:
            self._graph = self.resolver.resolve()
        return self._graph

    async def query(
        self,
        prompt: str,
        *,
        system_prompt: str | None = None,
        tools: tuple[ToolSchema, ...] = (),
        history: tuple[Message, ...] = (),
        canary_tools: tuple[Any, ...] = (),
        trace: Any = None,
        delivery_channel: str | None = None,
        delivery_marker: str | None = None,
    ) -> SutResponse:
        guard = self._lifecycle_lock if self.reset is not None or self.cleanup is not None else nullcontext()
        async with guard:
            return await self._query(
                prompt, system_prompt=system_prompt, tools=tools, history=history,
                canary_tools=canary_tools, trace=trace, delivery_channel=delivery_channel,
                delivery_marker=delivery_marker,
            )

    async def _query(
        self,
        prompt: str,
        *,
        system_prompt: str | None = None,
        tools: tuple[ToolSchema, ...] = (),
        history: tuple[Message, ...] = (),
        canary_tools: tuple[Any, ...] = (),
        trace: Any = None,
        delivery_channel: str | None = None,
        delivery_marker: str | None = None,
    ) -> SutResponse:
        _ = tools, canary_tools  # The graph owns its tool wiring; never run canaries here.
        if (
            delivery_channel is not None
            and self.delivery_channels is not None
            and delivery_channel not in self.delivery_channels
        ):
            return SutResponse(error=f"unsupported graph delivery channel: {delivery_channel}")
        exchange: dict[str, Any] = {
            "profile": "langgraph-messages-v1"
            if self.result_extractor is extract_default
            else "custom-graph",
            "messages_mode": self.messages_mode,
            "capture_complete": False,
            "origin": "local-graph-invocation",
            "delivery_semantics": "input state observed; target consumption not attested",
            "versions": _package_versions(),
        }
        thread_id = str(uuid.uuid4()) if self.thread_mode == "isolated" else None
        lifecycle = self._new_lifecycle(thread_id)
        exchange["lifecycle"] = lifecycle
        response = SutResponse(text="", exchanges=(exchange,))
        capture_response(lambda: response)
        graph = None
        try:
            _validate_hooks(self.reset, self.cleanup)
            graph = self.graph
            if self.reset is not None:
                lifecycle["reset"] = "started"
                await _run_hook(self.reset, graph, thread_id)
                lifecycle["reset"] = "completed"
            state = self.state_builder(prompt, system_prompt, history)
            # Freeze before invocation: graphs/reducers can mutate the input object.
            inputs = (
                copy.deepcopy([_message_snapshot(m) for m in _messages_of(state)])
                if self.result_extractor is extract_default
                else []
            )
            if self.result_extractor is extract_default:
                exchange["input_messages"] = inputs
            if delivery_channel is not None and delivery_marker and trace is not None:
                self._record_delivery(
                    inputs if self.result_extractor is extract_default else state.get("messages", []),
                    trace,
                    delivery_channel,
                    delivery_marker,
                )
            lifecycle["invocation"] = "started"
            final = await self._invoke(state, thread_id)
            response = self._extract_response(final, inputs, exchange)
            lifecycle["invocation"] = "completed"
        except asyncio.CancelledError:
            if lifecycle["reset"] == "started":
                lifecycle["reset"] = "interrupted"
            if lifecycle["invocation"] == "started":
                lifecycle["invocation"] = "interrupted"
            raise
        except Exception as exc:
            if lifecycle["invocation"] == "started":
                lifecycle["invocation"] = "failed"
            if lifecycle["reset"] == "started":
                lifecycle["reset"] = "failed"
            logger.error("LangGraph drive failed (%s)", type(exc).__name__)
            exchange["error_type"] = type(exc).__name__
            response = replace(response, error=f"{type(exc).__name__}: {exc}")
        finally:
            if self.cleanup is not None and graph is not None:
                response = await self._cleanup_response(graph, thread_id, lifecycle, response)
        return response

    def _new_lifecycle(self, thread_id: str | None) -> dict[str, Any]:
        return {
            "thread_mode": self.thread_mode,
            "thread_id": thread_id,
            "state_isolation": "fresh thread configuration; application state unverified"
            if thread_id else "unverified; no thread configuration supplied",
            "invocation": "not_attempted",
            "reset": "not_attempted" if self.reset is not None else "not_configured",
            "cleanup": "not_attempted" if self.cleanup is not None else "not_configured",
            "reset_attestation": "caller-supplied callback only; independent reset not attested",
            "resource_ownership": "invocation hooks only; graph/store lifetime remains caller-owned",
        }

    def _extract_response(
        self, final: Any, inputs: list[dict[str, Any]], exchange: dict[str, Any]
    ) -> SutResponse:
        if self.result_extractor is extract_default:
            messages = [_message_snapshot(m) for m in _messages_of(final)]
            exchange["returned_messages"] = messages
            outputs = messages
            if self.messages_mode == "append":
                if messages[: len(inputs)] != inputs:
                    raise ValueError(
                        "graph changed or omitted the input prefix; use an explicit output profile"
                    )
                outputs = messages[len(inputs) :]
            if not outputs:
                raise ValueError("graph produced no new output messages")
            exchange["output_messages"] = outputs
            # Snapshot tool representation is normalized; extractor accepts
            # the original message objects to preserve the public helper API.
            raw = _messages_of(final)
            selected = raw[len(inputs) :] if self.messages_mode == "append" else raw
            text, tool_calls, traces = self.result_extractor({"messages": selected})
        else:
            text, tool_calls, traces = self.result_extractor(final)
        exchange["capture_complete"] = self.result_extractor is extract_default
        if self.result_extractor is not extract_default:
            exchange["capture_limitations"] = "custom state/extractor; full graph state not captured"
        return SutResponse(
            text=text, tool_calls=tuple(tool_calls), traces=tuple(traces), exchanges=(exchange,)
        )

    async def _cleanup_response(
        self, graph: Any, thread_id: str | None, lifecycle: dict[str, Any], response: SutResponse
    ) -> SutResponse:
        lifecycle["cleanup"] = "started"
        try:
            await self._cleanup(graph, thread_id, lifecycle)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            error = f"graph cleanup failed ({type(exc).__name__})"
            return replace(response, error=f"{response.error}; {error}" if response.error else error)
        return response

    async def _cleanup(self, graph: Any, thread_id: str | None, lifecycle: dict[str, Any]) -> None:
        # Shield cooperative cleanup from caller cancellation and await it before
        # releasing the lifecycle lock. No detached worker or action retry.
        async def finish() -> None:
            try:
                async with asyncio.timeout(self.cleanup_timeout):
                    assert self.cleanup is not None
                    await _run_hook(self.cleanup, graph, thread_id)
                lifecycle["cleanup"] = "completed"
            except BaseException as exc:
                lifecycle["cleanup"] = "failed"
                lifecycle["cleanup_error_type"] = type(exc).__name__
                raise

        task = asyncio.create_task(finish())
        cancelled = False
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                if task.cancelled():
                    break
                cancelled = True
            except Exception:
                break
        if cancelled:
            # Retrieve any failure before propagating the caller cancellation.
            with suppress(BaseException):
                task.result()
            raise asyncio.CancelledError
        task.result()

    async def _invoke(self, state: dict[str, Any], thread_id: str | None = None) -> Any:
        graph = self.graph
        config = {"config": {"configurable": {"thread_id": thread_id}}} if thread_id else {}
        if hasattr(graph, "ainvoke"):
            return await graph.ainvoke(state, **config)
        if hasattr(graph, "invoke"):
            # An executor thread cannot be killed on timeout and may keep
            # executing tools; require cooperative async execution instead.
            raise ValueError("synchronous graph execution unsupported; provide ainvoke")
        final = None
        # Node-update streaming is not a final-state transcript.
        async for chunk in graph.astream(state, stream_mode="values", **config):
            final = chunk
        return final

    @staticmethod
    def _record_delivery(
        messages: list[Any],
        trace: Any,
        declared_channel: str,
        marker: str,
    ) -> None:
        """Scan state messages for the marker; record one DeliveryRecord per channel."""
        for m in messages:
            role = m.get("role", "") if isinstance(m, dict) else getattr(m, "role", "")
            content = (m.get("content") or "") if isinstance(m, dict) else (getattr(m, "content", "") or "")
            if not isinstance(content, str):
                content = str(content)
            channel = {
                "system": "system_prompt",
                "user": "user_message",
                "tool": "tool_result",
                "assistant": "memory",
            }.get(role, role)
            if role == "tool":
                name = m.get("name", "") if isinstance(m, dict) else getattr(m, "name", "")
                if name == "search_docs":
                    channel = "retrieved_document"
            present = marker in content
            trace.record_delivery(channel, marker, present=present)


def _package_versions() -> dict[str, str | None]:
    versions: dict[str, str | None] = {}
    for package in ("langgraph", "langchain-core", "langgraph-checkpoint"):
        try:
            versions[package] = version(package)
        except PackageNotFoundError:
            versions[package] = None
    return versions


def _resolve_hook(hook: LifecycleHook | str) -> LifecycleHook:
    if isinstance(hook, str):
        module, separator, attribute = hook.partition(":")
        if not separator or not module or not attribute:
            raise ValueError("lifecycle hook must be module:async_callable")
        hook = getattr(importlib.import_module(module), attribute)
    if not inspect.iscoroutinefunction(hook):
        raise ValueError("lifecycle hook must be an async function")
    return hook


def _validate_hooks(*hooks: LifecycleHook | str | None) -> None:
    for hook in hooks:
        if hook is not None:
            _resolve_hook(hook)


async def _run_hook(hook: LifecycleHook | str, graph: Any, thread_id: str | None) -> None:
    await _resolve_hook(hook)(graph, thread_id)
