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

import copy
import importlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from neuralstrike.adapters.base import Message, TargetAdapter, ToolSchema
from neuralstrike.evaluation.checkpoint import capture_response
from neuralstrike.evaluation.verdict import SutResponse, ToolCall
from neuralstrike.utils.logging import get_logger

__all__ = ["GraphResolver", "LangGraphAdapter", "build_default_state", "extract_default"]

logger = get_logger("neuralstrike.adapters.langgraph")


StateBuilder = Callable[[str, str | None, tuple[Message, ...]], dict[str, Any]]
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
    ) -> None:
        if messages_mode not in {"append", "output"}:
            raise ValueError("messages_mode must be append|output")
        if target_id is not None and (not isinstance(target_id, str) or not target_id.strip()):
            raise ValueError("target_id must be a nonempty application identity")
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
        capture_response(lambda: SutResponse(text="", exchanges=(exchange,)))
        try:
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
            final = await self._invoke(state)
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
        except Exception as exc:
            logger.error("LangGraph drive failed (%s)", type(exc).__name__)
            exchange["error_type"] = type(exc).__name__
            return SutResponse(text="", error=f"{type(exc).__name__}: {exc}", exchanges=(exchange,))
        return SutResponse(
            text=text, tool_calls=tuple(tool_calls), traces=tuple(traces), exchanges=(exchange,)
        )

    async def _invoke(self, state: dict[str, Any]) -> Any:
        graph = self.graph
        if hasattr(graph, "ainvoke"):
            return await graph.ainvoke(state)
        if hasattr(graph, "invoke"):
            # An executor thread cannot be killed on timeout and may keep
            # executing tools; require cooperative async execution instead.
            raise ValueError("synchronous graph execution unsupported; provide ainvoke")
        final = None
        # Node-update streaming is not a final-state transcript.
        async for chunk in graph.astream(state, stream_mode="values"):
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
