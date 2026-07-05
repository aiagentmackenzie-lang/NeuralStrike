"""LangGraph adapter — drives a real compiled graph end-to-end.

Discovers the compiled graph via attribute lookup (`graph` / `app` / `agent`
/ `build_graph()`) on a module or object, then drives it with ``ainvoke``
(async) or ``invoke`` (sync fallback). Tool calls are read from the final
state so oracles observe what the agent *did*.

langgraph is an **optional** extra: when installed, the adapter drives a real
``langgraph.graph.StateGraph``-compiled graph; when not, it drives any
duck-typed object exposing ``ainvoke``/``invoke`` (the bundled fixture does
this). The adapter code is identical either way, so the exit gate passes on a
fresh clone without forcing a heavy install.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from neuralstrike.adapters.base import Message, TargetAdapter, ToolSchema
from neuralstrike.evaluation.verdict import SutResponse, ToolCall
from neuralstrike.utils.logging import get_logger

__all__ = ["GraphResolver", "LangGraphAdapter", "build_default_state", "extract_default"]

logger = get_logger("neuralstrike.adapters.langgraph")


StateBuilder = Callable[[str, str | None, tuple[Message, ...]], dict[str, Any]]
ResultExtractor = Callable[[Any], tuple[str, list[ToolCall], list[dict[str, Any]]]]


def build_default_state(
    prompt: str, system_prompt: str | None, history: tuple[Message, ...]
) -> dict[str, Any]:
    """Default state shape: ``{"messages": [...]}`` (the LangGraph convention)."""
    msgs: list[dict[str, Any]] = []
    if system_prompt:
        msgs.append({"role": "system", "content": system_prompt})
    for m in history:
        msgs.append({"role": m.role, "content": m.content})
    msgs.append({"role": "user", "content": prompt})
    return {"messages": msgs}


def extract_default(final_state: Any) -> tuple[str, list[ToolCall], list[dict[str, Any]]]:
    """Read text + tool_calls from a final state (dict or langchain message).

    Handles both the duck-typed fixture (dict messages) and real langchain
    ``AIMessage`` objects (which expose ``.content`` and ``.tool_calls``).
    """
    messages = _messages_of(final_state)
    if not messages:
        return "", [], []
    last = messages[-1]
    text = _attr(last, "content", default="") or ""
    raw_tool_calls = _attr(last, "tool_calls", default=None) or []
    tool_calls: list[ToolCall] = []
    for tc in raw_tool_calls:
        name = _attr(tc, "name", default="") or _tc_get(tc, "name", "")
        args = _attr(tc, "args", default=None)
        if args is None:
            args = _tc_get(tc, "arguments", None) or _tc_get(tc, "args", None) or {}
        tc_id = _attr(tc, "id", default=None) or _tc_get(tc, "id", None)
        if name:
            tool_calls.append(ToolCall(name=name, arguments=args, tool_call_id=tc_id))
    return text, tool_calls, []


def _messages_of(state: Any) -> list[Any]:
    if isinstance(state, dict):
        return list(state.get("messages", []))
    msgs = getattr(state, "messages", None)
    return list(msgs) if msgs is not None else []


def _attr(obj: Any, name: str, *, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _tc_get(tc: Any, key: str, default: Any = None) -> Any:
    if isinstance(tc, dict):
        return tc.get(key, default)
    return getattr(tc, key, default)


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
        target = mod if not attr else getattr(mod, attr, mod)
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
        raise ValueError(
            "could not discover a compiled graph (looked for graph/app/agent/build_graph()); "
            f"got {target!r}"
        )


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
    ) -> None:
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
    ) -> SutResponse:
        _ = tools, canary_tools, trace  # LangGraph owns its own tool wiring.
        state = self.state_builder(prompt, system_prompt, history)
        try:
            graph = self.graph
            if hasattr(graph, "ainvoke"):
                final = await graph.ainvoke(state)
            elif hasattr(graph, "invoke"):
                final = graph.invoke(state)
            else:
                # astream: consume to completion.
                final = None
                async for chunk in graph.astream(state):
                    final = chunk
        except Exception as exc:
            logger.error("LangGraph drive failed: %s", exc)
            return SutResponse(text="", error=f"{type(exc).__name__}: {exc}")
        text, tool_calls, traces = self.result_extractor(final)
        return SutResponse(
            text=text,
            tool_calls=tuple(tool_calls),
            traces=tuple(traces),
        )
