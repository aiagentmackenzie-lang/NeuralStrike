"""Target adapters — drive real SUTs and observe what they *do*.

Phase 1 makes NeuralStrike a behavior-observing harness. Instead of sending
one prompt to a model name, an adapter drives a real target (an OpenAI-style
endpoint, a compiled LangGraph, an MCP server over HTTP, an A2A agent) and
returns a :class:`~neuralstrike.evaluation.verdict.SutResponse` carrying the
response **text**, the **tool_calls** the SUT emitted, and the **traces** of
any instrumented canary tools that actually executed (Tier-2 / Behavioral
evidence).

The adapter is the boundary where untrusted SUT output becomes typed
evidence. Oracles consume the :class:`SutResponse`; they never touch the
transport directly.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from neuralstrike.evaluation.verdict import SutResponse
from neuralstrike.oracles.tool_harness import CanaryTool, TraceLog

__all__ = [
    "Message",
    "TargetAdapter",
    "ToolSchema",
]


@dataclass(frozen=True)
class ToolSchema:
    """A tool definition the adapter advertises to the SUT.

    ``parameters`` is a JSON Schema (Draft 7) describing the arguments the
    SUT is allowed to send. For instrumented canary tools this comes from
    :class:`~neuralstrike.oracles.tool_harness.CanaryTool`.
    """

    name: str
    description: str
    parameters: dict[str, Any] = field(default_factory=dict)
    required: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class Message:
    """One turn of conversation history passed to an adapter."""

    role: str  # "system" | "user" | "assistant" | "tool"
    content: str
    tool_call_id: str | None = None
    name: str | None = None


class TargetAdapter(ABC):
    """Drives a real SUT and returns observed behaviour as a :class:`SutResponse`.

    Subclasses implement :meth:`query`. The contract:

    - **text**        — the SUT's words (Verbal evidence).
    - **tool_calls**  — what the SUT tried to do (IntentToAct evidence).
    - **traces**      — instrumented canary tools that actually ran
                        (Behavioral / Tier-2 evidence). Populated only when
                        the adapter executes a canary tool handler itself.
    - **error**       — a transport/parse error is recorded here, never
                        faked into a "response."

    Fail-closed: a backend error is recorded as ``error`` on the
    :class:`SutResponse` (the run treats it as Inconclusive), never as a
    fabricated success or resistance.
    """

    name: str = "adapter"
    tier: str = "text"  # "text" | "function-calling" | "instrumented"

    @abstractmethod
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
        """Drive one turn against the SUT; return observed behaviour.

        ``delivery_channel`` / ``delivery_marker`` (Phase 2): when both are
        set, the adapter inspects the messages it is about to send, scans
        each channel for ``delivery_marker``, and records a
        :class:`~neuralstrike.oracles.tool_harness.DeliveryRecord` on
        ``trace``. The exit gate verifies indirect-injection vectors by this
        adapter trace, never by reading the prompt.
        """
        raise NotImplementedError

    async def close(self) -> None:
        """Release transport resources. Override if the adapter holds a client."""
        return None

    @staticmethod
    def record_delivery_trace(
        trace: TraceLog | None,
        *,
        channel: str,
        marker: str,
        content: str,
    ) -> None:
        """Record a delivery record iff the marker is (not) present in ``content``.

        Helpers used by adapters that build role-tagged messages: after the
        adapter constructs a channel's content, it calls this to confirm the
        injection marker landed there. The Phase 2 contract: the adapter
        surfaces the channel distinctly; the test reads the trace.
        """
        if trace is None or not marker:
            return
        trace.record_delivery(channel, marker, present=marker in content)

    @staticmethod
    def canary_tools_as_schemas(canary_tools: tuple[CanaryTool, ...]) -> tuple[ToolSchema, ...]:
        """Advertise canary tools to the SUT using their own JSON schema."""
        return tuple(
            ToolSchema(name=t.name, description=t.description, parameters=t.parameters, required=t.required)
            for t in canary_tools
        )
