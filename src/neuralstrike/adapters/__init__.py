"""NeuralStrike target adapters — drive real SUTs, observe behaviour.

Phase 1: NeuralStrike stops sending one prompt to a model name. An adapter
drives a real target (OpenAI-style endpoint, compiled LangGraph, MCP-over-HTTP,
A2A agent) and returns a :class:`~neuralstrike.evaluation.verdict.SutResponse`
carrying response text, emitted tool_calls, and instrumented-tool execution
traces (Tier-2 / Behavioral evidence).

Adapters are transport; oracles are verdicts. The two layers meet only at
:class:`SutResponse`.
"""

from neuralstrike.adapters.a2a import A2AAdapter
from neuralstrike.adapters.base import Message, TargetAdapter, ToolSchema
from neuralstrike.adapters.langgraph import LangGraphAdapter
from neuralstrike.adapters.langgraph_server import LangGraphServerAdapter
from neuralstrike.adapters.mcp_http import MCPHTTPAdapter
from neuralstrike.adapters.openai_endpoint import OpenAIEndpointAdapter

__all__ = [
    "A2AAdapter",
    "LangGraphAdapter",
    "LangGraphServerAdapter",
    "MCPHTTPAdapter",
    "Message",
    "OpenAIEndpointAdapter",
    "TargetAdapter",
    "ToolSchema",
]
