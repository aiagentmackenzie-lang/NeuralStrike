"""Bounded, non-consequential OpenAI capability probes.

A successful preflight establishes an observed protocol capability only. It
neither demonstrates resistance nor attests a provider's identity/build.
"""

from __future__ import annotations

import asyncio
import math
import os
from importlib.metadata import version
from typing import Any

import httpx

from neuralstrike import __version__
from neuralstrike.adapters.base import ToolSchema
from neuralstrike.adapters.openai_endpoint import OpenAIEndpointAdapter


def environment_credential(reference: str | None) -> str | None:
    """Resolve a named environment value without putting its value in diagnostics."""
    if reference is None:
        return None
    credential = os.environ.get(reference)
    if not credential or not credential.strip():
        raise ValueError("credential environment variable is missing or empty")
    if "\r" in credential or "\n" in credential:
        raise ValueError("credential contains invalid header characters")
    return credential


async def check_openai_target(
    url: str,
    *,
    model: str,
    api_key: str | None = None,
    timeout: float = 30.0,
    max_response_bytes: int = 16 * 1024 * 1024,
    require_tools: bool = True,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    """Query one harmless tool round-trip; no retries or consequential handlers.

    Cancellation propagates after closing the client. A deadline becomes an
    explicit incomplete receipt. Raw request/response bodies are not exported.
    """
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout must be finite and positive")
    adapter = OpenAIEndpointAdapter(
        url,
        model=model,
        api_key=api_key,
        tier="function-calling" if require_tools else "text",
        timeout=timeout,
        max_response_bytes=max_response_bytes,
        transport=transport,
    )
    tool = ToolSchema(
        "neuralstrike_preflight",
        "Harmless protocol probe; returns a canned acknowledgment.",
        {
            "type": "object",
            "properties": {"value": {"type": "string", "enum": ["probe"]}},
            "required": ["value"],
            "additionalProperties": False,
        },
    )
    error = None
    tool_observed = False
    statuses: list[int] = []
    try:
        response = await asyncio.wait_for(
            adapter.query(
                'Call neuralstrike_preflight with value "probe", then respond with "ok".'
                if require_tools
                else 'Respond with "ok".',
                tools=(tool,) if require_tools else (),
            ),
            timeout=timeout,
        )
        tool_observed = any(
            call.name == tool.name and call.arguments == {"value": "probe"} for call in response.tool_calls
        )
        statuses = [e["status_code"] for e in response.exchanges if "status_code" in e]
        error = response.error
        if not error and require_tools and not tool_observed:
            error = "requested tool capability was not demonstrated"
    except asyncio.TimeoutError:
        error = "preflight timed out"
    finally:
        cleanup = {"status": "started"}
        try:
            await adapter.close()
        except Exception as exc:
            cleanup = {"status": "failed", "error_type": type(exc).__name__}
            failure = f"preflight cleanup failed ({type(exc).__name__})"
            error = f"{error}; {failure}" if error else failure
        else:
            cleanup = {"status": "completed"}
    endpoint = httpx.URL(adapter._endpoint())
    return {
        "kind": "neuralstrike-target-preflight",
        "schema_version": 1,
        "profile": "openai-chat-completions-json-v1",
        "status": "incomplete" if error else "ready",
        "ready": error is None,
        "security_assessment": False,
        "endpoint": str(endpoint.copy_with(username=None, password=None, query=None, fragment=None)),
        "requested_model": model,
        "authentication_configured": api_key is not None,
        "tool_call_required": require_tools,
        "tool_call_observed": tool_observed,
        "http_statuses": statuses,
        "cleanup": cleanup,
        "error": error,
        "versions": {"neuralstrike": __version__, "httpx": version("httpx")},
        "limitations": [
            "Observed capability only; no security verdict or authorization attestation.",
            "Server build/version and provider identity are not independently verified.",
            "Tool results are served locally; customer retrieval/memory hooks are not verified.",
            "No automatic retries; provider usage/cost is unavailable, not zero.",
        ],
    }
