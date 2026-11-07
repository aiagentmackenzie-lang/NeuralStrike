"""Explicit modern MCP discovery/execution with immutable local receipts.

Read-only discovery is not a security assessment. All tool execution requires a
complete exact argument plan; no automatic retry, MRTR continuation or downgrade.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import time
import uuid
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
from functools import partial
from importlib.metadata import version
from pathlib import Path
from typing import Any, TypeVar
from urllib.parse import urlsplit

import anyio
import mcp
from jsonschema import Draft202012Validator
from mcp import Client, types
from mcp.client.streamable_http import streamable_http_client
from mcp_types.methods import validate_server_result

from neuralstrike.adapters.mcp_transport import (
    BoundedHTTPClient,
    BoundedHTTPTransport,
    bounded_stdio,
    observed_tool_names,
)
from neuralstrike.runtime.outbound import OutboundPolicy
from neuralstrike.utils.artifacts import write_private_artifact

MCP_VERSION = "2026-07-28"

_T = TypeVar("_T")


class _Admission:
    """Use existing admission controls while leaving opaque server usage unknown."""

    def __init__(self, receipt: dict[str, Any], max_requests: int, requests_per_minute: float | None) -> None:
        self.policy = OutboundPolicy(max_requests=max_requests, requests_per_minute=requests_per_minute)
        self.receipt = receipt

    async def call(self, operation: Callable[[], Awaitable[_T]]) -> _T:
        try:
            async with self.policy.request():
                return await operation()
        finally:
            # Never report the policy's unmetered numeric token accumulator as
            # target usage: MCP tools may themselves invoke paid services.
            self.receipt["runtime"] = {
                "max_requests": self.policy.max_requests,
                "requests_admitted": self.policy.dispatched,
                "requests_per_minute": self.policy.requests_per_minute,
                "concurrency": self.policy.concurrency.summary(),
                "cost_usd": None,
                "cost_status": "unavailable",
                "tokens": None,
                "token_status": "target-internal usage not metered",
            }


_PRIVATE_SDK_LOGS: ContextVar[bool] = ContextVar("private_mcp_sdk_diagnostics", default=False)
_SDK_LOG_PATHS = tuple(
    str(Path(filename).parent) + os.sep for filename in (mcp.__file__, types.__file__) if filename
)


class _SDKLogFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return not (_PRIVATE_SDK_LOGS.get() and record.pathname.startswith(_SDK_LOG_PATHS))


_SDK_LOG_FILTER = _SDKLogFilter()


@contextmanager
def _private_sdk_diagnostics() -> Iterator[None]:
    # SDK 2.3 also uses a generic logger named 'client'; match package source,
    # not just logger names. Handler filters remain harmless outside this task.
    handlers = set(logging.getLogger().handlers)
    for logger in logging.Logger.manager.loggerDict.values():
        if isinstance(logger, logging.Logger):
            handlers.update(logger.handlers)
    if logging.lastResort is not None:
        handlers.add(logging.lastResort)
    for handler in handlers:
        handler.addFilter(_SDK_LOG_FILTER)
    token = _PRIVATE_SDK_LOGS.set(True)
    try:
        yield
    finally:
        _PRIVATE_SDK_LOGS.reset(token)


@dataclass(frozen=True)
class MCPTarget:
    url: str | None = None
    command: str | None = None
    args: tuple[str, ...] = ()
    env: dict[str, str] = field(default_factory=dict, repr=False)
    cwd: str | None = None
    bearer_token: str | None = field(default=None, repr=False)
    protocol_version: str = MCP_VERSION

    def __post_init__(self) -> None:
        if self.protocol_version != MCP_VERSION:
            raise ValueError("unsupported MCP profile; expected 2026-07-28")
        if bool(self.url) == bool(self.command):
            raise ValueError("provide exactly one MCP URL or stdio command")
        if self.url:
            parsed = urlsplit(self.url)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError("MCP endpoint must be HTTP(S), without userinfo/query/fragment")
            if self.args or self.env or self.cwd:
                raise ValueError("stdio settings require a stdio command")
        elif self.bearer_token is not None:
            raise ValueError("HTTP bearer credentials require an HTTP target")
        if self.bearer_token is not None and ("\r" in self.bearer_token or "\n" in self.bearer_token):
            raise ValueError("invalid MCP credential header")

    def description(self) -> dict[str, Any]:
        return {
            "transport": "http" if self.url else "stdio",
            "url": self.url,
            "command": self.command,
            "args": list(self.args),
            "cwd": self.cwd,
            "environment_names": sorted(self.env),
            "authentication_configured": bool(self.bearer_token),
            "protocol_version": self.protocol_version,
        }


def _dump(path: Path, value: Any) -> None:
    content = json.dumps(value, indent=2, sort_keys=True, allow_nan=False)
    if len(content.encode()) > 64 * 1024 * 1024:
        raise ValueError("MCP artifact exceeds file limit")
    write_private_artifact(path, content)


def _bounded_schema(schema: Any, depth: int = 0) -> None:
    """A declared structural subset; never run unbounded target regex/ref code.

    Other constructs remain discoverable but are unsupported for execution in
    this bounded profile. No remote schema fetch or recursive validator is used.
    """
    if depth > 16 or not isinstance(schema, (dict, bool)):
        raise ValueError("unsupported execution schema shape/depth")
    if isinstance(schema, bool):
        return
    allowed = {
        "type",
        "properties",
        "required",
        "additionalProperties",
        "items",
        "enum",
        "const",
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "multipleOf",
        "minLength",
        "maxLength",
        "minItems",
        "maxItems",
        "minProperties",
        "maxProperties",
        "title",
        "description",
        "default",
        "examples",
        "$schema",
        "readOnly",
        "writeOnly",
        "deprecated",
    }
    if set(schema) - allowed or len(schema.get("properties", {})) > 128 or len(schema.get("enum", [])) > 128:
        raise ValueError("unsupported execution schema construct or size")
    if "$schema" in schema and schema["$schema"] != "https://json-schema.org/draft/2020-12/schema":
        raise ValueError("unsupported execution schema dialect")
    for child in schema.get("properties", {}).values():
        _bounded_schema(child, depth + 1)
    for key in ("items", "additionalProperties"):
        if key in schema:
            _bounded_schema(schema[key], depth + 1)


def _validate_plan(tools: list[dict[str, Any]], plan: dict[str, dict[str, Any]]) -> None:
    inventory = {tool["name"]: tool for tool in tools}
    if len(inventory) != len(tools):
        raise ValueError("duplicate tool names in inventory")
    for name, arguments in plan.items():
        if name not in inventory or not isinstance(arguments, dict):
            raise ValueError("execution plan has an unknown tool or invalid arguments")
        schema = inventory[name]["inputSchema"]
        _bounded_schema(schema)
        if "outputSchema" in inventory[name]:
            _bounded_schema(inventory[name]["outputSchema"])
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(arguments)


async def _inventory(client: Client, receipt: dict[str, Any], admission: _Admission) -> list[dict[str, Any]]:
    receipt["stage"] = "inventory"
    cursor = None
    cursors: set[str] = set()
    tools: list[dict[str, Any]] = []
    for _ in range(10):
        listed = await admission.call(partial(client.list_tools, cursor=cursor, cache_mode="bypass"))
        if listed.result_type != "complete":
            raise ValueError("incomplete tool inventory")
        tools.extend(tool.model_dump(mode="json", by_alias=True, exclude_none=True) for tool in listed.tools)
        receipt["tools"] = tools
        receipt["tool_names"] = [tool["name"] for tool in tools]
        if len(tools) > 1000 or len(set(receipt["tool_names"])) != len(tools):
            raise ValueError("oversized or duplicate tool inventory")
        cursor = listed.next_cursor
        if cursor is None:
            return tools
        if cursor in cursors:
            raise ValueError("repeated inventory cursor")
        cursors.add(cursor)
    raise ValueError("inventory pagination limit exceeded")


async def _execute(
    client: Client, receipt: dict[str, Any], plan: dict[str, dict[str, Any]], admission: _Admission
) -> None:
    for name, arguments in plan.items():
        receipt["stage"] = "tool-execution"
        call: dict[str, Any] = {
            "tool": name,
            "arguments": arguments,
            "status": "started",
            "retry_policy": "one dispatch; no retry or MRTR continuation",
        }
        receipt["tool_calls"].append(call)
        # Bypass the high-level SDK's automatic input-required retry driver.
        result = await admission.call(
            partial(client.session.call_tool, name, arguments, allow_input_required=True)
        )
        call["result"] = result.model_dump(mode="json", by_alias=True, exclude_none=True)
        call["status"] = "complete"
        if (
            not isinstance(result, types.CallToolResult)
            or result.result_type != "complete"
            or result.is_error
        ):
            call["status"] = "incomplete"
            raise ValueError("tool result incomplete, input-required or error; no retry authorized")


async def _session(
    transport: Any,
    receipt: dict[str, Any],
    timeout: float,
    execution_plan: dict[str, dict[str, Any]],
    admission: _Admission,
    observations: list[dict[str, Any]],
) -> None:
    async with Client(
        transport,
        mode=MCP_VERSION,
        cache=None,
        read_timeout_seconds=timeout,
        client_info=types.Implementation(name="neuralstrike", version=version("neuralstrike")),
    ) as client:
        # Pinning mode adopts a placeholder; make one actual discovery request.
        receipt["stage"] = "discovery"
        raw = await admission.call(lambda: client.session.send_discover(MCP_VERSION))
        validate_server_result("server/discover", MCP_VERSION, raw)
        discovered = types.DiscoverResult.model_validate(raw)
        if MCP_VERSION not in discovered.supported_versions or discovered.result_type != "complete":
            raise ValueError("server does not support the selected complete discovery profile")
        client.session.adopt(discovered)
        receipt["protocol_version"] = client.protocol_version
        receipt["server_info"] = (
            client.server_info.model_dump(mode="json", exclude_none=True) if client.server_info else None
        )
        receipt["discovery"] = discovered.model_dump(mode="json", by_alias=True, exclude_none=True)
        if discovered.capabilities.tools is None:
            raise ValueError("server tools capability unavailable")
        tools = await _inventory(client, receipt, admission)
        receipt["stage"] = "inventory-verification"
        receipt["raw_tool_names"] = observed_tool_names(observations)
        if receipt["raw_tool_names"] != receipt["tool_names"]:
            raise ValueError("SDK-usable inventory omits or changes observed descriptors")
        receipt["stage"] = "plan-validation"
        _validate_plan(tools, execution_plan)
        await _execute(client, receipt, execution_plan, admission)
        receipt["stage"] = "cleanup"


async def _inspect(
    target: MCPTarget,
    receipt: dict[str, Any],
    record: Any,
    *,
    timeout: float,
    max_response_bytes: int,
    execution_plan: dict[str, dict[str, Any]],
    admission: _Admission,
    observations: list[dict[str, Any]],
) -> None:
    with anyio.fail_after(timeout):
        if target.url:
            transport = BoundedHTTPTransport(target.url, max_bytes=max_response_bytes, record=record)
            headers = {"Authorization": f"Bearer {target.bearer_token}"} if target.bearer_token else {}
            http = BoundedHTTPClient(
                transport=transport,
                headers=headers,
                timeout=timeout,
                trust_env=False,
                follow_redirects=False,
            )
            try:
                async with http:
                    await _session(
                        streamable_http_client(
                            target.url, http_client=http, max_sse_event_size=max_response_bytes
                        ),
                        receipt,
                        timeout,
                        execution_plan,
                        admission,
                        observations,
                    )
            finally:
                receipt["cleanup"] = {"clean": http.close_succeeded, "http_client_closed": http.is_closed}
        else:
            assert target.command is not None
            await _session(
                bounded_stdio(
                    target.command,
                    target.args,
                    env=target.env,
                    cwd=target.cwd,
                    max_bytes=max_response_bytes,
                    record=record,
                    cleanup=receipt["cleanup"],
                ),
                receipt,
                timeout,
                execution_plan,
                admission,
                observations,
            )
            if not receipt["cleanup"].get("clean"):
                raise ValueError("subprocess required forced or unsuccessful shutdown")


def _error_details(exc: BaseException, stage: str) -> dict[str, Any]:
    pending = [exc]
    causes: set[str] = set()
    codes: set[int] = set()
    for _ in range(32):
        if not pending:
            break
        item = pending.pop()
        causes.add(type(item).__name__)
        code = getattr(item, "code", None)
        if type(code) is int:
            codes.add(code)
        pending.extend(getattr(item, "exceptions", ()))
    return {"type": type(exc).__name__, "stage": stage, "causes": sorted(causes), "rpc_codes": sorted(codes)}


async def inspect_mcp(
    target: MCPTarget,
    *,
    run_dir: str | Path,
    timeout: float = 10,
    max_response_bytes: int = 1024 * 1024,
    max_requests: int = 64,
    requests_per_minute: float | None = None,
    execution_plan: dict[str, dict[str, Any]] | None = None,
) -> Path:
    """Persist an immutable capability receipt, including partial failures.

    Cancellation commits available evidence and propagates. Complete discovery or
    authorized execution never constitutes a behavioral security verdict.
    """
    # Fail optional setup before creating an ambiguous 'running' receipt.
    if version("mcp") != "2.3.0":
        raise ValueError("MCP SDK profile requires mcp==2.3.0")
    if (
        not math.isfinite(timeout)
        or timeout <= 0
        or type(max_response_bytes) is not int
        or max_response_bytes < 1
        or max_response_bytes > 16 * 1024 * 1024
    ):
        raise ValueError("invalid MCP timeout or response limit")
    target = replace(target, args=tuple(target.args), env=dict(target.env))
    plan = json.loads(json.dumps(execution_plan or {}, allow_nan=False))
    if not isinstance(plan, dict) or len(plan) > 32:
        raise ValueError("invalid or oversized execution plan")
    # Validate admission settings before starting or persisting an execution.
    OutboundPolicy(max_requests=max_requests, requests_per_minute=requests_per_minute)
    root = Path(run_dir) / f"mcp-{uuid.uuid4().hex}"
    root.mkdir(parents=True, mode=0o700, exist_ok=False)
    _dump(
        root / "plan.json",
        {
            "target": target.description(),
            "execution_plan": plan,
            "execution_order": list(plan),
            "timeout": timeout,
            "max_response_bytes": max_response_bytes,
            "max_requests": max_requests,
            "requests_per_minute": requests_per_minute,
        },
    )
    _dump(
        root / "manifest.json",
        {"kind": "neuralstrike-mcp-inspection", "schema_version": 1, "state": "running"},
    )
    receipt: dict[str, Any] = {
        "kind": "neuralstrike-mcp-inspection",
        "schema_version": 1,
        "status": "incomplete",
        "security_assessment": False,
        "protocol_version": None,
        "server_info": None,
        "versions": {name: version(name) for name in ("neuralstrike", "mcp", "mcp-types", "httpx2")},
        "tools": [],
        "tool_names": [],
        "tool_calls": [],
        "cleanup": {},
        "stage": "connect",
        "error": None,
        "started_at": time.time(),
        "limitations": [
            "Discovery/capability receipt only; no security pass or remediation attestation.",
            "Server identity/version is self-reported, not an authenticated application build.",
            "Private raw bodies can contain sensitive target data; headers/environment values are excluded.",
            "No automatic downgrade, retry, sampling, elicitation or consequential MRTR continuation.",
            "SDK logs are opaque in this task; private bodies and safe error classes/codes remain.",
            "Stdio executes trusted local code, not a sandbox. Stderr is omitted from capture.",
            "Call outcomes describe protocol completion, not verified remote side effects or rollback.",
        ],
    }
    observations: list[dict[str, Any]] = []
    total = 0

    def record(observation: dict[str, Any]) -> None:
        nonlocal total
        size = len(json.dumps(observation).encode())
        total += size
        if len(observations) >= 128 or total > 32 * 1024 * 1024:
            raise ValueError("MCP transcript limit exceeded")
        observations.append(json.loads(json.dumps(observation, allow_nan=False)))

    try:
        with _private_sdk_diagnostics():
            await _inspect(
                target,
                receipt,
                record,
                timeout=timeout,
                max_response_bytes=max_response_bytes,
                execution_plan=plan,
                admission=_Admission(receipt, max_requests, requests_per_minute),
                observations=observations,
            )
        receipt["status"] = "complete"
        receipt["stage"] = "complete"
    except BaseException as exc:
        # Never copy credential-bearing server/transport exception messages.
        receipt["error"] = _error_details(exc, receipt["stage"])
        if not isinstance(exc, Exception):
            raise
    finally:
        receipt["completed_at"] = time.time()
        receipt["http_statuses"] = [item["status_code"] for item in observations if "status_code" in item]
        _dump(root / "transcript.json", observations)
        _dump(root / "receipt.json", receipt)
        files = {
            name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in ("plan.json", "transcript.json", "receipt.json")
        }
        _dump(
            root / "manifest.json",
            {
                "kind": "neuralstrike-mcp-inspection",
                "schema_version": 1,
                "state": "committed",
                "files": files,
            },
        )
    return root
