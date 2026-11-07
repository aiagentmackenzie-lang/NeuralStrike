"""Bounded local transports for the SDK's modern MCP protocol engine.

This module is imported only by the optional MCP profile. Stdout is bounded
before JSON parsing; no shell, inherited credential environment or stderr echo.
HTTP credentials are sent only to the exact configured endpoint.
"""

from __future__ import annotations

import os
import signal
import subprocess
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager, suppress
from types import TracebackType
from typing import Any

import anyio
import httpx2
from anyio.streams.buffered import BufferedByteReceiveStream
from mcp import types
from mcp.shared.message import SessionMessage

from neuralstrike.utils.json import strict_json


class MCPTransportError(Exception):
    """A safe, local transport diagnostic (never target exception text)."""


class BoundedHTTPTransport(httpx2.AsyncBaseTransport):
    def __init__(self, endpoint: str, *, max_bytes: int, record: Callable[[dict[str, Any]], None]) -> None:
        self.endpoint = httpx2.URL(endpoint)
        self.max_bytes = max_bytes
        self.record = record
        self.inner = httpx2.AsyncHTTPTransport(retries=0)

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        if request.url != self.endpoint or request.method != "POST":
            raise MCPTransportError("MCP request outside the exact configured endpoint/profile")
        body = await request.aread()
        if len(body) > self.max_bytes:
            raise MCPTransportError("MCP request exceeds byte limit")
        observation: dict[str, Any] = {
            "direction": "http",
            "request": strict_json(body),
            "request_status": "attempted",
            "capture_complete": False,
        }
        self.record(observation)
        response = await self.inner.handle_async_request(request)
        try:
            observation["status_code"] = response.status_code
            observation["content_type"] = response.headers.get("content-type", "")
            content = bytearray()
            async for chunk in response.aiter_bytes():
                if len(content) + len(chunk) > self.max_bytes:
                    observation["error_type"] = "ResponseLimitExceeded"
                    raise MCPTransportError("MCP response exceeds byte limit")
                content.extend(chunk)
            observation["response_text"] = bytes(content).decode("utf-8")
            observation["capture_complete"] = True
            if 300 <= response.status_code < 400:
                raise MCPTransportError("MCP redirects are unsupported; configure the exact endpoint")
            if "application/json" in response.headers.get("content-type", ""):
                strict_json(bytes(content))
            # Decoded already. Avoid decompressing a second time and recompute length.
            headers = {
                k: v
                for k, v in response.headers.items()
                if k.lower() not in {"content-encoding", "content-length"}
            }
            return httpx2.Response(
                response.status_code,
                headers=headers,
                content=bytes(content),
                request=request,
                extensions=response.extensions,
            )
        finally:
            await response.aclose()
            self.record(observation)

    async def aclose(self) -> None:
        await self.inner.aclose()


class BoundedHTTPClient(httpx2.AsyncClient):
    """Distinguish a genuinely successful close from a CLOSED state after error."""

    close_succeeded = False

    async def aclose(self) -> None:
        self.close_succeeded = False
        await super().aclose()
        self.close_succeeded = True

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None = None,
        exc_value: BaseException | None = None,
        traceback: TracebackType | None = None,
    ) -> None:
        self.close_succeeded = False
        await super().__aexit__(exc_type, exc_value, traceback)
        self.close_succeeded = True


async def _terminate_descendants(pid: int) -> bool:
    try:
        os.killpg(pid, 0)
    except ProcessLookupError:
        return False
    with suppress(ProcessLookupError):
        os.killpg(pid, signal.SIGTERM)
    await anyio.sleep(0.05)
    with suppress(ProcessLookupError):
        os.killpg(pid, signal.SIGKILL)
    return True


async def _stop_process(process: anyio.abc.Process, cleanup: dict[str, Any]) -> None:
    close_failed = False
    if process.stdin is not None:
        try:
            await process.stdin.aclose()
        except Exception as exc:
            close_failed = True
            cleanup["stdin_close_error_type"] = type(exc).__name__
    with anyio.move_on_after(0.3):
        await process.wait()
    termination = "graceful"
    forced = False
    if process.returncode is None:
        termination = "terminated"
        try:
            os.killpg(process.pid, signal.SIGTERM)
            forced = True
        except ProcessLookupError:
            termination = "exited-before-signal"
        with anyio.move_on_after(0.5):
            await process.wait()
    if process.returncode is None:
        termination = "killed"
        try:
            os.killpg(process.pid, signal.SIGKILL)
            forced = True
        except ProcessLookupError:
            termination = "exited-before-signal"
        with anyio.move_on_after(0.5):
            await process.wait()
    cleanup.update(
        pid=process.pid,
        returncode=process.returncode,
        termination=termination,
        reaped=process.returncode is not None,
        clean=process.returncode == 0 and not forced and not close_failed,
    )
    if process.returncode is None:
        # Do not enter Process.aclose(): it waits indefinitely for an unreapable
        # process on some backends. Keep the failed-cleanup fact explicit.
        raise MCPTransportError("MCP subprocess did not exit after kill")
    # A parent can exit while its children keep running in our private group.
    descendants = await _terminate_descendants(process.pid)
    if descendants:
        cleanup["clean"] = False
    cleanup["descendant_cleanup_requested"] = descendants
    try:
        await process.aclose()
    except Exception as exc:
        cleanup["clean"] = False
        cleanup["resource_close_error_type"] = type(exc).__name__
        raise MCPTransportError("MCP subprocess resource close failed") from None


@asynccontextmanager
async def bounded_stdio(
    command: str,
    args: tuple[str, ...],
    *,
    env: dict[str, str],
    cwd: str | None,
    max_bytes: int,
    record: Callable[[dict[str, Any]], None],
    cleanup: dict[str, Any],
) -> AsyncIterator[Any]:
    if os.name != "posix":
        raise MCPTransportError("bounded stdio profile currently requires POSIX process groups")
    inherited = {
        key: os.environ[key]
        for key in ("HOME", "LOGNAME", "PATH", "SHELL", "TERM", "USER")
        if key in os.environ and not os.environ[key].startswith("()")
    }
    process = await anyio.open_process(
        [command, *args], env={**inherited, **env}, cwd=cwd, stderr=subprocess.DEVNULL, start_new_session=True
    )
    cleanup.update(pid=process.pid, reaped=False, clean=False)
    incoming_send, incoming = anyio.create_memory_object_stream[Any](0)
    outgoing, outgoing_receive = anyio.create_memory_object_stream[Any](0)

    async def read() -> None:
        assert process.stdout is not None
        buffered = BufferedByteReceiveStream(process.stdout)
        async with incoming_send:
            try:
                while True:
                    raw = await buffered.receive_until(b"\n", max_bytes=max_bytes + 1)
                    if len(raw) > max_bytes:
                        raise MCPTransportError("MCP stdio response exceeds byte limit")
                    # Parse duplicate/nonfinite checks before the SDK's typed parser.
                    obj = strict_json(raw)
                    record({"direction": "received", "message": obj, "capture_complete": True})
                    parsed = types.jsonrpc_message_adapter.validate_json(raw)
                    await incoming_send.send(SessionMessage(parsed))
            except (anyio.IncompleteRead, anyio.EndOfStream):
                return
            except Exception as exc:
                with suppress(anyio.BrokenResourceError, anyio.ClosedResourceError):
                    record(
                        {"direction": "received", "capture_complete": False, "error_type": type(exc).__name__}
                    )
                    await incoming_send.send(
                        MCPTransportError(f"MCP stdio input failed ({type(exc).__name__})")
                    )

    async def write() -> None:
        assert process.stdin is not None
        async with outgoing_receive:
            async for message in outgoing_receive:
                raw = message.message.model_dump_json(by_alias=True, exclude_unset=True).encode()
                if len(raw) > max_bytes:
                    raise MCPTransportError("MCP stdio request exceeds byte limit")
                record({"direction": "sent", "message": strict_json(raw), "capture_complete": True})
                await process.stdin.send(raw + b"\n")

    async with anyio.create_task_group() as group:
        group.start_soon(read)
        group.start_soon(write)
        try:
            yield incoming, outgoing
        finally:
            with anyio.CancelScope(shield=True):
                try:
                    await _stop_process(process, cleanup)
                finally:
                    await incoming.aclose()
                    await outgoing.aclose()
                    group.cancel_scope.cancel()


def _http_messages(observation: dict[str, Any]) -> list[Any]:
    text = observation["response_text"]
    if "json" in observation.get("content_type", "").lower():
        return [strict_json(text.encode())]
    messages = []
    data: list[str] = []
    for line in [*text.splitlines(), ""]:
        if line.startswith("data:"):
            data.append(line[5:].lstrip(" "))
        elif not line and data:
            messages.append(strict_json("\n".join(data).encode()))
            data.clear()
    return messages


def observed_tool_names(observations: list[dict[str, Any]]) -> list[str]:
    """Check usable SDK inventory against the actual bounded tools/list replies.

    This does not replace the SDK's protocol/parser validation. It ensures a
    MUST-drop invalid descriptor cannot silently look like a complete inventory.
    """
    methods: dict[Any, str] = {}
    names: list[str] = []
    for observation in observations:
        direction = observation["direction"]
        if direction == "http":
            request = observation["request"]
            if not observation["capture_complete"] or request["method"] != "tools/list":
                continue
            messages = _http_messages(observation)
            expected_id = request["id"]
        elif direction == "sent":
            message = observation["message"]
            if "id" in message:
                methods[message["id"]] = message.get("method", "")
            continue
        elif direction == "received" and observation["capture_complete"]:
            message = observation["message"]
            if methods.get(message.get("id")) != "tools/list":
                continue
            messages = [message]
            expected_id = message["id"]
        else:
            continue
        for message in messages:
            if isinstance(message, dict) and message.get("id") == expected_id:
                tools = message.get("result", {}).get("tools", [])
                names.extend(tool["name"] for tool in tools)
    return names
