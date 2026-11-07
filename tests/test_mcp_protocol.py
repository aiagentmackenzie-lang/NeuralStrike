"""Pinned modern MCP against independent local protocol implementations."""

import json
import os
import sys
import threading
from contextlib import suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from tests.fixtures.mcp_modern_stdio import response as fixture_response

from neuralstrike.adapters.mcp_protocol import MCPTarget, inspect_mcp

FIXTURE = Path(__file__).parent / "fixtures" / "mcp_modern_stdio.py"


def stdio_target(tmp_path, mode="valid"):
    return MCPTarget(
        command=sys.executable,
        args=(str(FIXTURE), mode),
        env={"FIXTURE_PID": str(tmp_path / "pid"), "FIXTURE_EVENTS": str(tmp_path / "events")},
    )


def read_receipt(root):
    return json.loads((root / "receipt.json").read_text())


async def test_stdio_discovery_is_pinned_read_only_and_private(tmp_path):
    root = await inspect_mcp(stdio_target(tmp_path), run_dir=tmp_path / "runs")
    receipt = read_receipt(root)
    assert receipt["status"] == "complete"
    assert receipt["security_assessment"] is False
    assert receipt["protocol_version"] == "2026-07-28"
    assert receipt["server_info"] == {"name": "independent-stdlib-mcp", "version": "1.0"}
    assert receipt["versions"]["mcp"] == "2.3.0"
    assert receipt["tool_names"] == ["read_account"]
    events = [json.loads(line) for line in (tmp_path / "events").read_text().splitlines()]
    assert [event["method"] for event in events] == ["server/discover", "tools/list"]
    assert (root / "receipt.json").stat().st_mode & 0o777 == 0o600
    assert json.loads((root / "manifest.json").read_text())["state"] == "committed"
    with pytest.raises(ProcessLookupError):
        os.kill(int((tmp_path / "pid").read_text()), 0)


@pytest.mark.parametrize("mode", ["wrong-version", "malformed", "timeout", "oversize", "pagination-loop"])
async def test_invalid_stdio_is_incomplete_and_process_is_reaped(tmp_path, mode):
    root = await inspect_mcp(
        stdio_target(tmp_path, mode), run_dir=tmp_path / "runs", timeout=0.4, max_response_bytes=4096
    )
    receipt = read_receipt(root)
    assert receipt["status"] == "incomplete"
    assert receipt["error"]
    assert receipt["security_assessment"] is False
    assert json.loads((root / "manifest.json").read_text())["state"] == "committed"
    with pytest.raises(ProcessLookupError):
        os.kill(int((tmp_path / "pid").read_text()), 0)


@pytest.mark.parametrize("mode", ["valid", "input-required", "tool-error"])
async def test_authorized_execution_is_once_without_automatic_mrtr_retry(tmp_path, mode):
    root = await inspect_mcp(
        stdio_target(tmp_path, mode),
        run_dir=tmp_path / "runs",
        execution_plan={"read_account": {"id": "synthetic"}},
    )
    receipt = read_receipt(root)
    events = [json.loads(line) for line in (tmp_path / "events").read_text().splitlines()]
    assert [event["method"] for event in events].count("tools/call") == 1
    assert receipt["status"] == ("complete" if mode == "valid" else "incomplete")
    assert receipt["security_assessment"] is False
    assert len(receipt["tool_calls"]) == 1


async def test_invalid_arguments_block_entire_plan_before_execution(tmp_path):
    root = await inspect_mcp(
        stdio_target(tmp_path), run_dir=tmp_path / "runs", execution_plan={"read_account": {"id": 123}}
    )
    assert read_receipt(root)["status"] == "incomplete"
    events = [json.loads(line) for line in (tmp_path / "events").read_text().splitlines()]
    assert not any(event["method"] == "tools/call" for event in events)


@pytest.mark.parametrize("framing", ["json", "sse"])
async def test_http_auth_and_modern_envelopes_over_actual_socket(tmp_path, framing):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            assert self.headers["Authorization"] == "Bearer synthetic-mcp-key"
            assert self.headers["MCP-Protocol-Version"] == "2026-07-28"
            assert self.headers["Mcp-Method"] == request["method"]
            assert self.headers.get("Mcp-Session-Id") is None
            requests.append(request)
            body = json.dumps(fixture_response(request)).encode()
            if framing == "sse":
                body = b"event: message\ndata: " + body + b"\n\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream" if framing == "sse" else "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        root = await inspect_mcp(
            MCPTarget(url=f"http://127.0.0.1:{server.server_port}/mcp", bearer_token="synthetic-mcp-key"),
            run_dir=tmp_path / "runs",
        )
        receipt = read_receipt(root)
        assert receipt["status"] == "complete", receipt
        assert receipt["cleanup"]["clean"] is True
        assert [request["method"] for request in requests] == ["server/discover", "tools/list"]
        assert "synthetic-mcp-key" not in json.dumps(receipt)
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def test_unsupported_revision_fails_before_any_transport():
    with pytest.raises(ValueError, match="unsupported MCP profile"):
        MCPTarget(url="http://127.0.0.1:1", protocol_version="2025-06-18")


async def test_cancellation_commits_partial_receipt_and_reaps_subprocess(tmp_path):
    import asyncio

    task = asyncio.create_task(inspect_mcp(stdio_target(tmp_path, "timeout"), run_dir=tmp_path / "runs"))
    try:
        for _ in range(100):
            if (tmp_path / "events").exists():
                break
            await asyncio.sleep(0.01)
        assert (tmp_path / "events").exists()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        root = next((tmp_path / "runs").glob("mcp-*"))
        assert read_receipt(root)["status"] == "incomplete"
        assert read_receipt(root)["cleanup"]["reaped"] is True
        assert json.loads((root / "manifest.json").read_text())["state"] == "committed"
        with pytest.raises(ProcessLookupError):
            os.kill(int((tmp_path / "pid").read_text()), 0)
    finally:
        task.cancel()


async def test_http_auth_failure_retains_status_and_closes_client(tmp_path):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(401)
            body = b'{"error":"unauthorized"}'
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        root = await inspect_mcp(
            MCPTarget(url=f"http://127.0.0.1:{server.server_port}/mcp", bearer_token="wrong-synthetic"),
            run_dir=tmp_path / "runs",
        )
        receipt = read_receipt(root)
        assert receipt["status"] == "incomplete"
        assert receipt["cleanup"]["http_client_closed"] is True
        transcript = json.loads((root / "transcript.json").read_text())
        assert any(item.get("status_code") == 401 for item in transcript)
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


async def test_self_redirect_is_not_retried_with_credentials(tmp_path):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            requests.append(self.rfile.read(int(self.headers["Content-Length"])))
            self.send_response(307)
            self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/mcp")
            self.send_header("Content-Length", "0")
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        root = await inspect_mcp(
            MCPTarget(url=f"http://127.0.0.1:{server.server_port}/mcp", bearer_token="synthetic-redirect"),
            run_dir=tmp_path / "runs",
            timeout=1,
        )
        assert read_receipt(root)["status"] == "incomplete"
        assert len(requests) == 1
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


async def test_execution_order_survives_sorted_json_receipt_serialization(tmp_path):
    from neuralstrike.evaluation.mcp_receipt import load_mcp_inspection

    root = await inspect_mcp(
        stdio_target(tmp_path, "two-tools"),
        run_dir=tmp_path / "runs",
        execution_plan={"read_status": {"id": "first"}, "read_account": {"id": "second"}},
    )
    assert load_mcp_inspection(root)["status"] == "complete"
    receipt = read_receipt(root)
    assert [call["tool"] for call in receipt["tool_calls"]] == ["read_status", "read_account"]


async def test_unbounded_schema_construct_is_unsupported_before_execution(tmp_path):
    root = await inspect_mcp(
        stdio_target(tmp_path, "unsafe-schema"),
        run_dir=tmp_path / "runs",
        execution_plan={"read_account": {"id": "synthetic"}},
    )
    receipt = read_receipt(root)
    assert receipt["status"] == "incomplete"
    assert receipt["error"]["stage"] == "plan-validation"
    assert receipt["tool_calls"] == []


async def test_official_sdk_server_interoperates_over_real_stdio(tmp_path):
    root = await inspect_mcp(
        MCPTarget(command=sys.executable, args=(str(Path("examples/mcp_profile/server.py").resolve()),)),
        run_dir=tmp_path / "runs",
        execution_plan={"read_account": {"id": "synthetic"}},
    )
    receipt = read_receipt(root)
    assert receipt["status"] == "complete", receipt
    assert receipt["server_info"]["version"] == "1.0.0"
    assert receipt["cleanup"]["reaped"] is True
    assert receipt["tool_calls"][0]["status"] == "complete"


async def test_request_budget_cannot_turn_omitted_inventory_into_complete_discovery(tmp_path):
    root = await inspect_mcp(stdio_target(tmp_path), run_dir=tmp_path / "runs", max_requests=1)
    receipt = read_receipt(root)
    assert receipt["status"] == "incomplete"
    assert receipt["error"]["stage"] == "inventory"
    assert receipt["runtime"]["requests_admitted"] == 1
    events = [json.loads(line) for line in (tmp_path / "events").read_text().splitlines()]
    assert [event["method"] for event in events] == ["server/discover"]


async def test_descendant_is_terminated_even_if_main_stdio_server_exits_cleanly(tmp_path):
    import asyncio
    import signal

    target = stdio_target(tmp_path, "child")
    target.env["FIXTURE_CHILD_PID"] = str(tmp_path / "child-pid")
    child = None
    try:
        root = await inspect_mcp(target, run_dir=tmp_path / "runs")
        child = int((tmp_path / "child-pid").read_text())
        gone = False
        for _ in range(100):
            try:
                os.kill(child, 0)
            except ProcessLookupError:
                gone = True
                break
            await asyncio.sleep(0.01)
        assert gone
        assert read_receipt(root)["cleanup"]["descendant_cleanup_requested"] is True
        assert read_receipt(root)["status"] == "incomplete"
    finally:
        if child is not None:
            with suppress(ProcessLookupError):
                os.kill(child, signal.SIGKILL)


async def test_official_sdk_server_interoperates_over_authenticated_http(tmp_path, monkeypatch):
    import asyncio
    import socket

    import uvicorn
    from examples.mcp_profile.server import http_app

    monkeypatch.setenv("MCP_FIXTURE_BEARER", "synthetic-official-sdk")
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen()
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(http_app(), log_level="critical", lifespan="on", ws="none"))
    worker = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    worker.start()
    try:
        for _ in range(100):
            if server.started:
                break
            await asyncio.sleep(0.02)
        assert server.started
        root = await inspect_mcp(
            MCPTarget(url=f"http://127.0.0.1:{port}/mcp", bearer_token="synthetic-official-sdk"),
            run_dir=tmp_path / "runs",
            execution_plan={"read_account": {"id": "synthetic"}},
        )
        receipt = read_receipt(root)
        assert receipt["status"] == "complete", receipt
        assert receipt["server_info"]["version"] == "1.0.0"
        assert receipt["tool_calls"][0]["status"] == "complete"
        assert receipt["runtime"]["requests_admitted"] == 3
        assert receipt["runtime"]["cost_usd"] is None
    finally:
        server.should_exit = True
        worker.join(timeout=5)
        sock.close()
        assert not worker.is_alive()


async def test_whole_plan_is_validated_before_any_tool_dispatch(tmp_path):
    root = await inspect_mcp(
        stdio_target(tmp_path),
        run_dir=tmp_path / "runs",
        execution_plan={"read_account": {"id": "allowed-prefix"}, "unadvertised": {}},
    )
    receipt = read_receipt(root)
    assert receipt["status"] == "incomplete"
    assert receipt["error"]["stage"] == "plan-validation"
    assert receipt["tool_calls"] == []


async def test_sdk_filtered_descriptor_cannot_be_presented_as_complete_inventory(tmp_path):
    root = await inspect_mcp(stdio_target(tmp_path, "invalid-header"), run_dir=tmp_path / "runs")
    receipt = read_receipt(root)
    assert receipt["status"] == "incomplete"
    assert receipt["raw_tool_names"] == ["read_account"]
    assert receipt["tool_names"] == []


async def test_target_controlled_sdk_diagnostics_stay_out_of_default_logs(tmp_path, caplog):
    import logging

    target = stdio_target(tmp_path, "private-descriptor")
    target.env["SELECTED_PRIVATE_VALUE"] = "private-fixture-value-ZXQ"
    root = await inspect_mcp(target, run_dir=tmp_path / "runs")
    assert read_receipt(root)["status"] == "incomplete"
    assert "private-fixture-value-ZXQ" not in caplog.text
    # Private original evidence remains exact; only opaque SDK logging is suppressed.
    assert "private-fixture-value-ZXQ" in (root / "transcript.json").read_text()
    logging.getLogger("mcp.client.session").warning("ordinary-outside-profile-diagnostic")
    assert "ordinary-outside-profile-diagnostic" in caplog.text
