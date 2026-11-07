"""An unreapable process must be reported, never hidden by an unbounded close."""

import asyncio

import pytest

from neuralstrike.adapters.mcp_transport import MCPTransportError, _stop_process


async def test_unreaped_process_does_not_enter_unbounded_resource_close(monkeypatch):
    class Process:
        stdin = None
        returncode = None
        pid = 99999999

        async def wait(self):
            await asyncio.Event().wait()

        async def aclose(self):
            await asyncio.Event().wait()

    monkeypatch.setattr("neuralstrike.adapters.mcp_transport.os.killpg", lambda pid, sig: None)
    cleanup = {}
    with pytest.raises(MCPTransportError, match="did not exit"):
        await asyncio.wait_for(_stop_process(Process(), cleanup), timeout=2)
    assert cleanup["reaped"] is False
    assert cleanup["clean"] is False


async def test_exit_between_timeout_and_signal_is_reaped_without_false_cleanup_error(monkeypatch):
    class Process:
        stdin = None
        returncode = None
        pid = 99999999
        waits = 0

        async def wait(self):
            self.waits += 1
            if self.waits == 1:
                await asyncio.Event().wait()
            self.returncode = 0
            return 0

        async def aclose(self):
            pass

    def already_exited(pid, sig):
        raise ProcessLookupError

    monkeypatch.setattr("neuralstrike.adapters.mcp_transport.os.killpg", already_exited)
    cleanup = {}
    await _stop_process(Process(), cleanup)
    assert cleanup["reaped"] is True
    assert cleanup["clean"] is True


async def test_stdin_close_failure_still_reaps_and_records_unclean_shutdown(monkeypatch):
    class Stdin:
        async def aclose(self):
            raise OSError("synthetic pipe failure")

    class Process:
        stdin = Stdin()
        returncode = None
        pid = 99999999

        async def wait(self):
            self.returncode = 0
            return 0

        async def aclose(self):
            pass

    def gone(pid, sig):
        raise ProcessLookupError

    monkeypatch.setattr("neuralstrike.adapters.mcp_transport.os.killpg", gone)
    cleanup = {}
    await _stop_process(Process(), cleanup)
    assert cleanup["reaped"] is True
    assert cleanup["clean"] is False
    assert cleanup["stdin_close_error_type"] == "OSError"


async def test_http_resource_close_failure_is_not_reported_clean(tmp_path, monkeypatch):
    import json
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from tests.fixtures.mcp_modern_stdio import response

    from neuralstrike.adapters.mcp_protocol import MCPTarget, inspect_mcp
    from neuralstrike.adapters.mcp_transport import BoundedHTTPTransport

    original_close = BoundedHTTPTransport.aclose

    async def failed_close(self):
        await original_close(self)
        raise OSError("synthetic resource close failure")

    monkeypatch.setattr(BoundedHTTPTransport, "aclose", failed_close)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            body = json.dumps(response(request)).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        root = await inspect_mcp(
            MCPTarget(url=f"http://127.0.0.1:{server.server_port}/mcp"), run_dir=tmp_path / "runs"
        )
        receipt = json.loads((root / "receipt.json").read_text())
        assert receipt["status"] == "incomplete"
        assert receipt["cleanup"]["clean"] is False
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
