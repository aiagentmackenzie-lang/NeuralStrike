"""Wire-level request checks against a strict stdlib HTTP fixture, without inference."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from neuralstrike.adapters.base import TargetAdapter
from neuralstrike.adapters.openai_endpoint import OpenAIEndpointAdapter
from neuralstrike.attacks.indirect import IndirectHarness
from neuralstrike.corpus import load_corpus_dir
from neuralstrike.oracles.tool_harness import make_canary_tools


def request_error(payload):
    names = [t["function"]["name"] for t in payload.get("tools", [])]
    if len(set(names)) != len(names):
        return "duplicate tool names"
    pending = {}
    for message in payload["messages"]:
        if message["role"] == "tool":
            call_id = message.get("tool_call_id")
            if call_id not in pending or message.get("name") != pending.pop(call_id):
                return "orphan or mismatched tool result"
        else:
            if pending:
                return "missing tool result"
            for call in message.get("tool_calls", []):
                pending[call["id"]] = call["function"]["name"]
    return "missing final tool result" if pending else None


@pytest.fixture
def strict_endpoint():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            error = request_error(payload)
            body = json.dumps(
                {"error": error}
                if error
                else {"model": "stdlib-fixture-v1", "choices": [{"message": {"content": "completed"}}]}
            ).encode()
            self.send_response(400 if error else 200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.asyncio
async def test_all_corpus_histories_accepted_over_real_http(strict_endpoint):
    adapter = OpenAIEndpointAdapter(strict_endpoint, model="fixture", seed=123)
    canaries = make_canary_tools()
    try:
        for scenario in load_corpus_dir():
            inputs = IndirectHarness(scenario).build_inputs("CANARY-SYNTHETIC")
            response = await adapter.query(
                inputs.prompt,
                system_prompt=inputs.system_prompt,
                history=inputs.history,
                canary_tools=canaries,
                tools=TargetAdapter.canary_tools_as_schemas(canaries),
            )
            assert response.error is None, (scenario.id, response.error)
            assert response.exchanges[0]["status_code"] == 200
    finally:
        await adapter.close()


@pytest.mark.asyncio
async def test_strict_server_rejects_duplicate_and_orphan_requests(strict_endpoint):
    async with httpx.AsyncClient() as client:
        for payload in [
            {"messages": [], "tools": [{"function": {"name": "same"}}] * 2},
            {"messages": [{"role": "tool", "tool_call_id": "missing"}]},
        ]:
            response = await client.post(f"{strict_endpoint}/v1/chat/completions", json=payload)
            assert response.status_code == 400
