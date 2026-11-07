"""NS-04 strict request contract for supported corpus history shapes."""

import json

import httpx
import pytest

from neuralstrike.adapters.base import TargetAdapter
from neuralstrike.adapters.openai_endpoint import OpenAIEndpointAdapter
from neuralstrike.attacks.indirect import IndirectHarness
from neuralstrike.corpus import load_corpus_dir
from neuralstrike.oracles.tool_harness import make_canary_tools


def validate_request(payload):
    names = [t["function"]["name"] for t in payload.get("tools", [])]
    assert len(names) == len(set(names)), "duplicate tool definitions"
    pending = set()
    for message in payload["messages"]:
        if message["role"] == "tool":
            assert message["tool_call_id"] in pending, "orphan tool message"
            pending.remove(message["tool_call_id"])
        else:
            assert not pending, "missing tool result"
            pending.update(call["id"] for call in message.get("tool_calls", []))
    assert not pending


@pytest.mark.parametrize("scenario", load_corpus_dir(), ids=lambda s: s.id)
@pytest.mark.asyncio
async def test_corpus_requests_accepted_by_strict_transport(scenario):
    def handler(request):
        validate_request(json.loads(request.content))
        return httpx.Response(200, json={"choices": [{"message": {"content": "fixture response"}}]})

    adapter = OpenAIEndpointAdapter("http://fixture", model="fixture", transport=httpx.MockTransport(handler))
    inputs = IndirectHarness(scenario).build_inputs("SYNTHETIC_CANARY")
    canaries = make_canary_tools()
    try:
        await adapter.query(
            inputs.prompt,
            system_prompt=inputs.system_prompt,
            history=inputs.history,
            tools=TargetAdapter.canary_tools_as_schemas(canaries),
            canary_tools=canaries,
        )
    finally:
        await adapter.close()


@pytest.mark.parametrize(
    "payload",
    [
        {"tools": [{"function": {"name": "x"}}] * 2, "messages": []},
        {"messages": [{"role": "tool", "tool_call_id": "missing"}]},
    ],
)
def test_strict_fixture_rejects_malformed_requests(payload):
    with pytest.raises(AssertionError):
        validate_request(payload)


@pytest.mark.asyncio
async def test_all_supported_histories_over_strict_loopback_http():
    """Exercise actual HTTP serialization, including malformed negative controls."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    accepted = []
    rejected = []

    class StrictHandler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            try:
                validate_request(payload)
            except AssertionError:
                rejected.append(payload)
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"invalid tool history")
                return
            accepted.append(payload)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"choices": [{"message": {"content": "fixture"}}]}).encode())

    server = ThreadingHTTPServer(("127.0.0.1", 0), StrictHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}"
    adapter = OpenAIEndpointAdapter(url, model="synthetic")
    scenarios = load_corpus_dir()
    try:
        for scenario in scenarios:
            inputs = IndirectHarness(scenario).build_inputs("SYNTHETIC_CANARY")
            canaries = make_canary_tools()
            response = await adapter.query(
                inputs.prompt,
                system_prompt=inputs.system_prompt,
                history=inputs.history,
                tools=TargetAdapter.canary_tools_as_schemas(canaries),
                canary_tools=canaries,
            )
            assert response.error is None, scenario.id
        async with httpx.AsyncClient(trust_env=False) as client:
            for malformed in [
                {"tools": [{"function": {"name": "duplicate"}}] * 2, "messages": []},
                {"messages": [{"role": "tool", "tool_call_id": "orphan"}]},
            ]:
                response = await client.post(url, json=malformed)
                assert response.status_code == 400
        assert len(accepted) == len(scenarios)
        assert len(rejected) == 2
    finally:
        await adapter.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
