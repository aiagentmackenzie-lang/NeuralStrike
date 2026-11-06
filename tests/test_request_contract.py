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
