"""Runtime controls must constrain dispatched requests, not just CLI metadata."""

import json
from types import SimpleNamespace

import httpx
import pytest

from neuralstrike.adapters.openai_endpoint import OpenAIEndpointAdapter
from neuralstrike.runtime.limits import RateLimiter


async def test_rate_limiter_does_not_credit_sleep_twice(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr("neuralstrike.runtime.limits.time", SimpleNamespace(monotonic=lambda: clock[0]))

    async def sleep(delay):
        clock[0] += delay

    monkeypatch.setattr("neuralstrike.runtime.limits.asyncio.sleep", sleep)
    limiter = RateLimiter(max_calls=1, per_seconds=10)
    arrivals = []
    for _ in range(3):
        await limiter.acquire()
        arrivals.append(clock[0])
    assert arrivals == [0, 10, 20]


async def test_shared_request_cap_stops_tool_continuation_without_retry():
    from neuralstrike.runtime.outbound import OutboundPolicy

    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": "",
                            "tool_calls": [
                                {
                                    "id": "one",
                                    "type": "function",
                                    "function": {"name": "lookup", "arguments": "{}"},
                                }
                            ],
                        }
                    }
                ]
            },
        )

    policy = OutboundPolicy(max_requests=1)
    adapter = OpenAIEndpointAdapter(
        "http://local", model="fixture", outbound=policy, transport=httpx.MockTransport(handler)
    )
    try:
        response = await adapter.query("task")
        assert response.error == "outbound request limit exhausted (1)"
        assert len(calls) == 1
        assert [call.name for call in response.tool_calls] == ["lookup"]
        assert response.exchanges[0]["runtime"]["token_usage_source"] == "estimated"
        assert response.exchanges[0]["runtime"]["cost_usd"] is None
        assert response.exchanges[1]["error_type"] == "RequestLimitExceeded"
    finally:
        await adapter.close()


async def test_token_threshold_stops_before_tool_execution_and_preserves_body():
    from neuralstrike.oracles.tool_harness import TraceLog, make_canary_tools
    from neuralstrike.runtime.outbound import OutboundPolicy

    canaries = make_canary_tools()
    body = {
        "usage": {"total_tokens": 101},
        "choices": [
            {
                "message": {
                    "content": "",
                    "tool_calls": [
                        {
                            "id": "one",
                            "type": "function",
                            "function": {"name": canaries[0].name, "arguments": "{}"},
                        }
                    ],
                }
            }
        ],
    }
    adapter = OpenAIEndpointAdapter(
        "http://local",
        model="fixture",
        tier="instrumented",
        outbound=OutboundPolicy(max_total_tokens=100),
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json=body)),
    )
    trace = TraceLog()
    try:
        response = await adapter.query("task", canary_tools=canaries, trace=trace)
        assert response.error and "token budget exceeded" in response.error
        assert trace.to_list() == []
        assert response.exchanges[0]["response"] == body
        assert response.exchanges[0]["runtime"]["token_usage_source"] == "provider-reported"
        assert response.exchanges[0]["runtime"]["tokens"] == 101
        assert "absolute" in json.dumps(response.exchanges[0]["runtime"])
    finally:
        await adapter.close()


async def test_concurrency_is_shared_across_distinct_adapters_and_cancellation_releases_slot():
    import asyncio

    from neuralstrike.runtime.outbound import OutboundPolicy

    policy = OutboundPolicy(max_concurrent_requests=1)
    entered = asyncio.Event()
    release = asyncio.Event()
    calls = []

    async def handler(request):
        calls.append(request)
        entered.set()
        await release.wait()
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    adapters = [
        OpenAIEndpointAdapter(
            "http://local", model="fixture", outbound=policy, transport=httpx.MockTransport(handler)
        )
        for _ in range(2)
    ]
    tasks = [asyncio.create_task(adapters[0].query("first"))]
    try:
        await asyncio.wait_for(entered.wait(), 1)
        tasks.append(asyncio.create_task(adapters[1].query("second")))
        await asyncio.sleep(0)
        assert len(calls) == 1
        tasks[1].cancel()
        with pytest.raises(asyncio.CancelledError):
            await tasks[1]
        release.set()
        assert (await tasks[0]).error is None
        assert policy.summary()["concurrency"] == {"max": 1, "active": 0, "peak": 1}
        assert (await adapters[1].query("third")).error is None
        assert len(calls) == 2
    finally:
        release.set()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for adapter in adapters:
            await adapter.close()


async def test_failed_request_with_unknown_tokens_blocks_budgeted_followup():
    from neuralstrike.runtime.outbound import OutboundPolicy

    calls = []

    def handler(request):
        calls.append(request)
        raise httpx.ReadTimeout("synthetic", request=request)

    adapter = OpenAIEndpointAdapter(
        "http://local",
        model="fixture",
        outbound=OutboundPolicy(max_total_tokens=1000),
        transport=httpx.MockTransport(handler),
    )
    try:
        assert (await adapter.query("first")).error
        second = await adapter.query("second")
        assert second.error == "token budget cannot continue after an unmeasured request"
        assert len(calls) == 1
    finally:
        await adapter.close()


def test_cli_request_budget_is_not_silently_ignored_for_graphs(tmp_path):
    from typer.testing import CliRunner

    from neuralstrike.main import app

    result = CliRunner().invoke(app, ["corpus", "--max-requests", "1", "--run-dir", str(tmp_path / "runs")])
    assert result.exit_code != 0
    assert "outbound limits currently require" in result.output
    from click import unstyle

    assert "--adapter openai" in unstyle(result.output)
    assert not (tmp_path / "runs").exists()


def test_cli_policy_is_shared_across_scenarios_and_frozen_in_plan(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from neuralstrike.main import app

    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": "fixture"}}]})

    def fixture_client(adapter):
        if adapter._client is None:
            adapter._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        return adapter._client

    monkeypatch.setattr(OpenAIEndpointAdapter, "client", property(fixture_client))
    result = CliRunner().invoke(
        app,
        [
            "corpus",
            "--adapter",
            "openai",
            "--url",
            "http://local",
            "--model",
            "fixture",
            "--limit",
            "2",
            "--max-requests",
            "1",
            "--fail-on",
            "vuln",
            "--format",
            "json",
            "--run-dir",
            str(tmp_path / "runs"),
            "--out",
            str(tmp_path / "report"),
        ],
    )
    assert result.exit_code == 3, result.output
    assert len(calls) == 1
    plan = json.loads(next((tmp_path / "runs").glob("assessment-*/plan.json")).read_text())
    assert plan["declared_scope"]["outbound_limits"]["max_requests"] == 1
    trials = [json.loads(file.read_text()) for file in (tmp_path / "runs").glob("run-*/trial-0.json")]
    assert len(trials) == 2
    blocked = [trial for trial in trials if "limit exhausted" in (trial["response_error"] or "")]
    assert len(blocked) == 1
    assert blocked[0]["exchanges"][0]["request_status"] == "planned"
    assert blocked[0]["exchanges"][0]["error_type"] == "RequestLimitExceeded"


async def test_exhausted_request_cap_does_not_wait_for_a_rate_token():
    from unittest.mock import AsyncMock

    from neuralstrike.runtime.outbound import OutboundPolicy, RequestLimitExceeded

    policy = OutboundPolicy(max_requests=1)
    async with policy.request() as receipt:
        policy.account(receipt, {}, {"usage": {"total_tokens": 1}})
    policy.rate = SimpleNamespace(acquire=AsyncMock(side_effect=AssertionError("must fail before rate wait")))
    with pytest.raises(RequestLimitExceeded, match="limit exhausted"):
        async with policy.request():
            raise AssertionError("must not dispatch")


@pytest.mark.parametrize(
    "usage", [None, {"total_tokens": -1}, {"total_tokens": True}, {"total_tokens": "12"}]
)
async def test_missing_or_malformed_usage_is_labeled_estimated(usage):
    from neuralstrike.runtime.outbound import OutboundPolicy

    policy = OutboundPolicy(max_requests=1)
    async with policy.request() as receipt:
        policy.account(receipt, {"messages": []}, {"usage": usage})
    assert receipt["token_usage_source"] == "estimated"
    assert receipt["tokens"] > 0
    assert receipt["cost_usd"] is None
    assert receipt["policy"]["concurrency"]["active"] == 0


def test_runtime_identity_binds_limits_but_not_mutable_usage_counters():
    from neuralstrike.evaluation.identity import comparison_identity
    from neuralstrike.runtime.outbound import OutboundPolicy

    policy = OutboundPolicy(max_requests=2)
    adapter = OpenAIEndpointAdapter("http://local", model="fixture", outbound=policy)
    before = comparison_identity(adapter, {}, [], [])
    policy.dispatched = 1
    policy.budget.add_usage(tokens=100)
    assert comparison_identity(adapter, {}, [], []) == before
    other = OpenAIEndpointAdapter("http://local", model="fixture", outbound=OutboundPolicy(max_requests=3))
    assert comparison_identity(other, {}, [], []) != before


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_requests": 0},
        {"max_requests": True},
        {"max_total_tokens": -1},
        {"requests_per_minute": float("nan")},
        {"requests_per_minute": float("inf")},
        {"max_concurrent_requests": 0},
    ],
)
def test_invalid_runtime_limits_fail_before_waiting(kwargs):
    from neuralstrike.runtime.outbound import OutboundPolicy

    with pytest.raises(ValueError):
        OutboundPolicy(**kwargs)
