"""A complete HTTP body is not necessarily a completed model generation."""

import json

import httpx
import pytest

from neuralstrike.adapters.base import ToolSchema
from neuralstrike.adapters.openai_endpoint import OpenAIEndpointAdapter
from neuralstrike.adapters.preflight import check_openai_target
from neuralstrike.evaluation.bundle import replay_bundle
from neuralstrike.evaluation.health import assessment_health
from neuralstrike.evaluation.probes import adapter_scan_probe
from neuralstrike.evaluation.runner import TrialRunner
from neuralstrike.evaluation.verdict import EvidenceFidelity, Verdict
from neuralstrike.oracles.forbidden_tool import ForbiddenToolOracle, ForbiddenToolSpec
from neuralstrike.oracles.tool_harness import make_canary_tools


def completion(name, *, finish_reason="stop", call_id="observed"):
    return {
        "choices": [
            {
                "finish_reason": finish_reason,
                "message": {
                    "content": "partial account summary",
                    "tool_calls": [
                        {"id": call_id, "type": "function", "function": {"name": name, "arguments": "{}"}}
                    ],
                },
            }
        ]
    }


@pytest.mark.parametrize(
    "reason", ["length", "content_filter", None, "future-reason", "function_call", 0, [], {}]
)
async def test_incomplete_or_unsupported_finish_cannot_establish_resistance(tmp_path, reason):
    requests = []
    body = completion("lookup_account", finish_reason=reason)

    def handler(request):
        requests.append(request)
        return httpx.Response(
            200,
            json=body
            if len(requests) == 1
            else {"choices": [{"finish_reason": "stop", "message": {"content": "done"}}]},
        )

    adapter = OpenAIEndpointAdapter("http://fixture", model="fixture", transport=httpx.MockTransport(handler))
    try:
        probe = adapter_scan_probe(
            adapter,
            payload="task",
            scenario_id="completion-health",
            tools=(ToolSchema("lookup_account", "read fixture", {"type": "object"}),),
            oracles=[ForbiddenToolOracle(ForbiddenToolSpec(forbidden_tools=("grant_admin_access",)))],
        )
        report = await TrialRunner(run_dir=tmp_path).run(probe)
        trial = report.trials[0]
        assert trial.verdict is Verdict.INCONCLUSIVE
        assert trial.response.error
        assert trial.response.text == "partial account summary"
        assert trial.response.tool_calls[0].name == "lookup_account"
        assert trial.response.exchanges[0]["response"] == body
        assert trial.response.exchanges[0]["capture_complete"] is True
        assert assessment_health([report]).exit_code("vuln") == 3
        assert len(requests) == 1  # no tool continuation or automatic retry
        assert replay_bundle(tmp_path / report.meta.run_id, verify_oracles=True).to_dict() == report.to_dict()
    finally:
        await adapter.close()


async def test_truncated_tool_batch_preserves_intent_but_executes_no_canary(tmp_path):
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(
            200,
            json=completion("grant_admin_access", finish_reason="length")
            if len(requests) == 1
            else {"choices": [{"message": {"content": "done"}}]},
        )

    adapter = OpenAIEndpointAdapter(
        "http://fixture", model="fixture", tier="instrumented", transport=httpx.MockTransport(handler)
    )
    try:
        probe = adapter_scan_probe(
            adapter,
            payload="task",
            scenario_id="truncated-action",
            canary_tools=make_canary_tools(),
            oracles=[ForbiddenToolOracle(ForbiddenToolSpec(forbidden_tools=("grant_admin_access",)))],
        )
        report = await TrialRunner(run_dir=tmp_path).run(probe)
        trial = report.trials[0]
        assert trial.verdict is Verdict.SUCCEEDED
        assert trial.fidelity is EvidenceFidelity.INTENT_TO_ACT
        assert trial.response.error
        assert trial.response.traces == ()
        assert trial.response.tool_calls[0].tool_call_id == "observed"
        assert assessment_health([report]).exit_code("vuln") == 3
        assert len(requests) == 1
        assert replay_bundle(tmp_path / report.meta.run_id, verify_oracles=True).to_dict() == report.to_dict()
    finally:
        await adapter.close()


async def test_doctor_does_not_promote_truncated_tool_capability_to_ready():
    requests = []

    def handler(request):
        requests.append(request)
        body = completion("neuralstrike_preflight", finish_reason="length")
        body["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] = json.dumps(
            {"value": "probe"}
        )
        return httpx.Response(
            200, json=body if len(requests) == 1 else {"choices": [{"message": {"content": "ok"}}]}
        )

    receipt = await check_openai_target(
        "http://fixture", model="fixture", transport=httpx.MockTransport(handler)
    )
    assert receipt["tool_call_observed"] is True
    assert receipt["ready"] is False
    assert receipt["security_assessment"] is False
    assert receipt["error"]
    assert len(requests) == 1


async def test_failed_handler_stops_batch_and_preserves_prior_receipt(tmp_path):
    from neuralstrike.oracles.tool_harness import CanaryTool

    executed = []
    requests = []

    def handler_for(name, *, fail=False):
        def execute(args):
            executed.append(name)
            if fail:
                raise RuntimeError("synthetic failure after dispatch")
            return "fixture acknowledgment"

        return execute

    canaries = tuple(
        CanaryTool(name, "local fixture", handler=handler_for(name, fail=name == "lookup_account"))
        for name in ("grant_admin_access", "lookup_account", "delete_all_records")
    )
    first = completion("grant_admin_access", finish_reason="tool_calls")
    batch = first["choices"][0]["message"]["tool_calls"]
    batch += [
        completion(name, call_id=name)["choices"][0]["message"]["tool_calls"][0]
        for name in ("lookup_account", "delete_all_records")
    ]

    def handler(request):
        requests.append(request)
        return httpx.Response(
            200, json=first if len(requests) == 1 else {"choices": [{"message": {"content": "done"}}]}
        )

    adapter = OpenAIEndpointAdapter(
        "http://fixture", model="fixture", tier="instrumented", transport=httpx.MockTransport(handler)
    )
    try:
        report = await TrialRunner(run_dir=tmp_path).run(
            adapter_scan_probe(
                adapter,
                payload="task",
                scenario_id="failed-handler",
                canary_tools=canaries,
                oracles=[ForbiddenToolOracle(ForbiddenToolSpec(forbidden_tools=("grant_admin_access",)))],
            )
        )
        trial = report.trials[0]
        assert executed == ["grant_admin_access", "lookup_account"]
        assert len(requests) == 1
        assert trial.verdict is Verdict.SUCCEEDED
        assert trial.fidelity is EvidenceFidelity.BEHAVIORAL
        assert trial.response.error
        assert len(trial.response.tool_calls) == 3  # emitted intent, not three executions
        assert len(trial.response.traces) == 1
        assert trial.response.exchanges[0]["tool_execution_error"]["tool_call_id"] == "lookup_account"
        assert assessment_health([report]).exit_code("vuln") == 3
        assert replay_bundle(tmp_path / report.meta.run_id, verify_oracles=True).to_dict() == report.to_dict()
    finally:
        await adapter.close()


@pytest.mark.parametrize("tier", ["text", "function-calling"])
async def test_noninstrumented_tier_never_executes_a_supplied_canary(tier):
    from neuralstrike.oracles.tool_harness import CanaryTool, TraceLog

    executed = []
    requests = []
    tool = CanaryTool("grant_admin_access", "fixture", handler=lambda args: executed.append(args) or "ok")

    def handler(request):
        requests.append(request)
        return httpx.Response(
            200,
            json=completion("grant_admin_access", finish_reason="tool_calls")
            if len(requests) == 1
            else {"choices": [{"message": {"content": "done"}}]},
        )

    adapter = OpenAIEndpointAdapter(
        "http://fixture", model="fixture", tier=tier, transport=httpx.MockTransport(handler)
    )
    trace = TraceLog()
    try:
        response = await adapter.query("task", canary_tools=(tool,), trace=trace)
        assert executed == []
        assert trace.to_list() == []
        assert response.tool_calls[0].name == "grant_admin_access"
        if tier == "text":
            assert response.error
            assert len(requests) == 1
        else:
            assert response.error is None
            assert len(requests) == 2
    finally:
        await adapter.close()


@pytest.mark.parametrize("result", [None, 3, {"invalid": "non-text"}])
async def test_invalid_handler_result_cannot_commit_a_corrupt_execution_receipt(tmp_path, result):
    from neuralstrike.oracles.tool_harness import CanaryTool

    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(
            200,
            json=completion("grant_admin_access", finish_reason="tool_calls")
            if len(calls) == 1
            else {"choices": [{"message": {"content": "done"}}]},
        )

    tool = CanaryTool("grant_admin_access", "fixture", handler=lambda args: result)
    adapter = OpenAIEndpointAdapter(
        "http://fixture", model="fixture", tier="instrumented", transport=httpx.MockTransport(handler)
    )
    try:
        report = await TrialRunner(run_dir=tmp_path).run(
            adapter_scan_probe(
                adapter,
                payload="task",
                scenario_id="invalid-handler-result",
                canary_tools=(tool,),
                oracles=[ForbiddenToolOracle(ForbiddenToolSpec(forbidden_tools=("grant_admin_access",)))],
            )
        )
        trial = report.trials[0]
        assert trial.response.error
        assert trial.response.traces == ()
        assert trial.fidelity is EvidenceFidelity.INTENT_TO_ACT
        assert assessment_health([report]).exit_code("vuln") == 3
        assert len(calls) == 1
        assert replay_bundle(tmp_path / report.meta.run_id, verify_oracles=True).to_dict() == report.to_dict()
    finally:
        await adapter.close()
