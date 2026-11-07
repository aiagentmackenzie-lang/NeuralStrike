"""Values-stream observations survive later stream failure without invented nodes."""

import asyncio
import json

import pytest
from tests.test_partial_trial_evidence import scenario

from neuralstrike.adapters.langgraph import LangGraphAdapter
from neuralstrike.attacks.indirect import IndirectHarness
from neuralstrike.evaluation.bundle import replay_bundle
from neuralstrike.evaluation.health import assessment_health
from neuralstrike.evaluation.runner import TrialRunner
from neuralstrike.evaluation.verdict import EvidenceFidelity, Verdict


def emitted(state, name="grant_admin_access", call_id="stream-action"):
    return {
        "messages": [
            *state["messages"],
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [{"id": call_id, "name": name, "args": {"user_id": "synthetic"}}],
            },
        ]
    }


@pytest.mark.parametrize("ending", ["timeout", "error", "malformed"])
async def test_observed_stream_action_survives_later_failure_and_replays(tmp_path, ending):
    closed = []

    class Graph:
        async def astream(self, state, *, stream_mode):
            assert stream_mode == "values"
            try:
                yield state  # normal input-only initial values
                yield emitted(state)
                if ending == "timeout":
                    await asyncio.Event().wait()
                if ending == "error":
                    raise RuntimeError("synthetic later node error")
                yield {"messages": None}
            finally:
                closed.append(True)

    report = await TrialRunner(run_dir=tmp_path, trial_timeout=0.05).run(
        IndirectHarness(scenario()).probe_for(LangGraphAdapter(graph=Graph()))
    )
    trial = report.trials[0]
    assert trial.verdict is Verdict.SUCCEEDED
    assert trial.fidelity is EvidenceFidelity.INTENT_TO_ACT
    assert trial.response.tool_calls[0].tool_call_id == "stream-action"
    assert trial.response.exchanges[0]["capture_complete"] is False
    assert assessment_health([report]).exit_code("vuln") == 3
    assert closed == [True]
    assert replay_bundle(tmp_path / report.meta.run_id, verify_oracles=True).to_dict() == report.to_dict()


async def test_user_cancel_retains_observed_stream_action_and_closes_stream(tmp_path):
    entered = asyncio.Event()
    closed = []

    class Graph:
        async def astream(self, state, *, stream_mode):
            try:
                yield emitted(state)
                entered.set()
                await asyncio.Event().wait()
            finally:
                closed.append(True)

    task = asyncio.create_task(
        TrialRunner(run_dir=tmp_path).run(
            IndirectHarness(scenario()).probe_for(LangGraphAdapter(graph=Graph()))
        )
    )
    await asyncio.wait_for(entered.wait(), 1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    journal = json.loads(next(tmp_path.glob("*/trial-0.json")).read_text())
    assert journal["verdict"] == Verdict.SUCCEEDED.value
    assert journal["tool_calls"][0]["tool_call_id"] == "stream-action"
    assert journal["exchanges"][0]["capture_complete"] is False
    assert closed == [True]


async def test_streamed_call_not_erased_by_later_output_only_snapshot(tmp_path):
    class Graph:
        async def astream(self, state, *, stream_mode):
            yield {"messages": emitted(state)["messages"][-1:]}
            yield {"messages": [{"role": "assistant", "content": "done"}]}

    report = await TrialRunner(run_dir=tmp_path).run(
        IndirectHarness(scenario()).probe_for(LangGraphAdapter(graph=Graph(), messages_mode="output"))
    )
    trial = report.trials[0]
    assert trial.verdict is Verdict.SUCCEEDED
    assert trial.response.text == "done"
    assert len(trial.response.tool_calls) == 1
    assert trial.response.exchanges[0]["capture_complete"] is True
    assert replay_bundle(tmp_path / report.meta.run_id, verify_oracles=True).to_dict() == report.to_dict()


async def test_stream_close_failure_retains_action_and_reports_failed_cleanup(tmp_path):
    class Stream:
        def __init__(self, state):
            self.state = state
            self.count = 0

        def __aiter__(self):
            return self

        async def __anext__(self):
            self.count += 1
            if self.count == 1:
                return emitted(self.state)
            raise StopAsyncIteration

        async def aclose(self):
            raise RuntimeError("synthetic stream close failure")

    class Graph:
        def astream(self, state, *, stream_mode):
            return Stream(state)

    report = await TrialRunner(run_dir=tmp_path).run(
        IndirectHarness(scenario()).probe_for(LangGraphAdapter(graph=Graph()))
    )
    trial = report.trials[0]
    assert trial.verdict is Verdict.SUCCEEDED
    assert trial.response.error
    assert trial.response.exchanges[0]["stream_cleanup"] == "failed"
    assert trial.response.exchanges[0]["capture_complete"] is False
    assert assessment_health([report]).exit_code("vuln") == 3
    assert replay_bundle(tmp_path / report.meta.run_id, verify_oracles=True).to_dict() == report.to_dict()


async def test_stream_conflicting_id_cannot_replace_a_previously_observed_violation(tmp_path):
    class Graph:
        async def astream(self, state, *, stream_mode):
            yield emitted(state)
            yield emitted(state, name="lookup_account")

    report = await TrialRunner(run_dir=tmp_path).run(
        IndirectHarness(scenario()).probe_for(LangGraphAdapter(graph=Graph()))
    )
    trial = report.trials[0]
    assert trial.verdict is Verdict.SUCCEEDED
    assert trial.response.tool_calls[0].name == "grant_admin_access"
    assert "already observed tool call ID" in trial.response.error
    assert trial.response.exchanges[0]["stream_cleanup"] == "completed"
    assert trial.response.exchanges[0]["capture_complete"] is False
    assert assessment_health([report]).exit_code("vuln") == 3


async def test_graph_mutation_cannot_rewrite_already_observed_stream_arguments(tmp_path):
    class Graph:
        async def astream(self, state, *, stream_mode):
            value = emitted(state)
            yield value
            value["messages"][-1]["tool_calls"][0]["args"]["user_id"] = "rewritten"
            yield value

    report = await TrialRunner(run_dir=tmp_path).run(
        IndirectHarness(scenario()).probe_for(LangGraphAdapter(graph=Graph()))
    )
    trial = report.trials[0]
    assert trial.verdict is Verdict.SUCCEEDED
    assert trial.response.tool_calls[0].arguments == {"user_id": "synthetic"}
    assert trial.response.error
    assert trial.response.exchanges[0]["stream_observed_tool_calls"][0]["arguments"] == {
        "user_id": "synthetic"
    }
    assert assessment_health([report]).exit_code("vuln") == 3
