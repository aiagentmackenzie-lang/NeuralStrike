"""Application state and invocation resources have explicit, fallible lifecycles."""

import asyncio
import json

import pytest
from tests.test_partial_trial_evidence import scenario

from neuralstrike.adapters.langgraph import LangGraphAdapter
from neuralstrike.attacks.indirect import IndirectHarness
from neuralstrike.evaluation.bundle import replay_bundle
from neuralstrike.evaluation.health import assessment_health
from neuralstrike.evaluation.runner import TrialRunner
from neuralstrike.evaluation.verdict import Verdict


async def test_real_checkpointer_uses_fresh_thread_and_deletes_owned_checkpoints():
    from langgraph.checkpoint.memory import InMemorySaver
    from langgraph.graph import END, START, MessagesState, StateGraph

    saver = InMemorySaver()
    seen = []

    async def reply(state):
        seen.append(len(state["messages"]))
        return {"messages": [{"role": "assistant", "content": "done"}]}

    builder = StateGraph(MessagesState)
    builder.add_node("reply", reply)
    builder.add_edge(START, "reply")
    builder.add_edge("reply", END)
    graph = builder.compile(checkpointer=saver)

    async def cleanup(graph, thread_id):
        await graph.checkpointer.adelete_thread(thread_id)

    adapter = LangGraphAdapter(graph=graph, thread_mode="isolated", cleanup=cleanup)
    responses = [await adapter.query("task"), await adapter.query("task")]
    assert all(r.error is None for r in responses)
    assert seen == [1, 1]
    ids = [r.exchanges[0]["lifecycle"]["thread_id"] for r in responses]
    assert ids[0] != ids[1]
    assert not saver.storage
    assert all(r.exchanges[0]["lifecycle"]["cleanup"] == "completed" for r in responses)


async def test_reset_failure_does_not_invoke_and_cleanup_is_attempted(tmp_path):
    events = []

    class Graph:
        async def ainvoke(self, state):
            events.append("invoke")
            raise AssertionError("reset failed")

    async def reset(graph, thread_id):
        events.append("reset")
        raise RuntimeError("synthetic reset failure")

    async def cleanup(graph, thread_id):
        events.append("cleanup")

    report = await TrialRunner(run_dir=tmp_path).run(
        IndirectHarness(scenario()).probe_for(LangGraphAdapter(graph=Graph(), reset=reset, cleanup=cleanup))
    )
    assert events == ["reset", "cleanup"]
    assert report.trials[0].verdict is Verdict.INCONCLUSIVE
    assert assessment_health([report]).exit_code("vuln") == 3
    lifecycle = report.trials[0].response.exchanges[0]["lifecycle"]
    assert lifecycle["reset"] == "failed"
    assert lifecycle["cleanup"] == "completed"


async def test_cleanup_failure_preserves_confirmed_action_and_replay(tmp_path):
    class Graph:
        async def ainvoke(self, state):
            return {
                "messages": [
                    *state["messages"],
                    {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {"id": "observed", "name": "grant_admin_access", "args": {"user_id": "synthetic"}}
                        ],
                    },
                ]
            }

    async def cleanup(graph, thread_id):
        raise RuntimeError("synthetic cleanup failure")

    report = await TrialRunner(run_dir=tmp_path).run(
        IndirectHarness(scenario()).probe_for(LangGraphAdapter(graph=Graph(), cleanup=cleanup))
    )
    trial = report.trials[0]
    assert trial.verdict is Verdict.SUCCEEDED
    assert trial.response.tool_calls[0].tool_call_id == "observed"
    assert "cleanup failed" in trial.response.error
    assert trial.response.exchanges[0]["lifecycle"]["cleanup"] == "failed"
    assert assessment_health([report]).exit_code("vuln") == 3
    assert replay_bundle(tmp_path / report.meta.run_id, verify_oracles=True).to_dict() == report.to_dict()


@pytest.mark.parametrize("ending", ["success", "exception", "timeout", "cancel"])
async def test_cleanup_runs_once_on_all_exit_paths_and_cancel_journal_retains_receipt(tmp_path, ending):
    started = asyncio.Event()
    events = []

    class Graph:
        async def ainvoke(self, state):
            started.set()
            if ending == "exception":
                raise RuntimeError("synthetic invocation error")
            if ending in {"timeout", "cancel"}:
                await asyncio.Event().wait()
            return {"messages": [*state["messages"], {"role": "assistant", "content": "done"}]}

    async def cleanup(graph, thread_id):
        await asyncio.sleep(0)
        events.append("cleanup")

    runner = TrialRunner(run_dir=tmp_path, trial_timeout=0.05 if ending == "timeout" else None)
    task = asyncio.create_task(
        runner.run(IndirectHarness(scenario()).probe_for(LangGraphAdapter(graph=Graph(), cleanup=cleanup)))
    )
    await asyncio.wait_for(started.wait(), 1)
    if ending == "cancel":
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        journal = json.loads(next(tmp_path.glob("*/trial-0.json")).read_text())
        assert journal["exchanges"][0]["lifecycle"]["cleanup"] == "completed"
        manifest = json.loads(next(tmp_path.glob("*/manifest.json")).read_text())
        assert manifest["state"] == "running"
    else:
        await task
    assert events == ["cleanup"]


async def test_cleanup_deadline_is_error_and_does_not_retry_action():
    calls = []

    class Graph:
        async def ainvoke(self, state):
            calls.append("action")
            return {"messages": [*state["messages"], {"role": "assistant", "content": "done"}]}

    async def cleanup(graph, thread_id):
        calls.append("cleanup")
        await asyncio.Event().wait()

    response = await LangGraphAdapter(graph=Graph(), cleanup=cleanup, cleanup_timeout=0.01).query("task")
    assert response.text == "done"
    assert response.error == "graph cleanup failed (TimeoutError)"
    assert response.exchanges[0]["lifecycle"]["cleanup"] == "failed"
    assert calls == ["action", "cleanup"]


async def test_reset_serializes_application_state_across_concurrent_queries():
    class Graph:
        counter = 99

        async def ainvoke(self, state):
            self.counter += 1
            await asyncio.sleep(0)
            return {"messages": [*state["messages"], {"role": "assistant", "content": str(self.counter)}]}

    async def reset(graph, thread_id):
        graph.counter = 0

    adapter = LangGraphAdapter(graph=Graph(), reset=reset)
    responses = await asyncio.gather(adapter.query("a"), adapter.query("b"))
    assert [r.text for r in responses] == ["1", "1"]
    assert all(r.exchanges[0]["lifecycle"]["reset"] == "completed" for r in responses)
    assert all("not attested" in r.exchanges[0]["lifecycle"]["reset_attestation"] for r in responses)


async def test_repeated_cancellation_waits_for_cleanup_and_retains_completed_action(tmp_path):
    entered = asyncio.Event()
    release = asyncio.Event()

    class Graph:
        async def ainvoke(self, state):
            return {
                "messages": [
                    *state["messages"],
                    {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [{"id": "before-cancel", "name": "grant_admin_access", "args": {}}],
                    },
                ]
            }

    async def cleanup(graph, thread_id):
        entered.set()
        await release.wait()

    task = asyncio.create_task(
        TrialRunner(run_dir=tmp_path).run(
            IndirectHarness(scenario()).probe_for(LangGraphAdapter(graph=Graph(), cleanup=cleanup))
        )
    )
    await asyncio.wait_for(entered.wait(), 1)
    task.cancel()
    await asyncio.sleep(0)
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    journal = json.loads(next(tmp_path.glob("*/trial-0.json")).read_text())
    assert journal["verdict"] == Verdict.SUCCEEDED.value
    assert journal["exchanges"][0]["lifecycle"]["cleanup"] == "completed"


def test_lifecycle_configuration_changes_comparison_identity():
    from neuralstrike.evaluation.identity import comparison_identity

    plain = comparison_identity(LangGraphAdapter(spec="fixture:graph"), {}, [], [])
    isolated = comparison_identity(LangGraphAdapter(spec="fixture:graph", thread_mode="isolated"), {}, [], [])
    assert plain["target_configuration_digest"] != isolated["target_configuration_digest"]

    async def reset(graph, thread_id):
        pass

    anonymous_hook = comparison_identity(LangGraphAdapter(spec="fixture:graph", reset=reset), {}, [], [])
    assert anonymous_hook["comparable"] is False


@pytest.mark.parametrize("command", ["scan", "corpus"])
def test_cli_lifecycle_hooks_preserve_cleanup_failures(tmp_path, monkeypatch, command):
    import sys
    from types import SimpleNamespace

    from typer.testing import CliRunner

    from neuralstrike.main import app

    events = []

    class Graph:
        async def ainvoke(self, state, config):
            events.append(("invoke", config["configurable"]["thread_id"]))
            return {
                "messages": [
                    *state["messages"],
                    {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [{"id": "cli-action", "name": "grant_admin_access", "args": {}}],
                    },
                ]
            }

    async def reset(graph, thread_id):
        events.append(("reset", thread_id))

    async def cleanup(graph, thread_id):
        events.append(("cleanup", thread_id))
        raise RuntimeError("synthetic close failure")

    monkeypatch.setitem(
        sys.modules, "lifecycle_fixture", SimpleNamespace(graph=Graph(), reset=reset, cleanup=cleanup)
    )
    args = [
        command,
        "--adapter",
        "langgraph",
        "--run-dir",
        str(tmp_path / "runs"),
        "--fail-on",
        "vuln",
        "--graph-thread-mode",
        "isolated",
        "--graph-reset",
        "lifecycle_fixture:reset",
        "--graph-cleanup",
        "lifecycle_fixture:cleanup",
        "--trials",
        "2",
    ]
    if command == "scan":
        args += ["--url", "local-fixture", "--module", "lifecycle_fixture:graph"]
    else:
        args += [
            "--graph-module",
            "lifecycle_fixture:graph",
            "--limit",
            "1",
            "--format",
            "json",
            "--out",
            str(tmp_path / "report"),
        ]
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 3, result.output
    assert [event[0] for event in events] == ["reset", "invoke", "cleanup"] * 2
    assert events[0][1] != events[3][1]
    journals = list((tmp_path / "runs").glob("*/trial-*.json"))
    assert len(journals) == 2
    assert all(
        json.loads(path.read_text())["exchanges"][0]["lifecycle"]["cleanup"] == "failed" for path in journals
    )


async def test_invalid_cleanup_hook_is_rejected_before_application_action():
    calls = []

    class Graph:
        async def ainvoke(self, state):
            calls.append("action")
            return {"messages": [*state["messages"], {"role": "assistant", "content": "done"}]}

    def cleanup(graph, thread_id):
        calls.append("sync cleanup")

    response = await LangGraphAdapter(graph=Graph(), cleanup=cleanup).query("task")
    assert response.error
    assert calls == []


async def test_cancellation_during_reset_cleans_up_without_claiming_invocation(tmp_path):
    entered = asyncio.Event()
    cleaned = []

    class Graph:
        async def ainvoke(self, state):
            raise AssertionError("reset never completed")

    async def reset(graph, thread_id):
        entered.set()
        await asyncio.Event().wait()

    async def cleanup(graph, thread_id):
        cleaned.append(True)

    task = asyncio.create_task(
        TrialRunner(run_dir=tmp_path).run(
            IndirectHarness(scenario()).probe_for(
                LangGraphAdapter(graph=Graph(), reset=reset, cleanup=cleanup)
            )
        )
    )
    await asyncio.wait_for(entered.wait(), 1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    receipt = json.loads(next(tmp_path.glob("*/trial-0.json")).read_text())["exchanges"][0]["lifecycle"]
    assert receipt["reset"] == "interrupted"
    assert receipt["invocation"] == "not_attempted"
    assert receipt["cleanup"] == "completed"
    assert cleaned == [True]


async def test_later_reset_failure_cannot_verify_remediation_of_prior_violation(tmp_path):
    from neuralstrike.evaluation.baseline import compare_baseline, save_baseline

    resets = []

    class Graph:
        async def ainvoke(self, state):
            return {
                "messages": [
                    *state["messages"],
                    {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [{"id": "initial-action", "name": "grant_admin_access", "args": {}}],
                    },
                ]
            }

    async def reset(graph, thread_id):
        resets.append(True)
        if len(resets) > 1:
            raise RuntimeError("synthetic reset outage")

    adapter = LangGraphAdapter(
        graph=Graph(), target_id="reset-fixture", reset=reset, lifecycle_id="fixture/1"
    )
    probe = IndirectHarness(scenario()).probe_for(adapter)
    runner = TrialRunner(run_dir=tmp_path / "runs")
    vulnerable = await runner.run(probe)
    assert vulnerable.trials[0].verdict is Verdict.SUCCEEDED
    save_baseline(tmp_path / "baseline", vulnerable)
    failed = await runner.run(probe)
    comparison = compare_baseline(tmp_path / "baseline", failed, fail_on="vuln")
    assert comparison.exit_code == 3
    assert comparison.fixed == ()
    assert failed.trials[0].response.exchanges[0]["lifecycle"]["invocation"] == "not_attempted"


async def test_graph_without_application_lifecycle_hooks_preserves_concurrent_invocation():
    entered = []
    both_entered = asyncio.Event()

    class Graph:
        async def ainvoke(self, state):
            entered.append(state["messages"][-1]["content"])
            if len(entered) == 2:
                both_entered.set()
            await both_entered.wait()
            return {"messages": [*state["messages"], {"role": "assistant", "content": "done"}]}

    adapter = LangGraphAdapter(graph=Graph())
    responses = await asyncio.wait_for(asyncio.gather(adapter.query("a"), adapter.query("b")), 0.1)
    assert len(responses) == 2
    assert set(entered) == {"a", "b"}
    assert all(r.error is None for r in responses)


@pytest.mark.parametrize("signature", ["no_args", "keyword_only", "extra_required"])
async def test_invalid_cleanup_signature_is_rejected_before_graph_resolution(signature):
    calls = []

    async def no_args():
        calls.append("cleanup")

    async def keyword_only(*, graph, thread_id):
        calls.append("cleanup")

    async def extra_required(graph, thread_id, extra):
        calls.append("cleanup")

    class Target:
        def build_graph(self):
            calls.append("resolve")
            return self

        async def ainvoke(self, state):
            calls.append("action")
            return {"messages": [*state["messages"], {"role": "assistant", "content": "done"}]}

    response = await LangGraphAdapter(
        graph={"build_graph": Target().build_graph},
        cleanup={"no_args": no_args, "keyword_only": keyword_only, "extra_required": extra_required}[
            signature
        ],
    ).query("task")
    assert response.error
    assert calls == []
    assert response.exchanges[0]["lifecycle"]["invocation"] == "not_attempted"
