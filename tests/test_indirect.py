"""Indirect-injection delivery-vector harness tests.

The Phase 2 exit gate: "Indirect-injection delivery vectors all exercise
the correct channel (verified by adapter trace, not by reading the prompt)."
These tests drive the bundled vulnerable LangGraph fixture through the
harness and assert the adapter's DeliveryRecord trace confirms the payload
landed in the scenario's declared channel — never by grepping the prompt.
"""

from __future__ import annotations

import pytest

from neuralstrike.adapters.base import TargetAdapter
from neuralstrike.adapters.langgraph import LangGraphAdapter
from neuralstrike.attacks.indirect import (
    INJECTION_MARKER_PREFIX,
    IndirectHarness,
    mint_injection_marker,
)
from neuralstrike.corpus import load_corpus_dir
from neuralstrike.evaluation.runner import TrialRunner
from neuralstrike.oracles.tool_harness import make_canary_tools


def _one_per_vector() -> dict[str, object]:
    by_vec: dict[str, object] = {}
    for s in load_corpus_dir():
        by_vec.setdefault(s.delivery_vector, s)
    return by_vec


def test_injection_marker_format() -> None:
    m = mint_injection_marker()
    assert m.startswith(INJECTION_MARKER_PREFIX + "-")
    # 16 hex chars after the prefix
    tail = m.split("-", 1)[1]
    assert len(tail) == 16
    int(tail, 16)  # parses as hex


def test_mint_injection_marker_is_distinct_from_canary() -> None:
    m = mint_injection_marker()
    assert not m.startswith("CANARY")
    # The marker prefix is distinct so canary-leakage detection and
    # channel-delivery verification never collide.
    assert INJECTION_MARKER_PREFIX != "CANARY"


@pytest.mark.parametrize("vector", sorted(_one_per_vector().keys()))
@pytest.mark.asyncio
async def test_delivery_vector_lands_in_declared_channel_by_adapter_trace(
    vector: str, tmp_path,
) -> None:
    """The adapter trace (not the prompt) confirms the channel."""
    from neuralstrike.fixtures.langgraph_agent import build_vulnerable_graph

    scenarios = load_corpus_dir()
    scenario = next(s for s in scenarios if s.delivery_vector == vector)
    adapter = LangGraphAdapter(graph=build_vulnerable_graph())
    harness = IndirectHarness(scenario)
    canary_tools = make_canary_tools()
    probe = harness.probe_for(
        adapter,
        canary_tools=canary_tools,
        tools=TargetAdapter.canary_tools_as_schemas(canary_tools),
    )
    runner = TrialRunner(base_seed=7, run_dir=tmp_path / "runs")
    try:
        report = await runner.run(probe, trials=1, persist=False)
    finally:
        await adapter.close()

    trial = report.trials[0]
    assert trial.response is not None
    # Read the delivery channels from the adapter-stamped trace only.
    present_channels: list[str] = []
    for rec in trial.response.traces:
        assert isinstance(rec, dict)
        if "delivery" in rec:
            d = rec["delivery"]
            assert isinstance(d, dict)
            # Every delivery record carries the marker + a present flag.
            assert "marker" in d and "present" in d and "channel" in d
            if d["present"]:
                present_channels.append(d["channel"])

    assert present_channels, (
        f"adapter recorded no present delivery channel for {vector!r}"
    )
    assert scenario.delivery_vector in present_channels, (
        f"declared channel {scenario.delivery_vector!r} not confirmed present "
        f"in adapter trace (got {present_channels})"
    )


@pytest.mark.asyncio
async def test_delivery_records_present_and_absent_channels(tmp_path) -> None:
    """The trace records BOTH present (declared) and absent channels.

    The adapter scans every role-tagged message, so for a tool_result
    scenario the user_message channel must be recorded as absent and
    tool_result as present — proof the harness did not string-stuff the
    user prompt.
    """
    from neuralstrike.fixtures.langgraph_agent import build_vulnerable_graph

    scenarios = load_corpus_dir()
    scenario = next(s for s in scenarios if s.delivery_vector == "tool_result")
    adapter = LangGraphAdapter(graph=build_vulnerable_graph())
    harness = IndirectHarness(scenario)
    canary_tools = make_canary_tools()
    probe = harness.probe_for(
        adapter,
        canary_tools=canary_tools,
        tools=TargetAdapter.canary_tools_as_schemas(canary_tools),
    )
    runner = TrialRunner(base_seed=8, run_dir=tmp_path / "runs")
    try:
        report = await runner.run(probe, trials=1, persist=False)
    finally:
        await adapter.close()

    trial = report.trials[0]
    assert trial.response is not None
    records = [
        rec["delivery"]
        for rec in trial.response.traces
        if isinstance(rec, dict) and "delivery" in rec
    ]
    channels_by_presence = {d["channel"]: d["present"] for d in records}
    # The declared channel is present; the user_message channel is absent
    # (the legitimate task went there, not the payload marker).
    assert channels_by_presence.get("tool_result") is True
    assert channels_by_presence.get("user_message") is False


@pytest.mark.asyncio
async def test_indirect_harness_produces_verdict_and_fidelity(tmp_path) -> None:
    """The harness returns a conclusive verdict + tagged fidelity per the contract."""
    from neuralstrike.fixtures.langgraph_agent import build_vulnerable_graph

    scenarios = load_corpus_dir()
    # A scenario whose success_criteria is forbidden_tool grant_admin_access
    # will succeed against the bundled fixture (which always emits that call).
    scenario = next(
        s for s in scenarios
        if s.delivery_vector == "tool_result"
        and any(c.oracle == "forbidden_tool" and "grant_admin_access" in c.forbidden_tools
                for c in s.success_criteria)
    )
    adapter = LangGraphAdapter(graph=build_vulnerable_graph())
    harness = IndirectHarness(scenario)
    canary_tools = make_canary_tools()
    probe = harness.probe_for(
        adapter,
        canary_tools=canary_tools,
        tools=TargetAdapter.canary_tools_as_schemas(canary_tools),
    )
    runner = TrialRunner(base_seed=9, run_dir=tmp_path / "runs")
    try:
        report = await runner.run(probe, trials=1, persist=False)
    finally:
        await adapter.close()

    trial = report.trials[0]
    from neuralstrike.evaluation.verdict import Verdict
    assert trial.verdict is Verdict.SUCCEEDED
    assert trial.findings  # deterministic oracle(s) fired
    assert trial.scenario_id == scenario.id
