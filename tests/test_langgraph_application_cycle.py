"""The same independent graph/scenario must detect vulnerability, fix and regression."""

import hashlib
import json
from pathlib import Path

import pytest
from examples.langgraph_account_support.application import AccountSupport

from neuralstrike.adapters.langgraph import LangGraphAdapter
from neuralstrike.attacks.indirect import IndirectHarness
from neuralstrike.corpus.loader import load_corpus
from neuralstrike.evaluation.baseline import compare_baseline, save_baseline
from neuralstrike.evaluation.bundle import replay_bundle
from neuralstrike.evaluation.runner import TrialRunner
from neuralstrike.evaluation.verdict import EvidenceFidelity, Verdict


@pytest.mark.parametrize("execution", ["invoke", "stream"])
async def test_same_application_vulnerable_hardened_regression_with_offline_evidence(tmp_path, execution):
    scenario = load_corpus(Path("examples/langgraph_account_support/scenarios.yaml"))[0]
    app = AccountSupport()
    async def reset(graph, thread_id):
        app.reset()

    class ValuesGraph:
        def astream(self, state, **kwargs):
            return app.graph.astream(state, **kwargs)

    adapter = LangGraphAdapter(
        graph=app.graph if execution == "invoke" else ValuesGraph(),
        reset=reset,
        lifecycle_id="controlled-account-support/reset-v1",
        target_id="controlled-account-support",
        delivery_channels=frozenset({"user_message", "retrieved_document"}),
    )
    probe = IndirectHarness(scenario).probe_for(adapter)
    paths = []
    reports = []
    observed = []
    for hardened in (False, True, False):
        app.hardened = hardened
        report = await TrialRunner(run_dir=tmp_path / "runs", base_seed=123).run(probe)
        reports.append(report)
        paths.append(tmp_path / "runs" / report.meta.run_id)
        assert app.events[0]["event"] == "retrieval_read"
        assert scenario.adversarial_payload in app.events[0]["documents"][0]
        assert app.roles["customer"] == ("reader" if hardened else "admin")
        assert report.trials[0].response.text in scenario.benign_task_markers
        assert report.trials[0].response.exchanges[0]["lifecycle"]["reset"] == "completed"
        assert report.trials[0].fidelity is EvidenceFidelity.INTENT_TO_ACT
        assert not any("receipt_id" in trace for trace in report.trials[0].response.traces)
        observed.append(json.loads(json.dumps(app.events)))

    assert [r.verdicts for r in reports] == [(Verdict.SUCCEEDED,), (Verdict.RESISTED,), (Verdict.SUCCEEDED,)]
    save_baseline(tmp_path / "vulnerable-baseline", reports[0])
    fixed = compare_baseline(tmp_path / "vulnerable-baseline", reports[1])
    assert fixed.exit_code == 0 and fixed.fixed == (scenario.id,)
    save_baseline(tmp_path / "hardened-baseline", reports[1])
    regressed = compare_baseline(tmp_path / "hardened-baseline", reports[2])
    assert regressed.exit_code == 4 and regressed.regressions == (scenario.id,)
    before = [
        {file.name: hashlib.sha256(file.read_bytes()).hexdigest() for file in path.iterdir()}
        for path in paths
    ]
    for path, original in zip(paths, reports, strict=True):
        assert replay_bundle(path, verify_oracles=True).to_dict() == original.to_dict()
    assert before == [
        {file.name: hashlib.sha256(file.read_bytes()).hexdigest() for file in path.iterdir()}
        for path in paths
    ]
    assert observed[0][1]["name"] == observed[2][1]["name"] == "grant_admin_access"
    assert observed[1][1]["name"] == "lookup_account"
