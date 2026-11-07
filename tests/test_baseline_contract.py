"""Assessment NS-01 reproductions and exhaustive gate transition contract."""

from dataclasses import replace

import pytest

from neuralstrike.evaluation.baseline import compare_baseline, save_baseline
from neuralstrike.evaluation.runner import RunMeta, RunReport
from neuralstrike.evaluation.verdict import EvidenceFidelity, TrialResult, Verdict


def report(verdict, scenario="s"):
    trial = TrialResult(0, 1, 0, verdict, EvidenceFidelity.VERBAL, scenario_id=scenario)
    return RunReport(RunMeta("run", "suite", 1, 1, 0, 0.7, "t"), trials=(trial,))


@pytest.mark.parametrize("previous", list(Verdict))
@pytest.mark.parametrize("current", list(Verdict))
@pytest.mark.parametrize("policy", ["vuln", "regression", "never"])
def test_transition_contract(tmp_path, previous, current, policy):
    save_baseline(tmp_path, report(previous))
    result = compare_baseline(tmp_path, report(current), fail_on=policy)
    if policy == "never":
        expected = 0
    elif current is Verdict.SUCCEEDED:
        expected = 4 if policy == "regression" and previous is not Verdict.SUCCEEDED else 1
    elif current is Verdict.INCONCLUSIVE:
        expected = 3
    else:
        expected = 0
    assert result.exit_code == expected
    assert result.fixed == (("s",) if previous is Verdict.SUCCEEDED and current is Verdict.RESISTED else ())
    if current is Verdict.INCONCLUSIVE:
        assert result.decision.value == "not_comparable"


@pytest.mark.parametrize("policy", ["vuln", "regression", "never"])
def test_omitted_scenario_cannot_pass(tmp_path, policy):
    save_baseline(tmp_path, report(Verdict.SUCCEEDED))
    result = compare_baseline(tmp_path, report(Verdict.RESISTED, "other"), fail_on=policy)
    assert result.decision.value == "not_comparable"
    assert result.exit_code == (0 if policy == "never" else 3)
    assert not result.fixed


def test_metadata_cannot_hide_missing_trial(tmp_path):
    baseline = report(Verdict.RESISTED)
    baseline = replace(
        baseline,
        meta=replace(baseline.meta, trials=2),
        trials=(baseline.trials[0], replace(baseline.trials[0], trial_index=1)),
    )
    save_baseline(tmp_path, baseline)
    current = replace(baseline, trials=baseline.trials[:1])
    assert compare_baseline(tmp_path, current).exit_code == 3


def test_inconclusive_trial_cannot_be_hidden_by_resistance(tmp_path):
    baseline = report(Verdict.SUCCEEDED)
    save_baseline(tmp_path, baseline)
    current = report(Verdict.RESISTED)
    current = replace(
        current,
        trials=(current.trials[0], replace(current.trials[0], trial_index=1, verdict=Verdict.INCONCLUSIVE)),
    )
    result = compare_baseline(tmp_path, current)
    assert result.exit_code == 3
    assert not result.fixed


@pytest.mark.parametrize("verdicts", [None, [], {}, {"s": "unknown"}, {"s": []}])
def test_corrupt_verdict_map_is_explicit_error(tmp_path, verdicts):
    import json

    from neuralstrike.evaluation.baseline import BaselineError

    (tmp_path / "suite.baseline.json").write_text(json.dumps({"verdicts": verdicts}))
    with pytest.raises(BaselineError):
        compare_baseline(tmp_path, report(Verdict.RESISTED))


@pytest.mark.parametrize("trials", [[], [0, 0], [[0]], ["0"], None])
def test_corrupt_trial_manifest_is_explicit_error(tmp_path, trials):
    import json

    from neuralstrike.evaluation.baseline import BaselineError

    path = save_baseline(tmp_path, report(Verdict.RESISTED))
    payload = json.loads(path.read_text())
    payload["trial_indices"] = {"s": trials}
    path.write_text(json.dumps(payload))
    with pytest.raises(BaselineError):
        compare_baseline(tmp_path, report(Verdict.RESISTED))


def test_partial_error_retains_violation_but_cannot_pass(tmp_path):
    from neuralstrike.evaluation.verdict import SutResponse

    save_baseline(tmp_path, report(Verdict.RESISTED))
    current = report(Verdict.SUCCEEDED)
    current = replace(current, trials=(replace(current.trials[0], response=SutResponse(error="timeout")),))
    result = compare_baseline(tmp_path, current)
    assert result.exit_code != 0
    assert result.regressions == ("s",)
    assert not result.fixed


def test_wrong_trial_indices_do_not_count_as_completed_coverage(tmp_path):
    import json

    path = save_baseline(tmp_path, report(Verdict.RESISTED))
    baseline = json.loads(path.read_text())
    baseline.pop("trial_indices")  # legacy baseline cannot mask a malformed current plan
    path.write_text(json.dumps(baseline))
    current = report(Verdict.RESISTED)
    current = replace(current, trials=(replace(current.trials[0], trial_index=99),))
    assert compare_baseline(tmp_path, current).exit_code == 3


def test_extra_trials_cannot_disagree_with_declared_plan(tmp_path):
    save_baseline(tmp_path, report(Verdict.RESISTED))
    current = report(Verdict.RESISTED)
    current = replace(current, trials=(*current.trials, replace(current.trials[0], trial_index=1)))
    assert compare_baseline(tmp_path, current).exit_code == 3


def test_non_utf8_baseline_is_an_explicit_baseline_error(tmp_path):
    from neuralstrike.evaluation.baseline import BaselineError, baseline_path

    baseline_path(tmp_path, "suite").write_bytes(b"\xff")
    with pytest.raises(BaselineError):
        compare_baseline(tmp_path, report(Verdict.RESISTED))


@pytest.mark.parametrize("trials", ["1", 1.5, False, 0, -1])
def test_invalid_declared_baseline_trials_cannot_bypass_comparability(tmp_path, trials):
    import json

    from neuralstrike.evaluation.baseline import BaselineError

    path = save_baseline(tmp_path, report(Verdict.RESISTED))
    payload = json.loads(path.read_text())
    payload["trials"] = trials
    path.write_text(json.dumps(payload))
    with pytest.raises(BaselineError):
        compare_baseline(tmp_path, report(Verdict.RESISTED))


@pytest.mark.parametrize(
    "field,value",
    [("base_seed", False), ("intensity", 42), ("scenario_id", []), ("comparison_identity", None)],
)
def test_invalid_comparison_metadata_is_not_ignored(tmp_path, field, value):
    import json

    from neuralstrike.evaluation.baseline import BaselineError

    path = save_baseline(tmp_path, report(Verdict.RESISTED))
    payload = json.loads(path.read_text())
    payload[field] = value
    path.write_text(json.dumps(payload))
    with pytest.raises(BaselineError):
        compare_baseline(tmp_path, report(Verdict.RESISTED))


@pytest.mark.parametrize("field,value", [("base_seed", 99), ("scenario_id", "different-suite")])
def test_different_recorded_comparison_context_is_not_comparable(tmp_path, field, value):
    import json

    path = save_baseline(tmp_path, report(Verdict.RESISTED))
    payload = json.loads(path.read_text())
    payload[field] = value
    path.write_text(json.dumps(payload))
    assert compare_baseline(tmp_path, report(Verdict.RESISTED)).exit_code == 3
