"""Properties of the comparison decision table, over its whole input space.

The Phase 0 audit's first release blocker was a transition table that let Resisted → Succeeded pass
`fail_on=vuln`, labelled Succeeded → Inconclusive a fix, and let a missing scenario pass. Those are
not three bugs; they are one property set that nobody had written down. This file writes it down
and then holds the shared decision function to it exhaustively rather than by example:

* incompleteness is **never** a pass when a policy is armed;
* a regression outranks a vuln, and `never` never fails a build;
* a fix appears only from `Succeeded → Resisted` with complete evidence, and never alongside
  `NOT_COMPARABLE`;
* every scenario the run observed is accounted for in exactly one bucket;
* adding a regression can never lower the exit code.

`decide_comparison` is called by both the live baseline gate and the offline `compare` command, so
a property that holds here holds for both surfaces.
"""

from __future__ import annotations

import itertools
import random

import pytest

from neuralstrike.evaluation.baseline import (
    BaselineError,
    CompareDecision,
    CompareResult,
    decide_comparison,
)
from neuralstrike.evaluation.verdict import Verdict

VERDICTS = (Verdict.SUCCEEDED.value, Verdict.RESISTED.value, Verdict.INCONCLUSIVE.value, "unrecorded")
POLICIES = ("never", "vuln", "regression")


def decisions() -> list[tuple[str | None, str, str, bool]]:
    """Every (previous, current, policy, incomplete) combination with one scenario."""
    previous_options: tuple[str | None, ...] = (*VERDICTS, None)
    return [
        (previous, current, policy, incomplete)
        for previous, current, policy, incomplete in itertools.product(
            previous_options, VERDICTS, POLICIES, (False, True)
        )
    ]


def run(
    previous: str | None, current: str, policy: str, incomplete: bool = False
) -> CompareResult:
    baseline = {} if previous is None else {"s-1": previous}
    return decide_comparison(
        baseline,
        {"s-1": current},
        fail_on=policy,
        incomplete=incomplete,
        missing=["s-2"] if incomplete else [],
        unresolved=["s-2"] if incomplete else [],
    )


@pytest.mark.parametrize(("previous", "current", "policy", "incomplete"), decisions())
def test_incompleteness_is_never_a_pass_when_a_policy_is_armed(
    previous: str | None, current: str, policy: str, incomplete: bool
) -> None:
    result = run(previous, current, policy, incomplete)
    if incomplete:
        assert result.decision is CompareDecision.NOT_COMPARABLE
        # `never` is not an armed policy: reporting-only mode may exit 0, and it must still report
        # the assessment as incomplete rather than as a pass.
        assert result.exit_code == (0 if policy == "never" else 3)
    # And a complete run is never reported as not comparable.
    else:
        assert result.decision is not CompareDecision.NOT_COMPARABLE


@pytest.mark.parametrize(("previous", "current", "policy", "incomplete"), decisions())
def test_a_fix_requires_a_complete_succeeded_to_resisted_transition(
    previous: str | None, current: str, policy: str, incomplete: bool
) -> None:
    result = run(previous, current, policy, incomplete)
    if result.fixed:
        assert previous == Verdict.SUCCEEDED.value
        assert current == Verdict.RESISTED.value
        assert not incomplete
        assert result.decision is CompareDecision.PASS


@pytest.mark.parametrize(("previous", "current", "policy", "incomplete"), decisions())
def test_never_policy_never_fails_a_build(
    previous: str | None, current: str, policy: str, incomplete: bool
) -> None:
    result = run(previous, current, policy, incomplete)
    if policy == "never":
        assert result.exit_code == 0


@pytest.mark.parametrize(("previous", "current", "policy", "incomplete"), decisions())
def test_regression_outranks_vuln(
    previous: str | None, current: str, policy: str, incomplete: bool
) -> None:
    result = run(previous, current, policy, incomplete)
    is_regression = previous in {Verdict.RESISTED.value, Verdict.INCONCLUSIVE.value}
    if (
        is_regression
        and current == Verdict.SUCCEEDED.value
        and policy == "regression"
        and not incomplete
    ):
        assert result.decision is CompareDecision.REGRESSION
        assert result.exit_code == 4
    if result.decision is CompareDecision.REGRESSION:
        assert policy == "regression", "a regression verdict under another policy is unrepresentable"


@pytest.mark.parametrize(("previous", "current", "policy", "incomplete"), decisions())
def test_every_observed_scenario_is_accounted_for(
    previous: str | None, current: str, policy: str, incomplete: bool
) -> None:
    """A scenario cannot vanish between the input and the accounting."""
    result = run(previous, current, policy, incomplete)
    bucket: dict[str, list[str]] = {
        "new": list(result.new_succeeded),
        "pre": list(result.pre_existing_succeeded),
        "regression": list(result.regressions),
        "fixed": list(result.fixed),
    }
    placements = [name for name, members in bucket.items() if "s-1" in members]
    assert len(placements) <= 1, f"s-1 was counted in {placements}"
    if current == Verdict.SUCCEEDED.value:
        assert len(placements) == 1, f"a Succeeded scenario vanished from {bucket}"
    if current == Verdict.INCONCLUSIVE.value:
        assert not placements, "an inconclusive scenario must not be given a verdict bucket"


def test_an_unknown_policy_is_refused_rather_than_defaulted() -> None:
    with pytest.raises(BaselineError):
        decide_comparison({"s": Verdict.RESISTED.value}, {"s": Verdict.RESISTED.value}, fail_on="warn")


def test_adding_a_regression_can_never_lower_the_exit_code() -> None:
    """Monotonicity over randomised maps: more findings cannot make a build safer."""
    rng = random.Random(20261112)
    for _ in range(200):
        names = [f"s-{index}" for index in range(rng.randint(1, 4))]
        baseline = {name: rng.choice(VERDICTS) for name in names}
        current = {name: rng.choice(VERDICTS) for name in names}
        policy = rng.choice(POLICIES)
        before = decide_comparison(baseline, current, fail_on=policy).exit_code

        victim = rng.choice(names)
        baseline_with_regression = dict(baseline)
        baseline_with_regression[victim] = Verdict.RESISTED.value
        current_with_regression = dict(current)
        current_with_regression[victim] = Verdict.SUCCEEDED.value
        after = decide_comparison(baseline_with_regression, current_with_regression, fail_on=policy)
        assert after.exit_code >= before, (baseline, current, policy, victim)

        # A fix is the mirror image: it can never raise the exit code, and it is reported as a
        # fix. It does not by itself make the run pass — another scenario can still be vulnerable,
        # which is why the assertion is `<=` and not `== 0`.
        baseline_with_fix = dict(baseline)
        baseline_with_fix[victim] = Verdict.SUCCEEDED.value
        current_with_fix = dict(current)
        current_with_fix[victim] = Verdict.RESISTED.value
        fixed = decide_comparison(baseline_with_fix, current_with_fix, fail_on=policy)
        assert fixed.exit_code <= before, (baseline, current, policy, victim)
        assert victim in fixed.fixed
        assert fixed.decision is not CompareDecision.NOT_COMPARABLE


def test_an_empty_current_map_is_not_silently_a_pass_with_a_policy() -> None:
    """No scenarios at all is incomplete evidence, not a clean run — the caller must say so."""
    complete = decide_comparison({}, {}, fail_on="regression")
    # The function cannot invent incompleteness; it reports pass, and the *caller* must mark it.
    # This test documents that boundary rather than hiding it.
    assert complete.decision is CompareDecision.PASS
    incomplete = decide_comparison({}, {}, fail_on="regression", incomplete=True, missing=["s-1"])
    assert incomplete.decision is CompareDecision.NOT_COMPARABLE
    assert incomplete.exit_code == 3
