"""Oracle honesty — the both-directions invariant.

This is the Phase-0 exit-gate test for the oracle corpus. It asserts the
single invariant that makes the oracles trustworthy:

- Every ``SAFE_CASE``  must NOT score ``Succeeded``.
- Every ``VULN_CASE``  must NOT score ``Resisted``.

A failure here means an oracle is dishonest in one direction — either
accusing a safe model (false positive) or letting a real leak through as
a pass (false negative, the worst failure mode for a security tool).
Every such failure must seed a permanent regression case in
:mod:`tests.oracle_honesty_corpus.cases`.
"""

from __future__ import annotations

import pytest
from tests.oracle_honesty_corpus.cases import ALL_CASES, SAFE_CASES, VULN_CASES, Case

from neuralstrike.evaluation.verdict import Verdict


@pytest.mark.parametrize("case", SAFE_CASES, ids=[c.case_id for c in SAFE_CASES])
def test_safe_cases_never_succeed(case: Case) -> None:
    """Safe responses must never score Succeeded (no false positives)."""
    result = case.oracle.check(case.response)
    assert result.verdict is not Verdict.SUCCEEDED, (
        f"SAFE case {case.case_id!r} falsely scored SUCCEEDED: {result.reason}"
    )


@pytest.mark.parametrize("case", VULN_CASES, ids=[c.case_id for c in VULN_CASES])
def test_vuln_cases_never_resisted(case: Case) -> None:
    """Vulnerable responses must never score Resisted (no false negatives)."""
    result = case.oracle.check(case.response)
    assert result.verdict is not Verdict.RESISTED, (
        f"VULN case {case.case_id!r} falsely scored RESISTED: {result.reason}"
    )


@pytest.mark.parametrize("case", ALL_CASES, ids=[c.case_id for c in ALL_CASES])
def test_case_produces_expected_verdict(case: Case) -> None:
    """Each case must produce its declared honest verdict (positive assertion)."""
    result = case.oracle.check(case.response)
    assert result.verdict is case.expected_verdict, (
        f"case {case.case_id!r} expected {case.expected_verdict.value}, "
        f"got {result.verdict.value}: {result.reason}"
    )


def test_corpus_has_both_directions() -> None:
    """The corpus must contain both safe and vulnerable cases (else it tests nothing)."""
    assert len(SAFE_CASES) > 0
    assert len(VULN_CASES) > 0
    # And every oracle family must be represented in BOTH directions.
    safe_oracle_ids = {c.oracle.oracle_id for c in SAFE_CASES}
    vuln_oracle_ids = {c.oracle.oracle_id for c in VULN_CASES}
    assert safe_oracle_ids == vuln_oracle_ids, (
        f"asymmetric corpus: safe={safe_oracle_ids} vuln={vuln_oracle_ids}"
    )
