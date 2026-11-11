"""Contract: the tool-axis comparator is a plan, and a plan is not a result.

ENGINEERING_BACKLOG.md E-6. The plan asks for PyRIT and garak compared *as tools* on the same
targets, budgets and ground truth. That comparison has never run. This contract protects the two
things that make the document honest:

1. it declares `unsupported` rows before execution, so a tool that cannot express a question is
   never later reported as having scored zero on it;
2. it carries no result. A document that has never been executed may not grow a results table —
   the cheapest way to fake a comparator is to write the table you expected.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLAN = ROOT / "docs/implementation/TOOL_AXIS_COMPARATOR_PLAN.md"

TOOLS = ("NeuralStrike", "PyRIT", "garak")


def text() -> str:
    return PLAN.read_text()


def flat() -> str:
    """Prose contracts match against collapsed whitespace: markdown wraps mid-phrase."""
    return " ".join(PLAN.read_text().split())


def test_the_plan_exists_and_names_all_three_tools() -> None:
    assert PLAN.is_file()
    body = text()
    for tool in TOOLS:
        assert tool in body, tool


def test_the_plan_is_declared_and_not_executed() -> None:
    body = text()
    assert "DECLARED, NOT EXECUTED" in body
    assert "No row in this document has been measured" in body


def test_unsupported_rows_are_declared_before_execution() -> None:
    body = flat()
    assert body.count("**unsupported**") >= 4, (
        "the plan must declare, per row, which tools cannot express the question"
    )
    # The distinction this plan exists to protect.
    assert "unsupported by construction" in body
    assert "has not failed" in body


def test_the_scoring_rule_is_one_scorer_for_every_tool() -> None:
    body = text()
    body_flat = flat()
    assert "one scorer, applied to all three" in body.lower()
    assert "never reads a tool's own score to decide an outcome" in body_flat


def test_the_decision_rule_allows_a_result_that_flatters_another_tool() -> None:
    body = flat()
    assert "published first, in those words" in body
    assert "including one where a third-party tool's row reads better than" in body


def test_the_plan_carries_no_result_table() -> None:
    """A comparator that has never run may not report a measurement."""
    body = text()
    for claim in ("hits:", "hit rate", "observed:", "result:", "we measured"):
        assert claim not in body.lower(), f"the unexecuted plan appears to report a result: {claim}"
    # Counts-per-row tables are fine as declarations; a populated result column is not.
    assert not re.search(r"\|\s*\d+\s*/\s*\d+\s*\|", body), (
        "a populated count appears in a plan that declares it has measured nothing"
    )


def test_the_missing_prerequisites_are_named() -> None:
    body = flat()
    assert "not installed" in body
    assert "needs the owner's approval" in body
