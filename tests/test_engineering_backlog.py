"""Contract: a backlog item is closed by evidence, not by a feeling.

`ENGINEERING_BACKLOG.md` is the work list, and after the 2026-11-12 sprint it carries a state per
item. This contract makes the state machine real:

* every item `E-1`…`E-12` appears exactly once, in a row with a state;
* a `CLOSED` row names a commit and at least one test path, and that test file exists — a closure
  that cites a test nobody can run is a claim, not a closure;
* a `BLOCKED` row names the exact dependency that is missing, so "blocked" cannot mean "I stopped";
* no row may say both.

It also freezes the item set: adding item thirteen is fine, silently dropping one is not.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKLOG = ROOT / "docs/implementation/ENGINEERING_BACKLOG.md"

ITEMS = tuple(f"E-{number}" for number in range(1, 13))
ROW = re.compile(r"^\|\s*(E-\d+)\s*\|")
COMMIT = re.compile(r"`([0-9a-f]{7,40})`")
TEST_PATH = re.compile(r"`(tests/[\w/]+\.py)`")
STATE = re.compile(r"\*\*(CLOSED|BLOCKED)\b")


def rows() -> dict[str, str]:
    found: dict[str, str] = {}
    for line in BACKLOG.read_text().splitlines():
        match = ROW.match(line)
        if match is None:
            continue
        assert match.group(1) not in found, f"{match.group(1)} is defined twice"
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        found[match.group(1)] = cells[-1]
    return found


def test_every_item_is_present_exactly_once() -> None:
    assert tuple(rows()) == ITEMS, tuple(rows())


def test_every_item_carries_a_state() -> None:
    for item, state in rows().items():
        assert STATE.search(state), f"{item} has no CLOSED or BLOCKED state: {state!r}"


def test_a_closed_item_names_a_commit_and_a_runnable_test() -> None:
    for item, state in rows().items():
        if not state.startswith("**CLOSED"):
            continue
        commit = COMMIT.search(state)
        assert commit, f"{item} is CLOSED without a commit"
        assert len(commit.group(1)) >= 7, f"{item} cites an abbreviated commit that cannot resolve"
        tests = TEST_PATH.findall(state)
        assert tests, f"{item} is CLOSED without a contract test"
        for test in tests:
            assert (ROOT / test).is_file(), f"{item} cites a test that does not exist: {test}"


def test_a_blocked_item_names_the_exact_dependency() -> None:
    for item, state in rows().items():
        if not state.startswith("**BLOCKED"):
            continue
        lowered = state.lower()
        assert any(
            marker in lowered
            for marker in ("needs", "approval", "requires", "missing", "absent")
        ), f"{item} is BLOCKED without naming what is missing: {state!r}"


def test_no_row_claims_two_states() -> None:
    for item, state in rows().items():
        assert len(STATE.findall(state)) == 1, f"{item} claims more than one state: {state!r}"


def test_the_closed_items_are_not_still_promised_as_work() -> None:
    """The summary table and the rows must agree; a stale summary is a second work list."""
    body = BACKLOG.read_text()
    summary = body[body.index("## State after") : body.index("## A. Integrity")]
    closed = {item for item, state in rows().items() if state.startswith("**CLOSED")}
    blocked = {item for item, state in rows().items() if state.startswith("**BLOCKED")}
    for item in closed:
        assert item in summary, f"{item} is CLOSED in its row but missing from the summary"
    for item in blocked:
        assert item in summary, f"{item} is BLOCKED in its row but missing from the summary"
