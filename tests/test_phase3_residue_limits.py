"""Contract: the two Phase 3 residues are limits, and a limit is not a closed gate.

ENGINEERING_BACKLOG.md E-8. The destructive class was measured and never reproduced; persistent-
memory influence stood at one 2/3 in one stage. The backlog allowed two honest outcomes: measure
the effect on an application this project did not author, or restate the residue as a permanent
limit of the declared profiles. This sprint took the second, and these tests protect the
distinction that makes it honest:

* the restatement is present and says "permanent limit", not "open work in progress";
* it does not promote either residue to evidence — no percentage, no rate, no "reproduced";
* it does not move P3-6, which stays `PARTIAL` with the shortfall the acceptance record names;
* it does not author a payload or a profile to make a class light up, which the master plan's
  non-goals forbid.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EFFICACY = ROOT / "docs/implementation/PHASE3_EFFICACY.md"
ACCEPTANCE = ROOT / "docs/implementation/PHASE3_ACCEPTANCE.md"
HEADING = "## Two permanent limits of the declared profiles — 2026-11-12"


def efficacy() -> str:
    return EFFICACY.read_text()


def section() -> str:
    body = efficacy()
    assert HEADING in body, "the residue restatement disappeared; the limits are unrecorded again"
    start = body.index(HEADING)
    boundaries = [m.start() for m in re.finditer(r"^## ", body[start:], re.MULTILINE)][1:]
    end = start + boundaries[0] if boundaries else len(body)
    return body[start:end]


def test_the_restatement_exists_and_says_permanent_limit() -> None:
    body = section()
    assert "permanent limit" in body.lower()
    assert "### 1. Destructive action" in body
    assert "### 2. Persistent-memory influence" in body


def test_the_destructive_residue_is_not_promoted_to_a_reproduced_effect() -> None:
    body = section()
    assert "measured-not-reproduced" in body
    # The forbidden promotion: a completed claim that the effect was observed. The section is
    # allowed to say what a reproduced effect *would* need — that is the limit being explained —
    # but not that one exists.
    for claim in (
        "effect was reproduced",
        "has been reproduced",
        "we reproduced",
        "was observed on",
        "closed the destructive",
    ):
        assert claim not in body.lower(), claim


def test_no_rate_is_quoted_from_a_k_of_three() -> None:
    body = section()
    # k=3 is a count. A percentage in this section would be the exact error it warns about.
    assert not re.search(r"\d+(?:\.\d+)?\s*%", body), "a percentage appears in a counts section"
    assert "percentage" in body.lower(), "the section must say that no percentage is quoted"


def test_the_residue_does_not_move_the_gate() -> None:
    body = section()
    assert "does not move a gate" in body
    assert "P3-6 stays `PARTIAL`" in body
    # And the acceptance record still says exactly that.
    row = [line for line in ACCEPTANCE.read_text().splitlines() if line.startswith("| P3-6")]
    assert len(row) == 1, "P3-6 must appear exactly once in the acceptance record"
    assert "PARTIAL" in row[0]
    assert "destructive action: attempts only, never a reproduced effect" in row[0]


def test_the_restatement_refuses_the_payload_route() -> None:
    """The cheapest way to close this is a new payload, which is the move the plan forbids."""
    body = section()
    assert "new attack payload" in body
    assert "not a fix" in body
