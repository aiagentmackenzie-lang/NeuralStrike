"""Contract: the package may not claim a stability grade its own gate documents deny.

The classifier is the first thing a buyer reads — it ships on the package page and inside the
wheel metadata — while the honesty (NOT RELEASED, NOT ACCEPTED) lives three clicks deeper in
`docs/implementation/`. That asymmetry is the defect this contract closes: the two statements
must agree, and the only way to make them agree is to move the classifier down or the gates up.

Read from the artefacts, never from prose about the artefacts: `pyproject.toml` for the claim and
the Phase 3 / Phase 4 status lines for the evidence.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
PHASE3 = ROOT / "docs/implementation/PHASE3_ACCEPTANCE.md"
PHASE4 = ROOT / "docs/implementation/PHASE4_PLAN.md"

# PEP 639 / trove ordering: 1 is the least mature claim, 7 the most.
STABILITY = {
    "Development Status :: 1 - Planning": 1,
    "Development Status :: 2 - Pre-Alpha": 2,
    "Development Status :: 3 - Alpha": 3,
    "Development Status :: 4 - Beta": 4,
    "Development Status :: 5 - Production/Stable": 5,
    "Development Status :: 6 - Mature": 6,
    "Development Status :: 7 - Inactive": 7,
}
STATUS_LINE = re.compile(r"^Status:\s*\*\*(?P<claim>[^*]+)\*\*", re.MULTILINE)


def classifiers() -> list[str]:
    data = tomllib.loads(PYPROJECT.read_text())
    found = data["project"]["classifiers"]
    assert isinstance(found, list)
    return [str(item) for item in found]


def stability_rows() -> list[str]:
    return [item for item in classifiers() if item.startswith("Development Status ::")]


def declared_stability() -> str:
    rows = stability_rows()
    assert len(rows) == 1, f"exactly one Development Status classifier is allowed, found {rows}"
    return rows[0]


def status_claim(path: Path) -> str:
    match = STATUS_LINE.search(path.read_text())
    assert match is not None, f"{path.name} has no `Status: **...**` line"
    return match.group("claim").strip()


def test_exactly_one_stability_classifier() -> None:
    declared_stability()  # asserts the invariant
    assert declared_stability() in STABILITY, "unrecognised Development Status classifier"


def test_classifier_does_not_outrun_the_release_plan() -> None:
    """A `Production/Stable` wheel under a `NOT RELEASED` plan is a false claim on the package page."""
    grade = STABILITY[declared_stability()]
    phase4 = status_claim(PHASE4)
    phase3 = status_claim(PHASE3)

    if grade >= 5:
        assert phase4.upper().startswith("RELEASED"), (
            f"pyproject.toml claims {declared_stability()!r} but PHASE4_PLAN.md says "
            f"{phase4!r}: the package must not advertise a stability the release gate denies"
        )
        assert phase3.upper().startswith("ACCEPTED"), (
            f"pyproject.toml claims {declared_stability()!r} but PHASE3_ACCEPTANCE.md says "
            f"{phase3!r}: efficacy is not accepted, so 'Production/Stable' is unsupported"
        )


@pytest.mark.parametrize("path", [PHASE3, PHASE4])
def test_status_documents_are_present_and_parseable(path: Path) -> None:
    assert path.is_file()
    assert status_claim(path)
