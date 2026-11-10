"""Contracts for the Phase 3 acceptance document.

The document is the definition by which Phase 3 will be judged, so it is worth protecting from
the two ways such documents decay: a gate quietly disappearing, and a status line drifting into
claiming more than the gates support. Neither check can judge whether a gate is *right* — only a
reviewer can — and the document says so.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ACCEPTANCE = ROOT / "docs/implementation/PHASE3_ACCEPTANCE.md"
EFFICACY = ROOT / "docs/implementation/PHASE3_EFFICACY.md"
README = ROOT / "README.md"

# Frozen: removing a gate is a change to what Phase 3 has to prove, so it fails here first.
GATES = ("P3-1", "P3-2", "P3-3", "P3-4", "P3-5", "P3-6", "P3-7")
STATUSES = ("ACCEPTED", "PARTIAL", "OPEN")
GATE_ROW = re.compile(r"^\|\s*(P3-\d+)\s*\|")


def gate_rows() -> dict[str, list[str]]:
    rows: dict[str, list[str]] = {}
    for line in ACCEPTANCE.read_text().splitlines():
        match = GATE_ROW.match(line)
        if match is None:
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        assert match.group(1) not in rows, f"gate {match.group(1)} is defined twice"
        rows[match.group(1)] = cells
    return rows


def gate_status(cells: list[str]) -> str:
    joined = " | ".join(cells)
    found = [status for status in STATUSES if f"**{status}**" in joined]
    assert len(found) == 1, f"exactly one bold status per gate row, found {found}"
    return found[0]


def test_the_acceptance_document_exists_and_defines_every_gate_once() -> None:
    assert ACCEPTANCE.is_file()
    assert tuple(gate_rows()) == GATES


def test_every_gate_carries_one_declared_status_and_a_rule() -> None:
    for gate, cells in gate_rows().items():
        gate_status(cells)
        # A gate without a binary criterion and a named signer is an opinion, not a gate.
        assert len(cells) == 6, f"{gate} must have 6 columns (id, gate, criterion, state, evidence, signer)"
        assert cells[2], f"{gate} has no binary criterion"
        assert cells[5], f"{gate} has no signer cell"


def test_the_status_line_cannot_claim_acceptance_while_a_gate_gate_is_not_accepted() -> None:
    statuses = {gate: gate_status(cells) for gate, cells in gate_rows().items()}
    header = ACCEPTANCE.read_text().split("## The acceptance rule")[0]
    if all(status == "ACCEPTED" for status in statuses.values()):
        assert "NOT ACCEPTED" not in header
    else:
        assert "NOT ACCEPTED" in header, (
            "a gate is not ACCEPTED, so the document must say NOT ACCEPTED: "
            f"{ {g: s for g, s in statuses.items() if s != 'ACCEPTED'} }"
        )


def test_every_document_the_acceptance_document_links_to_exists() -> None:
    for target in re.findall(r"\]\(([^)]+\.md)\)", ACCEPTANCE.read_text()):
        if target.startswith("http"):
            continue
        assert (ACCEPTANCE.parent / target).is_file(), target


def test_the_efficacy_record_points_at_the_acceptance_document() -> None:
    """One entry point, not two: the phase record must not describe gates in isolation."""
    assert "PHASE3_ACCEPTANCE.md" in EFFICACY.read_text()


def test_a_gate_cannot_be_silently_upgraded_by_editing_its_status_only() -> None:
    """A gate may only read ACCEPTED with a signer that is not the author."""
    for gate, cells in gate_rows().items():
        if gate_status(cells) == "ACCEPTED":
            signer = cells[5].strip()
            assert signer and "—" not in signer, f"{gate} is ACCEPTED with no named signer"
            assert "author" not in signer.lower(), f"{gate} is ACCEPTED by the author"


@pytest.mark.parametrize("document", ["PHASE3_EFFICACY.md", "PHASE3_MEASUREMENT_BOUNDARIES.md"])
def test_the_documents_that_describe_phase_3_do_not_claim_acceptance(document: str) -> None:
    text = (ROOT / "docs/implementation" / document).read_text()
    lowered = text.lower()
    assert ("phase 3 remains open" in lowered or "phase 3 remains in progress" in lowered
            or "not established" in lowered), document


def test_the_acceptance_document_is_discoverable_from_the_readme() -> None:
    """A gate document nobody can find is not a gate document."""
    assert "PHASE3_ACCEPTANCE.md" in README.read_text()
