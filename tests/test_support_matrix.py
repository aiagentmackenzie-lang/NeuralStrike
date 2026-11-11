"""Contract: the support matrix may not be silent about a command that sends traffic.

ENGINEERING_BACKLOG.md E-2: the one document that exists to prevent "it must work, it isn't
excluded" said nothing about the fifteen legacy offensive commands — the largest part of the CLI.
Silence was the failure mode. This contract makes silence and drift fail:

* every legacy command has a row in the legacy section, with the effect class the package
  declares (`LEGACY_EFFECT`);
* every command that sends traffic is named somewhere in the matrix, so a newly gated command
  cannot be added without the document saying what it is;
* no legacy command is listed as supported;
* the document states that the scope gate is opt-in, because the opposite reading is the one a
  reader takes by default.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from neuralstrike.safety.surface import (
    LEGACY_COMMANDS,
    LEGACY_EFFECT,
    TRAFFIC_COMMANDS,
    CommandRow,
    surface_row,
)

ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "docs/SUPPORT_MATRIX.md"
LEGACY_HEADING = "## Legacy offensive commands — no acceptance claim"
ROW = re.compile(r"^\|\s*`(?P<name>[a-z0-9-]+)`\s*\|(?P<rest>.*)$", re.MULTILINE)


def matrix_text() -> str:
    return MATRIX.read_text()


def legacy_section() -> str:
    text = matrix_text()
    assert LEGACY_HEADING in text, "the legacy section disappeared; the document is silent again"
    start = text.index(LEGACY_HEADING)
    end = text.index("\n## ", start + 1)
    return text[start:end]


def legacy_rows() -> dict[str, list[str]]:
    rows: dict[str, list[str]] = {}
    for line in legacy_section().splitlines():
        match = ROW.match(line)
        if match is None:
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        rows[match.group("name")] = cells
    return rows


def test_the_legacy_section_names_every_legacy_command() -> None:
    documented = set(legacy_rows())
    missing = sorted(LEGACY_COMMANDS - documented)
    extra = sorted(documented - LEGACY_COMMANDS)
    assert not missing, f"legacy commands the support matrix is silent about: {missing}"
    assert not extra, f"the legacy section claims commands that are not legacy: {extra}"


@pytest.mark.parametrize("name", sorted(LEGACY_COMMANDS))
def test_each_legacy_command_declares_its_effect_class(name: str) -> None:
    cells = legacy_rows()[name]
    rendered = " ".join(cells).lower()
    declared = LEGACY_EFFECT[name].replace("-", " ")
    assert declared in rendered, (
        f"{name} is declared {LEGACY_EFFECT[name]!r} in the package but the matrix says {cells!r}"
    )


@pytest.mark.parametrize("name", sorted(LEGACY_COMMANDS))
def test_each_legacy_command_states_that_it_carries_no_acceptance_claim(name: str) -> None:
    """Per-command silence is what the section exists to prevent, so the claim is per-command.

    The section's heading carries the sentence and each row carries its effect class; what must
    not happen is a command appearing in a *supported* table, which would assert the opposite.
    """
    row = surface_row(name)
    assert row.kind == "legacy"
    assert row.sends_traffic, f"{name} is legacy but classified as sending no traffic"


@pytest.mark.parametrize("name", sorted(TRAFFIC_COMMANDS))
def test_no_traffic_sending_command_is_absent_from_the_matrix(name: str) -> None:
    row: CommandRow = surface_row(name)
    assert row.sends_traffic
    text = matrix_text()
    assert f"`{name}`" in text, (
        f"{name} sends traffic but no section of SUPPORT_MATRIX.md names it; a command that is "
        "neither supported, experimental, excluded nor listed as legacy is exactly the silence "
        "this document exists to prevent"
    )


def test_supported_section_does_not_claim_a_legacy_command() -> None:
    text = matrix_text()
    supported = text[text.index("## Supported") : text.index("## Experimental")]
    for name in LEGACY_COMMANDS:
        assert f"`{name}`" not in supported, (
            f"{name} is a legacy command with no acceptance record but appears under Supported"
        )


def test_the_matrix_states_that_the_scope_gate_is_opt_in() -> None:
    """The default reading of a command table is 'the gate is global'. It is not."""
    section = legacy_section().lower()
    assert "opt-in" in section, "the legacy section must state that --scope-file is opt-in"
    assert "does not create a global gate" in section
    assert "not containment" in section or "not sandbox" in section


def test_the_matrix_states_the_measured_gate_counts() -> None:
    """The numbers in the document are measurements; a prose number is a claim."""
    section = legacy_section()
    assert "42 registered" in section
    assert "27" in section and "15" in section
