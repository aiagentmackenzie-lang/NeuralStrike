"""Contract: the README's first instruction is inside the acceptance claims.

ENGINEERING_BACKLOG.md E-4: the quickstart's third step was `neuralstrike forge` — an ungated
legacy command — while the accepted path (`assess`) was step four. The first thing a new reader is
told to run was outside every claim the project makes.

Three things are asserted: the first command in the quickstart is `doctor`, `assess` follows it
and `forge` appears nowhere in the quickstart; the legacy catalogue is one headed section with an
explicit no-acceptance-claim warning that also says the scope gate is opt-in; and no legacy
command is presented in a second table elsewhere in the README, because two tables of the same
fifteen commands is how one of them goes stale.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from neuralstrike.safety.surface import LEGACY_COMMANDS

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
LEGACY_HEADING = "### Legacy offensive catalogue — no acceptance claim"
COMMAND = re.compile(r"neuralstrike\s+([a-z][a-z0-9-]+)")
TABLE_ROW = re.compile(r"^\|\s*`(?P<name>[a-z0-9-]+)`\s*\|", re.MULTILINE)


def text() -> str:
    return README.read_text()


def section(heading: str) -> str:
    """Return the README body under a heading, up to the next heading of the same depth."""
    body = text()
    assert heading in body, f"README lost the heading {heading!r}"
    start = body.index(heading)
    # The heading itself matches the heading pattern, so drop the match at offset 0.
    boundaries = [m.start() for m in re.finditer(r"^#{2,3} ", body[start:], re.MULTILINE)][1:]
    end = start + boundaries[0] if boundaries else len(body)
    return body[start:end]


def test_the_quickstart_starts_with_a_gated_command() -> None:
    quickstart = section("## Quickstart")
    commands = [name for name in COMMAND.findall(quickstart) if name != "neuralstrike"]
    assert commands, "the quickstart names no command"
    assert commands[0] == "doctor", (
        f"the quickstart's first command is {commands[0]!r}; it must be `doctor`, because the "
        "first thing a reader runs has to be inside the acceptance claims"
    )
    assert "assess" in commands, "the accepted assessment path is not in the quickstart"
    assert commands.index("assess") < len(commands), commands


def test_the_quickstart_contains_no_legacy_command() -> None:
    quickstart = section("## Quickstart")
    named = set(COMMAND.findall(quickstart))
    offenders = sorted(named & LEGACY_COMMANDS)
    assert not offenders, (
        f"the quickstart invokes legacy commands with no acceptance claim: {offenders}"
    )


def test_the_legacy_section_carries_the_warning() -> None:
    body = section(LEGACY_HEADING).lower()
    assert "no acceptance claim" in body
    assert "opt-in" in body or "unless you supply" in body, (
        "the legacy section must say the scope gate is opt-in, not merely that it exists"
    )
    assert "local observation" in body or "not evidence" in body


@pytest.mark.parametrize("name", sorted(LEGACY_COMMANDS))
def test_each_legacy_command_is_named_in_the_legacy_section(name: str) -> None:
    assert f"`{name}`" in section(LEGACY_HEADING), f"{name} is not in the legacy catalogue"


def test_no_legacy_command_appears_in_a_table_outside_the_legacy_section() -> None:
    body = text()
    start = body.index(LEGACY_HEADING)
    end = body.index("\n## ", start + 1) if "\n## " in body[start + 1 :] else len(body)
    outside = body[:start] + body[end:]
    rows = set(TABLE_ROW.findall(outside))
    offenders = sorted(rows & LEGACY_COMMANDS)
    assert not offenders, (
        f"legacy commands are tabulated outside the legacy section: {offenders}; the catalogue "
        "must have exactly one description or the two will drift"
    )


def test_there_is_exactly_one_legacy_catalogue() -> None:
    """A pointer to the catalogue is fine; a second catalogue is not."""
    catalogues = [
        line
        for line in text().splitlines()
        if line.startswith("#") and "catalogue" in line.lower()
    ]
    assert len(catalogues) == 1, catalogues
