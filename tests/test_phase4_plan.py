"""Contracts for the Phase 4 plan and its first implemented gate.

Same purpose as the Phase 3 contracts: the document defines what "released" means, so it is
protected against a gate disappearing and against a status line drifting into a claim the
gates do not support. Plus one anti-vapour contract — every command a document names must be a
registered command — and one over the scheduled dependency job, which is the gate this
increment actually implements.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PLAN = ROOT / "docs/implementation/PHASE4_PLAN.md"
PHASE3 = ROOT / "docs/implementation/PHASE3_ACCEPTANCE.md"
README = ROOT / "README.md"
USAGE = ROOT / "USAGE.md"
MAIN = ROOT / "src/neuralstrike/main.py"
DEPENDENCY_WORKFLOW = ROOT / ".github/workflows/dependency-check.yml"
RELEASE_WORKFLOW = ROOT / ".github/workflows/release.yml"

# Frozen: removing a gate changes what Phase 4 has to prove, so it fails here first.
GATES = ("P4-1", "P4-2", "P4-3", "P4-4", "P4-5", "P4-6", "P4-7")
STATUSES = ("MET", "PARTIAL", "OPEN")
GATE_ROW = re.compile(r"^\|\s*(P4-\d+)\s*\|")


def gate_rows() -> dict[str, list[str]]:
    rows: dict[str, list[str]] = {}
    for line in PLAN.read_text().splitlines():
        match = GATE_ROW.match(line)
        if match is None:
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        assert match.group(1) not in rows, f"gate {match.group(1)} is defined twice"
        rows[match.group(1)] = cells
    assert tuple(rows) == GATES
    return rows


def gate_status(cells: list[str]) -> str:
    joined = " | ".join(cells)
    found = [status for status in STATUSES if f"**{status}**" in joined]
    assert len(found) == 1, f"exactly one bold status per gate row, found {found}"
    return found[0]


def test_every_gate_has_a_binary_rule_a_signer_and_no_signature() -> None:
    for gate, cells in gate_rows().items():
        assert len(cells) == 7, f"{gate} must have 7 columns"
        assert cells[2], f"{gate} has no binary criterion"
        assert cells[5], f"{gate} has no required-signer cell"
        assert cells[6] in {"—", "-", ""}, f"{gate} cannot be signed by this repository"


def test_the_status_line_cannot_claim_a_release_while_a_gate_is_unmet_or_unsigned() -> None:
    rows = gate_rows()
    statuses = {gate: gate_status(cells) for gate, cells in rows.items()}
    unsigned = {gate for gate, cells in rows.items() if cells[6] in {"—", "-", ""}}
    header = PLAN.read_text().split("## The acceptance rule")[0]
    released = all(status == "MET" for status in statuses.values()) and not unsigned
    if released:
        assert "NOT RELEASED" not in header
    else:
        assert "NOT RELEASED" in header, (
            "the phase must say NOT RELEASED while a gate is not MET or is unsigned: "
            f"not met { {g: s for g, s in statuses.items() if s != 'MET'} }, unsigned {sorted(unsigned)}"
        )


def test_a_met_gate_must_cite_evidence_that_is_not_a_placeholder() -> None:
    for gate, cells in gate_rows().items():
        if gate_status(cells) == "MET":
            evidence = cells[4].strip()
            assert evidence and evidence not in {"—", "-"}, f"{gate} is MET with no evidence"
            assert "todo" not in evidence.lower(), f"{gate} is MET with a placeholder"


def test_the_plan_does_not_move_phase_3() -> None:
    plan = PLAN.read_text()
    assert "PHASE3_ACCEPTANCE.md" in plan
    assert "NOT ACCEPTED" in plan
    # Phase 3's own status line must still say so.
    assert "NOT ACCEPTED" in PHASE3.read_text().split("## The acceptance rule")[0]


def test_every_document_the_plan_links_to_exists() -> None:
    for target in re.findall(r"\]\(([^)]+\.md)\)", PLAN.read_text()):
        if target.startswith("http"):
            continue
        assert (PLAN.parent / target).is_file(), target


def registered_commands() -> set[str]:
    """Command names as Typer registers them: explicit ``name=`` else the function name."""
    source = MAIN.read_text()
    decorators = re.findall(
        r"@app\.command\((?P<args>[^)]*)\)\s*\n(?P<body>(?:@[^\n]*\n)*)def (?P<fn>\w+)", source
    )
    names = set()
    for args, _body, fn in decorators:
        explicit = re.search(r'name\s*=\s*"([^"]+)"', args)
        names.add(explicit.group(1) if explicit else fn.replace("_", "-"))
    return names


SUPPORT_MATRIX = ROOT / "docs/SUPPORT_MATRIX.md"
LIVE_TARGET_GUIDE = ROOT / "docs/LIVE_TARGET_GUIDE.md"
OFFLINE_EXAMPLE = ROOT / "docs/OFFLINE_EXAMPLE.md"
PILOT_DOCS = (SUPPORT_MATRIX, LIVE_TARGET_GUIDE, OFFLINE_EXAMPLE)


@pytest.mark.parametrize("document", [README, USAGE, SUPPORT_MATRIX, LIVE_TARGET_GUIDE, OFFLINE_EXAMPLE])
def test_no_document_names_a_command_that_is_not_registered(document: Path) -> None:
    """Anti-vapour: documentation may not describe a CLI surface the code does not have."""
    commands = registered_commands()
    assert commands, "no commands parsed from main.py; the parser is blind"
    mentioned = set(re.findall(r"neuralstrike\s+([a-z][a-z0-9-]{2,})", document.read_text()))
    unknown = {name for name in mentioned if name not in commands and name != "neuralstrike"}
    assert not unknown, f"{document.name} names unregistered commands: {sorted(unknown)}"


def test_the_scheduled_dependency_job_is_scheduled_and_audits_the_pinned_locks() -> None:
    workflow = DEPENDENCY_WORKFLOW.read_text()
    assert re.search(r"^on:", workflow, re.MULTILINE)
    assert re.search(r"cron:\s*\"[^\"]+\"", workflow), "no cron schedule"
    assert "workflow_dispatch:" in workflow, "a gate nobody can trigger on demand is not checkable"
    assert "pip-audit" in workflow
    for lock in ("requirements.txt", "requirements-dev.txt"):
        assert f"--require-hashes -r {lock}" in workflow, lock
    # A health signal may not publish, tag or sign anything.
    for forbidden in ("cosign", "docker/build-push-action", "gh release", "pypi-publish", "twine"):
        assert forbidden not in workflow, forbidden
    assert "permissions:" in workflow and "contents: read" in workflow


def test_signing_is_declared_optional_and_no_artifact_is_claimed_signed() -> None:
    release = RELEASE_WORKFLOW.read_text()
    cosign_steps = re.findall(r"- name: Cosign[^\n]*\n\s+if: ([^\n]+)", release)
    assert cosign_steps, "cosign steps disappeared; the policy would then describe nothing"
    for condition in cosign_steps:
        assert "inputs.sign" in condition, condition
    plan = PLAN.read_text()
    assert "optional and off by default" in plan
    assert "every artifact is **unsigned**" in plan


def test_the_plan_is_discoverable_from_the_readme_and_the_phase3_document() -> None:
    assert "PHASE4_PLAN.md" in README.read_text()
    assert "PHASE4_PLAN.md" in PHASE3.read_text()


def test_the_pilot_documents_exist_are_linked_and_are_accurate_in_shape() -> None:
    readme = README.read_text()
    for document in PILOT_DOCS:
        assert document.is_file(), document.name
        assert f"docs/{document.name}" in readme, f"{document.name} is not discoverable"
    matrix = SUPPORT_MATRIX.read_text()
    for heading in ("## Supported", "## Experimental", "## Excluded", "## Measured limits"):
        assert heading in matrix, heading
    # The three accepted profiles must be the supported ones; a fourth would be a claim.
    for profile in ("OpenAI-compatible", "LangGraph", "MCP"):
        assert profile in matrix, profile
    assert "NOT RELEASED" in matrix


def test_the_live_target_guide_never_inlines_a_credential_or_invents_a_flag() -> None:
    guide = LIVE_TARGET_GUIDE.read_text()
    assert "--target-api-key-env" in guide
    # Credentials by reference only: no bearer literal on a command line.
    assert not re.search(r"--(?:api-key|token|bearer)\s+['\"]?\S{8,}", guide), "inline credential"
    # The documented authenticated path is doctor/corpus, never scan.
    scan_lines = [line for line in guide.splitlines() if "scan" in line and "--url" in line]
    assert not scan_lines, f"guide documents authenticated scan, which has no bearer option: {scan_lines}"
    assert "no** `--target-api-key-env`" in guide or "has **no**" in guide


def test_the_offline_example_matches_the_command_it_documents() -> None:
    example = OFFLINE_EXAMPLE.read_text()
    assert "neuralstrike smoke" in example
    # It must not claim efficacy from a fixture run.
    lowered = example.lower()
    assert "not an efficacy result" in lowered
