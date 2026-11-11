"""Contract: the README's measured claims are re-derived from the tree, not trusted.

The README now states breadth in numbers — commands, modules, adapters, oracles, scenarios,
transforms, packs, report formats, frameworks, tests. A number in a README rots the moment the tree
moves, and this project has already paid for that twice: the dev section claimed "911 tests, ~90 %"
long after both were wrong, and the capability map still said MCP stdio was "Planned" years after
the bounded stdio transport shipped.

So every one of those numbers is asserted here against the artefact it describes:

* semantic counts (adapters, oracles, transforms, packs, formats, frameworks, corpus) are exact —
  adding a transform without saying so is a documentation defect;
* descriptive counts (modules, packages, lines, tests) are grow-tolerant — they may lag, but not by
  more than 10 %, so the table cannot drift into fiction;
* the three evidence marks must be defined and every capability row must carry one;
* claims of *absence* are pinned too: the README says `mcp-scan` is HTTP-only and that the
  delegation analyzer has no CLI, so both are asserted absent from the CLI.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
SRC = ROOT / "src/neuralstrike"

MARKS = ("✅", "⚠️", "❌")


def text() -> str:
    return README.read_text()


def flat() -> str:
    return " ".join(text().split())


def src_modules() -> list[Path]:
    return sorted(p for p in SRC.rglob("*.py") if "__pycache__" not in p.parts)


# --- the shape of the document --------------------------------------------------------------


def test_the_three_evidence_marks_are_defined_and_used() -> None:
    body = text()
    assert "### Evidence marks used in this README" in body
    for mark in MARKS:
        assert mark in body, f"mark {mark} is not used anywhere"
    assert "CI-verified" in body and "Local observation" in body and "Not implemented" in body


def test_the_stale_two_mark_legend_is_gone() -> None:
    """`Verified / Informational / Planned` was a second vocabulary that could disagree."""
    body = text()
    assert "*Verified*: implemented and covered" not in body
    assert "*Planned*: on the roadmap" not in body


def test_every_capability_row_carries_a_mark() -> None:
    body = text()
    start = body.index("## Capability map")
    end = body.index("### Honest limitations", start)
    rows = [
        line
        for line in body[start:end].splitlines()
        if line.startswith("|") and not line.startswith("|---") and "Capability" not in line
    ]
    assert len(rows) >= 15, f"the capability map shrank to {len(rows)} rows"
    for row in rows:
        assert any(mark in row for mark in MARKS), f"capability row has no evidence mark: {row}"


# --- semantic counts: exact ---------------------------------------------------------------


def test_command_counts_are_exact() -> None:
    from typer.main import get_command

    from neuralstrike.main import app

    group = get_command(app)
    names = set(group.commands)
    # Typer wraps each callback per command, so identity has to come from the underlying function:
    # `assess` and `corpus` must count as one callback, not two.
    callbacks = {
        getattr(command.callback, "__wrapped__", command.callback) for command in group.commands.values()
    }
    body = flat()
    assert f"**{len(names)}** command names" in body, f"README does not state {len(names)} names"
    assert f"**{len(callbacks)}** distinct callbacks" in body, (
        f"README does not state {len(callbacks)} distinct callbacks"
    )
    assert len(callbacks) < len(names), "the alias collapsed; the count sentence is now wrong"
    assert names, "the command scan is blind"


def test_adapter_list_matches_the_cli_choices() -> None:
    main_source = (SRC / "main.py").read_text()
    listed = re.search(r"adapter not in \{([^}]+)\}", main_source)
    assert listed is not None, "cannot find the adapter allowlist in main.py"
    adapters = {item.strip().strip("\"'") for item in listed.group(1).split(",")}
    row = next(line for line in text().splitlines() if line.startswith("| Target adapters |"))
    normalised = row.replace("_", "-")
    named = {name for name in adapters if name in normalised}
    assert named == adapters, f"adapters missing from the README row: {sorted(adapters - named)}"
    assert f"**{len(adapters)}**" in row


def test_transform_count_is_exact() -> None:
    from neuralstrike.transforms import list_transforms

    count = len(list_transforms())
    row = next(line for line in text().splitlines() if line.startswith("| Evasion codecs |"))
    assert f"**{count}**" in row, f"README does not state {count} transforms"


def test_pack_count_is_exact_and_none_are_vendored() -> None:
    from neuralstrike.packs import list_packs

    packs = list_packs()
    row = next(line for line in text().splitlines() if line.startswith("| Benchmark packs |"))
    assert f"**{len(packs)}**" in row
    lowered = row.lower()
    for pack in packs:
        assert pack in lowered, f"pack {pack} is not named"


def test_report_format_count_is_exact() -> None:
    import inspect

    from neuralstrike.reports.render import render_report

    source = inspect.getsource(render_report)
    formats = re.findall(r'"([a-z]+)": to_', source)
    row = next(line for line in text().splitlines() if line.startswith("| Report formats |"))
    assert f"**{len(formats)}**" in row, f"README does not state {len(formats)} formats"
    lowered = row.lower()
    for fmt in formats:
        assert fmt in lowered, f"format {fmt} is not named"


def test_compliance_framework_count_is_exact() -> None:
    from neuralstrike.reports.compliance import FrameworkID

    frameworks = FrameworkID.__args__
    row = next(line for line in text().splitlines() if line.startswith("| Compliance crosswalk |"))
    assert f"**{len(frameworks)}**" in row, f"README does not state {len(frameworks)} frameworks"
    for required in (
        "OWASP ASI",
        "OWASP LLM",
        "MITRE ATLAS",
        "NIST AI RMF",
        "EU AI Act",
        "ISO/IEC 42001",
        "SOC 2",
        "CSA MAESTRO",
    ):
        assert required in row, f"{required} is missing from the crosswalk row"


def test_defense_and_checker_counts_are_exact() -> None:
    from neuralstrike.defenses import checkers, defenses
    from neuralstrike.defenses.base import DEFENSES

    row = next(line for line in text().splitlines() if line.startswith("| Defense testing |"))
    assert f"**{len(DEFENSES)}**" in row, f"README does not state {len(DEFENSES)} defenses"
    checker_classes = [
        name
        for name, obj in vars(checkers).items()
        if isinstance(obj, type) and name.endswith("Checker") and name != "Checker"
    ]
    assert len(checker_classes) == 2, checker_classes
    assert "checkers" in row
    assert defenses  # imported to prove the module is the one counted


def test_oracle_families_are_exact() -> None:
    """Five deterministic families. Adding a sixth without saying so is a documentation defect."""
    families = {
        "canary": SRC / "oracles/canary.py",
        "forbidden_tool": SRC / "oracles/forbidden_tool.py",
        "predicate": SRC / "oracles/predicate.py",
        "schema": SRC / "oracles/schema.py",
        "system_prompt": SRC / "oracles/system_prompt.py",
    }
    for name, path in families.items():
        assert path.is_file(), f"oracle family {name} has no module"
    row = next(line for line in text().splitlines() if line.startswith("| Deterministic oracles |"))
    assert f"**{len(families)}**" in row
    for readable in ("canary", "forbidden-tool", "predicate", "schema", "system-prompt"):
        assert readable in row, f"{readable} is missing from the oracle row"


def test_corpus_counts_are_exact_and_shipped() -> None:
    from neuralstrike.corpus import corpus_path, load_corpus_dir

    scenarios = load_corpus_dir()
    categories = {s.owasp_category for s in scenarios}
    vectors = {s.delivery_vector for s in scenarios}
    files = sorted(corpus_path().glob("*.yaml"))
    row = next(line for line in text().splitlines() if line.startswith("| Scenario corpus |"))
    assert f"**{len(scenarios)}**" in row, f"README does not state {len(scenarios)} scenarios"
    assert f"**{len(categories)}**" in row, f"README does not state {len(categories)} categories"
    assert f"**{len(vectors)}**" in row, f"README does not state {len(vectors)} vectors"
    assert f"**{len(files)}**" in row, f"README does not state {len(files)} corpus files"
    assert len(files) == 4, [f.name for f in files]


def test_adaptive_strategy_count_is_exact() -> None:
    main_source = (SRC / "main.py").read_text()
    listed = re.search(r"if strategy not in \{([^}]+)\}", main_source)
    assert listed is not None
    strategies = {item.strip().strip("\"'") for item in listed.group(1).split(",")}
    real = strategies - {"auto"}
    row = next(line for line in text().splitlines() if line.startswith("| Adaptive strategies |"))
    assert f"**{len(real)}**" in row, f"README does not state {len(real)} strategies"


# --- descriptive counts: grow-tolerant ----------------------------------------------------


def test_module_package_and_line_counts_lag_by_no_more_than_ten_percent() -> None:
    modules = [p for p in src_modules() if p.name != "__init__.py"]
    packages = {p.parent for p in src_modules()}
    loc = sum(len(p.read_text().splitlines()) for p in src_modules())
    row = next(line for line in text().splitlines() if line.startswith("| Source |"))
    stated_modules = int(re.search(r"\*\*(\d+)\*\* implementation modules", row).group(1))
    stated_packages = int(re.search(r"\*\*(\d+)\*\* packages", row).group(1))
    stated_k = float(re.search(r"≈([\d.]+)k", row).group(1))

    def lags(stated: float, actual: float) -> bool:
        return -0.05 <= (stated - actual) / actual <= 0.10

    assert lags(stated_modules, len(modules)), f"README says {stated_modules} modules, tree has {len(modules)}"
    assert lags(stated_packages, len(packages)), f"README says {stated_packages} packages, tree has {len(packages)}"
    assert lags(stated_k * 1000, loc), f"README says ≈{stated_k}k lines, tree has {loc}"


def test_test_counts_are_internally_consistent_and_above_the_enforced_floor() -> None:
    body = flat()
    match = re.search(
        r"\*\*([\d,]+)\*\* collected \(\*\*([\d,]+)\*\* pass, \*\*([\d,]+)\*\* skip\), "
        r"\*\*([\d.]+) %\*\*",
        body,
    )
    assert match is not None, "the development section no longer states test counts"
    collected, passed, skipped, coverage = (
        int(match.group(1).replace(",", "")),
        int(match.group(2).replace(",", "")),
        int(match.group(3).replace(",", "")),
        float(match.group(4)),
    )
    assert passed + skipped == collected, (collected, passed, skipped)
    assert coverage >= 85.0, f"coverage claim {coverage} is below the enforced floor"
    assert coverage <= 100.0


def test_the_stated_collected_count_matches_a_fresh_collection() -> None:
    """The one number that cannot be read from inside a run: ask pytest.

    This is deliberately an exact assertion. "911 tests" survived in this README long after it was
    false, because nothing re-derived it. A collection run costs about a second and makes the claim
    either true or a failing test.
    """
    import subprocess
    import sys

    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "-o", "addopts=", "-q", "--collect-only"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout[-2000:] + completed.stderr[-2000:]
    match = re.search(r"(\d+) tests? collected", completed.stdout)
    assert match is not None, completed.stdout[-2000:]
    fresh = int(match.group(1))

    body = flat()
    stated = int(re.search(r"\*\*([\d,]+)\*\* collected", body).group(1).replace(",", ""))
    assert stated == fresh, (
        f"the development section claims {stated} collected tests; a fresh collection has {fresh}. "
        "Update the counts in README (breadth table + Development) and in this file's expectations."
    )


def test_test_file_and_function_counts_are_close() -> None:
    files = sorted((ROOT / "tests").glob("test_*.py"))
    functions = sum(
        len(re.findall(r"^\s*def test_", path.read_text(), re.MULTILINE)) for path in files
    )
    body = flat()
    stated_files = re.search(r"tests/\s*#\s*(\d+) files", body)
    stated_functions = re.search(r"([\d,]+) test functions", body)
    assert stated_files is not None and stated_functions is not None
    assert abs(int(stated_files.group(1)) - len(files)) <= 3, (stated_files.group(1), len(files))
    stated = int(stated_functions.group(1).replace(",", ""))
    assert abs(stated - functions) / functions <= 0.10, (stated, functions)


# --- claims of absence must stay true -----------------------------------------------------


def test_the_readme_says_mcp_scan_is_http_only_because_it_is() -> None:
    source = (SRC / "main.py").read_text()
    scan = source[source.index("def mcp_scan(") :]
    scan = scan[: scan.index("\n@app.command")]
    assert "stdio_command" not in scan, "mcp_scan grew stdio support: the README row is now wrong"
    body = flat()
    assert "`mcp-scan` requires `--url`" in body
    assert "❌ not implemented" in next(
        line for line in text().splitlines() if line.startswith("| MCP stdio **scanning**")
    )


def test_the_delegation_analyzer_is_library_only_as_documented() -> None:
    source = (SRC / "main.py").read_text()
    assert "DelegationAnalyzer" not in source, "a CLI command now drives the analyzer; update the row"
    row = next(line for line in text().splitlines() if line.startswith("| Delegation-chain analysis"))
    assert "library only" in row
    assert (SRC / "attacks/a2a/delegation.py").is_file()


def test_the_incident_scenarios_are_described_as_modelled_not_replayed() -> None:
    """They are synthetic test cases in the taxonomy, not reproductions of incident evidence."""
    body = flat()
    row = next(line for line in text().splitlines() if line.startswith("| Incident-modelled scenarios"))
    assert "modelled" in row and "not" in row
    assert "replays of the original evidence" in body
    # And the old overclaim is gone.
    assert "Real-incident replays" not in body


def test_tap_is_described_as_a_beam_of_one_with_three_candidates() -> None:
    import inspect

    from neuralstrike.attacks.adaptive.tap import tap_attacker_fn

    source = inspect.getsource(tap_attacker_fn)
    assert "candidates_per_turn: int = 3" in source
    assert "beam=1" in source
    body = flat()
    assert "beam of one" in body
    assert "three candidates" in body


@pytest.mark.parametrize("path", [README])
def test_no_document_claims_certification_or_independent_acceptance(path: Path) -> None:
    body = path.read_text().lower()
    for forbidden in ("certified product", "is certified", "independently verified by",
                      "production-ready", "production ready"):
        assert forbidden not in body, f"{path.name} claims {forbidden!r}"
    assert "what neuralstrike is not" in body
