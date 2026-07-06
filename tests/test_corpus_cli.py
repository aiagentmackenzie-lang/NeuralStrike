"""Phase 2 CLI tests — `neuralstrike corpus` and `neuralstrike readme-mapping`."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from neuralstrike.main import app

runner = CliRunner()


def test_readme_mapping_dry_run_prints_section() -> None:
    """Without --apply the command prints the generated section to stdout."""
    result = runner.invoke(app, ["readme-mapping"])
    assert result.exit_code == 0, result.output
    assert "<!-- BEGIN neuralstrike-mapping -->" in result.output
    assert "<!-- END neuralstrike-mapping -->" in result.output
    # The auto-generation banner is present.
    assert "Auto-generated" in result.output
    # Every OWASP category appears in the printed table.
    for cat in ("ASI01", "ASI10", "LLM01", "LLM10"):
        assert cat in result.output


def test_readme_mapping_apply_writes_section_between_markers(tmp_path: Path) -> None:
    """--apply replaces the section between the markers in README.md."""
    from neuralstrike.reports.readme_mapping import BEGIN_MARKER, END_MARKER

    readme = tmp_path / "README.md"
    readme.write_text(
        "# Project\n\nSome intro.\n\n"
        f"{BEGIN_MARKER}\nOLD CONTENT — stale hand-written table.\n{END_MARKER}\n\n"
        "More text after.\n",
        encoding="utf-8",
    )
    # Chdir into tmp_path so the command finds README.md there.
    import os

    cwd = os.getcwd()
    try:
        os.chdir(tmp_path)
        result = runner.invoke(app, ["readme-mapping", "--apply"])
    finally:
        os.chdir(cwd)
    assert result.exit_code == 0, result.output
    text = readme.read_text(encoding="utf-8")
    assert "OLD CONTENT" not in text, "stale table not replaced"
    assert BEGIN_MARKER in text and END_MARKER in text
    # The new generated table is between the markers.
    start = text.index(BEGIN_MARKER)
    end = text.index(END_MARKER) + len(END_MARKER)
    section = text[start:end]
    assert "Auto-generated" in section
    # Surrounding prose is preserved.
    assert text.startswith("# Project")
    assert text.endswith("More text after.\n")


def test_readme_mapping_apply_requires_markers(tmp_path: Path) -> None:
    """--apply fails closed with a clear error when the markers are absent."""
    from neuralstrike.core.exceptions import ValidationError

    readme = tmp_path / "README.md"
    readme.write_text("# Project\n\nNo markers here.\n", encoding="utf-8")
    import os

    cwd = os.getcwd()
    try:
        os.chdir(tmp_path)
        result = runner.invoke(app, ["readme-mapping", "--apply"])
    finally:
        os.chdir(cwd)
    assert result.exit_code == 1, result.output
    assert isinstance(result.exception, ValidationError)
    assert "marker" in str(result.exception).lower()


def test_corpus_command_emits_sarif(tmp_path: Path) -> None:
    """`neuralstrike corpus --limit N --format sarif` produces a valid SARIF file."""
    import os

    out = tmp_path / "report"
    cwd = os.getcwd()
    try:
        os.chdir(tmp_path)
        result = runner.invoke(
            app,
            ["corpus", "--limit", "3", "--format", "sarif", "--out", str(out)],
        )
    finally:
        os.chdir(cwd)
    assert result.exit_code == 0, result.output
    sarif_path = Path(str(out) + ".sarif")
    assert sarif_path.is_file(), f"SARIF not written: {sarif_path}"
    doc = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "NeuralStrike"
    # 3 scenarios -> 3 rules; every rule maps to OWASP + ATLAS + controls.
    rules = run["tool"]["driver"]["rules"]
    assert len(rules) == 3
    for rule in rules:
        props = rule["properties"]
        assert props["owasp_category"]
        assert props["mitre_atlas"]
        assert props["compliance_controls"]


def test_corpus_command_rejects_bad_format(tmp_path: Path) -> None:
    import os

    from neuralstrike.core.exceptions import ValidationError

    cwd = os.getcwd()
    try:
        os.chdir(tmp_path)
        result = runner.invoke(app, ["corpus", "--format", "docx", "--limit", "1"])
    finally:
        os.chdir(cwd)
    assert result.exit_code == 1, result.output
    assert isinstance(result.exception, ValidationError)
    assert "format" in str(result.exception).lower()


def test_corpus_command_openai_requires_url_and_model() -> None:
    from neuralstrike.core.exceptions import ValidationError

    result = runner.invoke(app, ["corpus", "--adapter", "openai"])
    assert result.exit_code == 1, result.output
    assert isinstance(result.exception, ValidationError)
    msg = str(result.exception).lower()
    assert "url" in msg or "model" in msg
