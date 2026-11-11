"""Contract: `--out report.json` must not write `report.json.json`.

ENGINEERING_BACKLOG.md E-5. The extension was appended unconditionally, so the first command in
the offline example (`neuralstrike smoke --out smoke`) produced `smoke.json` while
`--out report.json` produced `report.json.json`. Small, but it is the first thing a reader runs.

The rule, which is the one a naive fix gets wrong: the extension is appended **only when the path
has none**. A path that already carries the format's extension is used verbatim, and a path that
carries a *different* extension is also used verbatim — a suffix the operator typed is never
silently replaced, because that would overwrite a file they did not name.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from neuralstrike.main import app
from neuralstrike.reports.paths import FORMAT_EXTENSIONS, report_destination

runner = CliRunner()


@pytest.mark.parametrize(
    ("out", "format", "expected"),
    [
        ("report", "json", "report.json"),
        ("report.json", "json", "report.json"),
        ("report.sarif", "sarif", "report.sarif"),
        ("report", "sarif", "report.sarif"),
        ("report", "junit", "report.xml"),
        ("report", "markdown", "report.md"),
        ("report", "pdf", "report.pdf"),
        # A different extension is the operator's choice, not a typo to correct.
        ("report.txt", "json", "report.txt"),
        ("report.sarif", "json", "report.sarif"),
        # Dots in a directory name are not an extension.
        ("out.d/report", "json", "out.d/report.json"),
    ],
)
def test_report_destination_appends_only_when_absent(out: str, format: str, expected: str) -> None:
    assert report_destination(out, format) == Path(expected)


def test_the_format_extension_table_is_complete() -> None:
    assert set(FORMAT_EXTENSIONS) == {"json", "sarif", "junit", "markdown", "pdf"}


@pytest.mark.parametrize("name", sorted(FORMAT_EXTENSIONS))
def test_an_unknown_format_is_refused(name: str) -> None:
    with pytest.raises(ValueError):
        report_destination("report", "docx")
    assert FORMAT_EXTENSIONS[name].startswith(".")


def _invoke_in(cwd: Path, args: list[str]) -> object:
    previous = os.getcwd()
    try:
        os.chdir(cwd)
        return runner.invoke(app, args)
    finally:
        os.chdir(previous)


def test_smoke_writes_an_explicit_extension_once(tmp_path: Path) -> None:
    result = _invoke_in(tmp_path, ["smoke", "--out", str(tmp_path / "report.json")])
    assert result.exit_code == 0, result.output
    assert (tmp_path / "report.json").is_file()
    assert not (tmp_path / "report.json.json").exists(), "the extension was appended twice"


def test_smoke_still_appends_when_the_path_has_no_extension(tmp_path: Path) -> None:
    """The behaviour the offline example documents must not change."""
    result = _invoke_in(tmp_path, ["smoke", "--out", str(tmp_path / "report")])
    assert result.exit_code == 0, result.output
    assert (tmp_path / "report.json").is_file()


def test_assess_writes_an_explicit_extension_once(tmp_path: Path) -> None:
    result = _invoke_in(
        tmp_path,
        ["assess", "--limit", "2", "--format", "json", "--out", str(tmp_path / "assessment.json")],
    )
    assert result.exit_code in {0, 1}, result.output
    assert (tmp_path / "assessment.json").is_file()
    assert not (tmp_path / "assessment.json.json").exists()


def test_assess_appends_the_format_extension_when_absent(tmp_path: Path) -> None:
    result = _invoke_in(
        tmp_path,
        ["assess", "--limit", "2", "--format", "sarif", "--out", str(tmp_path / "assessment")],
    )
    assert result.exit_code in {0, 1}, result.output
    assert (tmp_path / "assessment.sarif").is_file()
    json.loads((tmp_path / "assessment.sarif").read_text())  # a real SARIF document


def test_replay_writes_an_explicit_extension_once(tmp_path: Path) -> None:
    assessed = _invoke_in(
        tmp_path,
        ["assess", "--limit", "2", "--format", "json", "--out", str(tmp_path / "a.json")],
    )
    assert assessed.exit_code in {0, 1}, assessed.output
    bundles = sorted((tmp_path / "runs").iterdir())
    assert bundles, "assess committed no bundle"
    replayed = _invoke_in(
        tmp_path,
        ["replay", str(bundles[-1]), "--out", str(tmp_path / "replayed.json"), "--fail-on", "never"],
    )
    assert replayed.exit_code == 0, replayed.output
    assert (tmp_path / "replayed.json").is_file()
    assert not (tmp_path / "replayed.json.json").exists()
