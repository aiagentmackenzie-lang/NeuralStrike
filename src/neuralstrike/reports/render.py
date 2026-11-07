"""One format dispatch for live and offline assessment presentations."""

from __future__ import annotations

from collections.abc import Callable

from neuralstrike.reports.json_report import to_json
from neuralstrike.reports.junit import to_junit
from neuralstrike.reports.markdown import to_markdown
from neuralstrike.reports.model import CorpusRun
from neuralstrike.reports.pdf import to_pdf
from neuralstrike.reports.sarif import to_sarif


def render_report(report: CorpusRun, format: str) -> str | bytes:
    writers: dict[str, Callable[[CorpusRun], str | bytes]] = {
        "json": to_json,
        "sarif": to_sarif,
        "junit": to_junit,
        "markdown": to_markdown,
        "pdf": to_pdf,
    }
    if format not in writers:
        raise ValueError("unsupported assessment report format")
    return writers[format](report)
