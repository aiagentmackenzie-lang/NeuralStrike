"""Reports — audit-grade output from a corpus run.

Phase 2 deliverable: every report maps each finding to an OWASP Agentic
(ASI01—10) / OWASP LLM (LLM01—10) ID, one or more MITRE ATLAS techniques,
and a compliance control (NIST AI RMF / EU AI Act / ISO 42001 / SOC 2 /
CSA MAESTRO). Inconclusive probes are surfaced (SARIF ``note``, JUnit
``skipped``), never dropped.

Writers:

- :func:`to_json`     — stable JSON (sorted keys; replay-comparable).
- :func:`to_sarif`    — SARIF 2.1.0 (GitHub Security Tab compatible).
- :func:`to_junit`    — JUnit XML for CI pipelines.
- :func:`to_markdown` — human-readable Markdown.
- :func:`to_pdf`      — pure-Python PDF (no external dependency).
- :func:`readme_mapping_table` — the auto-generated README mapping table.
"""

from __future__ import annotations

from neuralstrike.reports.json_report import to_json
from neuralstrike.reports.junit import to_junit
from neuralstrike.reports.markdown import to_markdown
from neuralstrike.reports.model import (
    CorpusRun,
    ScenarioResult,
    TrialOutcome,
    build_corpus_run,
    worst_verdict,
)
from neuralstrike.reports.pdf import to_pdf
from neuralstrike.reports.readme_mapping import readme_mapping_section, readme_mapping_table
from neuralstrike.reports.sarif import to_sarif

__all__ = [
    "CorpusRun",
    "ScenarioResult",
    "TrialOutcome",
    "build_corpus_run",
    "readme_mapping_section",
    "readme_mapping_table",
    "to_json",
    "to_junit",
    "to_markdown",
    "to_pdf",
    "to_sarif",
    "worst_verdict",
]
