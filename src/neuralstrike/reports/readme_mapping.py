"""README mapping-table generator.

Closes Phase 2 gaps **C1 / I1** "by construction": the README's OWASP /
ATLAS mapping table is *generated* from the shipped corpus, never
hand-written. A CI step (or the ``neuralstrike readme-mapping`` CLI command)
calls :func:`readme_mapping_table` and writes the section between the
``<!-- BEGIN neuralstrike-mapping -->`` / ``<!-- END neuralstrike-mapping
-->`` markers in ``README.md``. The markers make the section replaceable
on every regeneration so the table can never drift from the corpus.

The table has one row per OWASP category (ASI01—10, LLM01—10), with:

- the official OWASP category name,
- the count of shipped scenarios for that category,
- the MITRE ATLAS techniques those scenarios reference,
- the delivery vectors exercised,
- a short "what NeuralStrike tests" line.

Honesty rules: counts come from :func:`load_corpus_dir`; nothing is
hardcoded. If a category has zero scenarios, the row says so.
"""

from __future__ import annotations

from collections import Counter

from neuralstrike.corpus.loader import Scenario, load_corpus_dir
from neuralstrike.reports.compliance import OWASP_ASI_INDEX, OWASP_LLM_INDEX

__all__ = ["BEGIN_MARKER", "END_MARKER", "readme_mapping_section", "readme_mapping_table"]

BEGIN_MARKER = "<!-- BEGIN neuralstrike-mapping -->"
END_MARKER = "<!-- END neuralstrike-mapping -->"


def _category_rows(scenarios: list[Scenario]) -> list[str]:
    by_cat: dict[str, list[Scenario]] = {}
    for s in scenarios:
        by_cat.setdefault(s.owasp_category, []).append(s)

    def _row(cat: str, name: str) -> str:
        cases = by_cat.get(cat, [])
        count = len(cases)
        atlas = sorted({a for s in cases for a in s.mitre_atlas})
        vectors = sorted({s.delivery_vector for s in cases})
        atlas_str = ", ".join(f"`{a}`" for a in atlas) if atlas else "—"
        vectors_str = ", ".join(f"`{v}`" for v in vectors) if vectors else "—"
        return f"| **{cat}** | {name} | {count} | {atlas_str} | {vectors_str} |"

    rows: list[str] = []
    rows.append("### OWASP Top 10 for Agentic Applications (2026)")
    rows.append("")
    rows.append("| ID | Category | Scenarios | MITRE ATLAS | Delivery vectors |")
    rows.append("|----|----------|----------:|-------------|------------------|")
    for cat, name in OWASP_ASI_INDEX.items():
        rows.append(_row(cat, name))

    rows.append("")
    rows.append("### OWASP Top 10 for LLM Applications (2025)")
    rows.append("")
    rows.append("| ID | Category | Scenarios | MITRE ATLAS | Delivery vectors |")
    rows.append("|----|----------|----------:|-------------|------------------|")
    for cat, name in OWASP_LLM_INDEX.items():
        rows.append(_row(cat, name))

    return rows


def readme_mapping_table(scenarios: list[Scenario] | None = None) -> str:
    """Generate the README mapping-table body (without the surrounding markers)."""
    if scenarios is None:
        scenarios = load_corpus_dir()
    total = len(scenarios)
    cats = Counter(s.owasp_category for s in scenarios)
    vectors = Counter(s.delivery_vector for s in scenarios)

    lines: list[str] = []
    lines.append("> **Auto-generated from `corpus/*.yaml` by `neuralstrike readme-mapping`.**")
    lines.append(
        "> Do not hand-edit the table below the markers — regenerate it. "
        "The mapping is real because the corpus is real: every scenario "
        "row is a runnable, deterministic-oracle-scored probe."
    )
    lines.append("")
    lines.append(
        f"The corpus ships **{total} scenarios** across "
        f"{len(cats)} OWASP categories "
        f"({sum(1 for c in cats if c.startswith('ASI'))} ASI + "
        f"{sum(1 for c in cats if c.startswith('LLM'))} LLM), exercising "
        f"{len(vectors)} delivery vectors: "
        + ", ".join(f"`{v}`" for v in sorted(vectors))
        + "."
    )
    lines.append("")
    lines.extend(_category_rows(scenarios))
    lines.append("")
    lines.append(
        "_Each scenario's `success_criteria` reference deterministic oracles "
        "(canary / forbidden-tool / predicate / schema / system-prompt "
        "extraction); the Judge is advisory only and never flips a "
        "deterministic verdict. See `PRODUCTION_ROADMAP.md` §Phase 2._"
    )
    return "\n".join(lines)


def readme_mapping_section(scenarios: list[Scenario] | None = None) -> str:
    """The full replaceable section, including the BEGIN/END markers."""
    return f"{BEGIN_MARKER}\n{readme_mapping_table(scenarios)}\n{END_MARKER}"
