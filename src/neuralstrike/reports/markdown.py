"""Markdown report writer.

Emits a human-readable Markdown report from a
:class:`~neuralstrike.reports.model.CorpusRun`. Each scenario is a section
with its OWASP/ATLAS mapping, delivery vector, per-trial verdicts, and the
compliance controls it implicates. Succeeded findings are flagged; Resisted
trials are noted; Inconclusive trials are explicitly marked as coverage
gaps (surfaced, not dropped).
"""

from __future__ import annotations

from neuralstrike.evaluation.verdict import Verdict
from neuralstrike.reports.model import CorpusRun, ScenarioResult

__all__ = ["to_markdown"]


def _verdict_emoji(v: Verdict) -> str:
    if v is Verdict.SUCCEEDED:
        return "❌ Succeeded"
    if v is Verdict.INCONCLUSIVE:
        return "⚠️ Inconclusive"
    return "✅ Resisted"


def _scenario_section(sr: ScenarioResult) -> str:
    s = sr.scenario
    atlas = ", ".join(s.mitre_atlas) if s.mitre_atlas else "—"
    controls = sr.controls
    owasp_line = f"**{s.owasp_category} — {s.owasp_name}**"
    lines = [
        f"### `{s.id}` — {owasp_line}",
        "",
        f"- **Intent:** {s.intent}",
        f"- **MITRE ATLAS:** {atlas}",
        f"- **Delivery vector:** `{s.delivery_vector}`",
        f"- **Severity:** {s.severity}",
        f"- **Aggregate verdict:** {_verdict_emoji(sr.verdict)} "
        f"({sr.succeeded} succeeded / {sr.resisted} resisted / {sr.inconclusive} inconclusive)",
        "- **Compliance controls:**",
    ]
    if controls:
        for c in controls:
            lines.append(f"  - `{c.framework}` `{c.control_id}` — {c.control_name}")
    else:
        lines.append("  - _no controls mapped_")
    lines.append("")
    lines.append("| Trial | Oracle | Verdict | Fidelity | Evidence |")
    lines.append("|------:|--------|---------|----------|----------|")
    for t in sr.trials:
        ev = (t.evidence_quote or "").replace("|", "\\|").replace("\n", " ")
        if len(ev) > 80:
            ev = ev[:77] + "..."
        reason = (t.reason or "").replace("|", "\\|").replace("\n", " ")
        if len(reason) > 60:
            reason = reason[:57] + "..."
        lines.append(
            f"| {t.trial_index} | `{t.oracle_id}` | {_verdict_emoji(t.verdict)} "
            f"| {t.fidelity.value} | {escape_md(ev or reason)} |"
        )
    lines.append("")
    if s.mitigations:
        lines.append("**Mitigations:**")
        for m in s.mitigations:
            lines.append(f"- {m}")
        lines.append("")
    return "\n".join(lines)


def escape_md(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def to_markdown(run: CorpusRun) -> str:
    """Render the corpus run as a Markdown document."""
    header = [
        "# NeuralStrike Corpus Run Report",
        "",
        f"- **Started:** {run.started_at}",
        f"- **Adapter:** `{run.adapter}` — target: `{run.target}`",
        f"- **Base seed:** {run.base_seed} · **Trials per scenario:** {run.trials_per_scenario}",
        f"- **Overall:** {run.overall_total} trials — "
        f"{run.overall_succeeded} succeeded · {run.overall_resisted} resisted · "
        f"{run.overall_inconclusive} inconclusive",
        f"- **ASR (conclusive-only):** {run.asr:.2%} · **Coverage:** {run.coverage:.2%}",
        "",
        "Verdict legend: ❌ Succeeded (exploitable) · ✅ Resisted · "
        "⚠️ Inconclusive (coverage gap, surfaced not dropped).",
        "",
        "---",
        "",
    ]
    sections = [_scenario_section(sr) for sr in run.scenario_results]
    return "\n".join(header) + "\n".join(sections)
