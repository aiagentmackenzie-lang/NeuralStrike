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
        f"- **Source:** {s.source_path or 'unrecorded'} ({s.fingerprint})",
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
    lines.extend(_trial_annotations(sr))
    if s.mitigations:
        lines.append("**Mitigations:**")
        for m in s.mitigations:
            lines.append(f"- {m}")
        lines.append("")
    return "\n".join(lines)


def _trial_annotations(sr: ScenarioResult) -> list[str]:
    lines: list[str] = []
    for t in sr.trials:
        lines.append(f"Evidence {t.evidence_id}; origin: {t.evidence_origin}; run: {t.source_run_id}.")
        if t.receipt_id:
            lines.append(f"Local fixture receipt: {t.receipt_id}.")
        if t.error:
            lines.append(f"Execution error for trial {t.trial_index}: {escape_md(t.error)}")
        if t.findings:
            lines.append(f"Oracle annotations for trial {t.trial_index} (do not count as trials):")
            for finding in t.findings:
                lines.append(
                    f"- `{finding.oracle_id}`: {finding.verdict.value} "
                    f"{'(advisory) ' if finding.advisory else ''}{escape_md(finding.reason)}"
                )
            lines.append("")
    return lines


def escape_md(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def to_markdown(run: CorpusRun) -> str:
    """Render the corpus run as a Markdown document."""
    header = [
        "# NeuralStrike Corpus Run Report",
        "",
        "- **Handling:** Private raw evidence; not sanitized for sharing.",
        f"- **Assessment health:** {run.health.status if run.health else 'unavailable'}",
        f"- **Started:** {run.started_at}",
        f"- **Completed:** {run.completed_at or 'unrecorded'}",
        f"- **Scope:** {len(run.scenario_results)} selected scenarios; "
        f"{run.assessment_scope['planned_trials']} planned trials; authorization not attested.",
        "- **Limitations:** " + " ".join(run.limitations),
        f"- **Adapter:** `{run.adapter}` — target: `{run.target}`",
        f"- **Base seed:** {run.base_seed} · **Trials per scenario:** {run.trials_per_scenario}",
        f"- **Overall:** {run.overall_total} trials — "
        f"{run.overall_succeeded} succeeded · {run.overall_resisted} resisted · "
        f"{run.overall_inconclusive} inconclusive",
        f"- **ASR (conclusive-only):** {run.asr_display} · **Coverage:** {run.coverage:.2%}",
        "",
        "Verdict legend: ❌ Succeeded (exploitable) · ✅ Resisted · "
        "⚠️ Inconclusive (coverage gap, surfaced not dropped).",
        "",
        "---",
        "",
    ]
    sections = [_scenario_section(sr) for sr in run.scenario_results]
    return "\n".join(header) + "\n".join(sections)
