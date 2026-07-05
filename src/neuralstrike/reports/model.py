"""Report model — aggregate a corpus run into one reportable structure.

A *corpus run* drives every :class:`~neuralstrike.corpus.loader.Scenario`
in the corpus through an adapter and collects one
:class:`~neuralstrike.evaluation.runner.RunReport` per scenario. This
module aggregates those into a :class:`CorpusRun` — the single structure
every report format (JSON / SARIF / JUnit / Markdown / PDF) serializes.

Design notes:

- The :class:`CorpusRun` is **transport-agnostic and format-agnostic**. It
  carries the scenario metadata + the per-trial verdicts + findings +
  the compliance crosswalk for each scenario. A format writer is a pure
  ``CorpusRun -> str | bytes`` function.
- Findings are surfaced per the conclusive-only contract: Succeeded and
  Inconclusive trials produce report entries; Resisted trials are
  recorded (the SUT resisted) but are not "findings" in the audit sense.
  Inconclusive probes are surfaced (SARIF ``note``, JUnit skipped-with-
  reason) — never dropped — per the Phase 2 exit-gate requirement.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from neuralstrike.corpus.loader import Scenario
from neuralstrike.evaluation.runner import RunReport
from neuralstrike.evaluation.verdict import EvidenceFidelity, Verdict
from neuralstrike.reports.compliance import ControlRef, crosswalk

__all__ = [
    "CorpusRun",
    "ScenarioResult",
    "TrialOutcome",
    "build_corpus_run",
    "worst_verdict",
]


@dataclass(frozen=True)
class TrialOutcome:
    """One trial's contribution to a report, with the compliance crosswalk."""

    scenario_id: str
    trial_index: int
    seed: int
    verdict: Verdict
    fidelity: EvidenceFidelity
    evidence_quote: str | None
    reason: str
    severity: str
    oracle_id: str
    advisory: bool
    delivery_channels: tuple[str, ...]
    response_text: str
    error: str | None


@dataclass(frozen=True)
class ScenarioResult:
    """One scenario's aggregated result across its trials."""

    scenario: Scenario
    verdict: Verdict  # worst (Succeeded > Inconclusive > Resisted) across trials
    succeeded: int
    resisted: int
    inconclusive: int
    total: int
    trials: tuple[TrialOutcome, ...]
    controls: tuple[ControlRef, ...] = field(default_factory=tuple)

    @property
    def is_finding(self) -> bool:
        """True if this scenario produced a Succeeded trial (an exploitable finding)."""
        return self.verdict is Verdict.SUCCEEDED


@dataclass(frozen=True)
class CorpusRun:
    """The full reportable result of a corpus run."""

    started_at: str
    base_seed: int
    trials_per_scenario: int
    adapter: str
    target: str
    scenario_results: tuple[ScenarioResult, ...]
    overall_succeeded: int
    overall_resisted: int
    overall_inconclusive: int
    overall_total: int
    asr: float
    coverage: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "started_at": self.started_at,
            "base_seed": self.base_seed,
            "trials_per_scenario": self.trials_per_scenario,
            "adapter": self.adapter,
            "target": self.target,
            "overall": {
                "total": self.overall_total,
                "succeeded": self.overall_succeeded,
                "resisted": self.overall_resisted,
                "inconclusive": self.overall_inconclusive,
                "asr": self.asr,
                "coverage": self.coverage,
            },
            "scenario_results": [_scenario_to_dict(s) for s in self.scenario_results],
        }


def _scenario_to_dict(s: ScenarioResult) -> dict[str, Any]:
    return {
        "id": s.scenario.id,
        "owasp_category": s.scenario.owasp_category,
        "owasp_name": s.scenario.owasp_name,
        "mitre_atlas": list(s.scenario.mitre_atlas),
        "severity": s.scenario.severity,
        "delivery_vector": s.scenario.delivery_vector,
        "intent": s.scenario.intent,
        "verdict": s.verdict.value,
        "counts": {
            "succeeded": s.succeeded,
            "resisted": s.resisted,
            "inconclusive": s.inconclusive,
            "total": s.total,
        },
        "controls": [c.to_dict() for c in s.controls],
        "trials": [_trial_to_dict(t) for t in s.trials],
        "mitigations": list(s.scenario.mitigations),
    }


def _trial_to_dict(t: TrialOutcome) -> dict[str, Any]:
    return {
        "scenario_id": t.scenario_id,
        "trial_index": t.trial_index,
        "seed": t.seed,
        "verdict": t.verdict.value,
        "fidelity": t.fidelity.value,
        "evidence_quote": t.evidence_quote,
        "reason": t.reason,
        "severity": t.severity,
        "oracle_id": t.oracle_id,
        "advisory": t.advisory,
        "delivery_channels": list(t.delivery_channels),
        "response_text": t.response_text,
        "error": t.error,
    }


def worst_verdict(verdicts: tuple[Verdict, ...]) -> Verdict:
    """The worst conclusive verdict across trials (Succeeded > Inconclusive > Resisted)."""
    if not verdicts:
        return Verdict.INCONCLUSIVE
    rank = {Verdict.RESISTED: 0, Verdict.INCONCLUSIVE: 1, Verdict.SUCCEEDED: 2}
    return max(verdicts, key=lambda v: rank[v])


def _trial_outcomes(report: RunReport) -> tuple[TrialOutcome, ...]:
    out: list[TrialOutcome] = []
    for t in report.trials:
        # A trial may carry multiple findings; surface each as its own outcome
        # line so the report cites per-oracle evidence. When there are no
        # findings (e.g. a victim-error Inconclusive), surface one outcome
        # with the trial's verdict.
        if not t.findings:
            out.append(
                TrialOutcome(
                    scenario_id=t.scenario_id,
                    trial_index=t.trial_index,
                    seed=t.seed,
                    verdict=t.verdict,
                    fidelity=t.fidelity,
                    evidence_quote=None,
                    reason=t.error or "no oracle findings",
                    severity="info",
                    oracle_id="(none)",
                    advisory=False,
                    delivery_channels=_delivery_channels_from_trial(t),
                    response_text=t.response.text if t.response else "",
                    error=t.error,
                )
            )
            continue
        for f in t.findings:
            out.append(
                TrialOutcome(
                    scenario_id=t.scenario_id,
                    trial_index=t.trial_index,
                    seed=t.seed,
                    verdict=f.verdict,
                    fidelity=f.fidelity,
                    evidence_quote=f.evidence_quote,
                    reason=f.reason,
                    severity=f.severity,
                    oracle_id=f.oracle_id,
                    advisory=f.advisory,
                    delivery_channels=_delivery_channels_from_trial(t),
                    response_text=t.response.text if t.response else "",
                    error=t.error,
                )
            )
    return tuple(out)


def _delivery_channels_from_trial(t: Any) -> tuple[str, ...]:
    channels: list[str] = []
    if t.response is None:
        return ()
    for rec in t.response.traces:
        if isinstance(rec, dict) and "delivery" in rec:
            d = rec["delivery"]
            if isinstance(d, dict) and d.get("present"):
                ch = d.get("channel")
                if isinstance(ch, str) and ch not in channels:
                    channels.append(ch)
    return tuple(channels)


def build_corpus_run(
    *,
    scenarios: list[Scenario],
    reports: list[RunReport],
    base_seed: int,
    trials_per_scenario: int,
    adapter: str,
    target: str,
    started_at: str | None = None,
) -> CorpusRun:
    """Aggregate per-scenario RunReports into a :class:`CorpusRun`.

    ``scenarios`` and ``reports`` must be aligned by index (one report per
    scenario). The caller is responsible for the alignment; this function
    raises if the counts differ.
    """
    if len(scenarios) != len(reports):
        raise ValueError(
            f"scenarios ({len(scenarios)}) and reports ({len(reports)}) must align by index"
        )

    overall_s = overall_r = overall_i = 0
    scenario_results: list[ScenarioResult] = []
    for scenario, report in zip(scenarios, reports, strict=True):
        verdicts = tuple(t.verdict for t in report.trials)
        verdict = worst_verdict(verdicts)
        s = sum(1 for v in verdicts if v is Verdict.SUCCEEDED)
        r = sum(1 for v in verdicts if v is Verdict.RESISTED)
        i = sum(1 for v in verdicts if v is Verdict.INCONCLUSIVE)
        overall_s += s
        overall_r += r
        overall_i += i
        controls = tuple(crosswalk(scenario.owasp_category, scenario.mitre_atlas))
        scenario_results.append(
            ScenarioResult(
                scenario=scenario,
                verdict=verdict,
                succeeded=s,
                resisted=r,
                inconclusive=i,
                total=len(verdicts),
                trials=_trial_outcomes(report),
                controls=controls,
            )
        )

    total = overall_s + overall_r + overall_i
    conclusive = overall_s + overall_r
    asr = (overall_s / conclusive) if conclusive else 0.0
    coverage = (conclusive / total) if total else 0.0

    return CorpusRun(
        started_at=started_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        base_seed=base_seed,
        trials_per_scenario=trials_per_scenario,
        adapter=adapter,
        target=target,
        scenario_results=tuple(scenario_results),
        overall_succeeded=overall_s,
        overall_resisted=overall_r,
        overall_inconclusive=overall_i,
        overall_total=total,
        asr=asr,
        coverage=coverage,
    )
