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

from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from typing import Any

from neuralstrike import __version__
from neuralstrike.corpus.loader import Scenario
from neuralstrike.evaluation.health import AssessmentHealth, assessment_health
from neuralstrike.evaluation.runner import RunReport
from neuralstrike.evaluation.runner import _trial_to_dict as serialize_trial
from neuralstrike.evaluation.scoring import score_trials
from neuralstrike.evaluation.verdict import EvidenceFidelity, Finding, Verdict, normalize_trial
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
    findings: tuple[Finding, ...] = field(default_factory=tuple)
    evidence_id: str = ""
    evidence_origin: str = "unverified-observation"
    source_run_id: str = ""
    receipt_id: str | None = None


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
    evidence: dict[str, Any] = field(default_factory=dict)

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
    health: AssessmentHealth | None = None
    completed_at: str | None = None

    @property
    def artifact_policy(self) -> dict[str, Any]:
        return {"classification": "private-raw", "sanitized": False}

    @property
    def assessment_scope(self) -> dict[str, Any]:
        return {
            "adapter": self.adapter,
            "configured_target": self.target,
            "selected_scenarios": [sr.scenario.id for sr in self.scenario_results],
            "planned_trials": len(self.scenario_results) * self.trials_per_scenario,
            "authorization": "not attested by this report",
        }

    @property
    def limitations(self) -> tuple[str, ...]:
        return (
            "Remote builds and authorization are not authenticated by this report.",
            "Delivery observations show the sent channel, not target consumption.",
            "Local canary receipts prove fixture execution, not production side effects.",
            "Hashes detect changed bytes; they do not authenticate the evidence author.",
            "Raw target content is private; report formats are not sanitizers.",
        )

    @property
    def measured_asr(self) -> float | None:
        return self.asr if self.overall_succeeded + self.overall_resisted else None

    @property
    def asr_display(self) -> str:
        return f"{self.asr:.2%}" if self.measured_asr is not None else "unavailable"

    def overall(self) -> dict[str, Any]:
        return {
            "total": self.overall_total,
            "succeeded": self.overall_succeeded,
            "resisted": self.overall_resisted,
            "inconclusive": self.overall_inconclusive,
            "asr": self.measured_asr,
            "coverage": self.coverage,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_policy": self.artifact_policy,
            "assessment_scope": self.assessment_scope,
            "limitations": list(self.limitations),
            "health": self.health.to_dict() if self.health else None,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "base_seed": self.base_seed,
            "trials_per_scenario": self.trials_per_scenario,
            "adapter": self.adapter,
            "target": self.target,
            "schema_version": 2,
            "tool_version": __version__,
            "overall": self.overall(),
            "scenario_results": [_scenario_to_dict(s) for s in self.scenario_results],
        }


def _scenario_to_dict(s: ScenarioResult) -> dict[str, Any]:
    return {
        "id": s.scenario.id,
        "source": {
            "path": s.scenario.source_path,
            "sha256": s.scenario.source_sha256,
            "scenario_fingerprint": s.scenario.fingerprint,
        },
        "evidence": s.evidence,
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
        "evidence_id": t.evidence_id,
        "evidence_origin": t.evidence_origin,
        "source_run_id": t.source_run_id,
        "receipt_id": t.receipt_id,
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
        "findings": [asdict(finding) for finding in t.findings],
    }


def worst_verdict(verdicts: tuple[Verdict, ...]) -> Verdict:
    """The worst conclusive verdict across trials (Succeeded > Inconclusive > Resisted)."""
    if not verdicts:
        return Verdict.INCONCLUSIVE
    rank = {Verdict.RESISTED: 0, Verdict.INCONCLUSIVE: 1, Verdict.SUCCEEDED: 2}
    return max(verdicts, key=lambda v: rank[v])


def _trial_outcomes(report: RunReport) -> tuple[TrialOutcome, ...]:
    out: list[TrialOutcome] = []
    for original in report.trials:
        t = normalize_trial(original)
        matching = [f for f in t.findings if not f.advisory and f.verdict is t.verdict]
        primary = matching[0] if matching else None
        error = t.error or (t.response.error if t.response else None)
        out.append(
            TrialOutcome(
                scenario_id=t.scenario_id,
                trial_index=t.trial_index,
                seed=t.seed,
                verdict=t.verdict,
                fidelity=t.fidelity,
                evidence_quote=primary.evidence_quote if primary else None,
                reason=primary.reason if primary else error or "aggregate trial outcome; see oracle findings",
                severity=primary.severity if primary else "info",
                oracle_id=primary.oracle_id if primary else "(aggregate)",
                advisory=False,
                delivery_channels=_delivery_channels_from_trial(t),
                response_text=t.response.text if t.response else "",
                error=error,
                findings=t.findings,
                evidence_id=serialize_trial(t)["evidence_id"],
                evidence_origin=(
                    primary.evidence_origin
                    if primary and primary.evidence_origin
                    else "captured-provider-response"
                    if t.response and t.response.exchanges
                    else "unverified-observation"
                ),
                source_run_id=report.meta.run_id,
                receipt_id=primary.receipt_id if primary else None,
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


def _recorded_start(reports: list[RunReport], override: str | None) -> str:
    values = [override] if override is not None else [report.meta.started_at for report in reports]
    if not values:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    try:
        timestamps = [datetime.fromisoformat(value.replace("Z", "+00:00")) for value in values]
        if any(timestamp.utcoffset() is None for timestamp in timestamps):
            raise ValueError("timezone missing")
    except ValueError as exc:
        raise ValueError("invalid run start timestamp; an explicit timezone is required") from exc
    return min(timestamps).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _recorded_completion(reports: list[RunReport]) -> str | None:
    if not reports or any(report.meta.completed_at is None for report in reports):
        return None
    completed = []
    for report in reports:
        end = datetime.fromisoformat(str(report.meta.completed_at).replace("Z", "+00:00"))
        start = datetime.fromisoformat(report.meta.started_at.replace("Z", "+00:00"))
        if end.utcoffset() is None or start.utcoffset() is None or end < start:
            raise ValueError("invalid recorded completion timestamp")
        completed.append(end)
    return max(completed).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


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
        raise ValueError(f"scenarios ({len(scenarios)}) and reports ({len(reports)}) must align by index")

    if len({scenario.id for scenario in scenarios}) != len(scenarios):
        raise ValueError("duplicate scenario identities in assessment plan")
    for scenario, report in zip(scenarios, reports, strict=True):
        if report.meta.scenario_id != scenario.id or any(t.scenario_id != scenario.id for t in report.trials):
            raise ValueError(f"scenario/report identity mismatch for {scenario.id}")
        if report.meta.trials != trials_per_scenario:
            raise ValueError(f"scenario trial plan mismatch for {scenario.id}")

    overall_s = overall_r = overall_i = 0
    scenario_results: list[ScenarioResult] = []
    for scenario, source_report in zip(scenarios, reports, strict=True):
        normalized = tuple(normalize_trial(t) for t in source_report.trials)
        report = replace(
            source_report,
            trials=normalized,
            score=score_trials(normalized, category_of={scenario.id: scenario.owasp_category}),
        )
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
                evidence=report.to_dict(),
            )
        )

    total = overall_s + overall_r + overall_i
    conclusive = overall_s + overall_r
    asr = (overall_s / conclusive) if conclusive else 0.0
    coverage = (conclusive / total) if total else 0.0

    return CorpusRun(
        started_at=_recorded_start(reports, started_at),
        completed_at=_recorded_completion(reports),
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
        health=assessment_health(reports, selected=len(scenarios) * trials_per_scenario),
    )
