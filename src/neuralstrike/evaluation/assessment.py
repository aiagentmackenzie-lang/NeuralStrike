"""Portable, private multi-scenario assessments with a frozen selection plan.

A committed bundle can contain incomplete execution. Its manifest commits bytes;
assessment health and the selected failure policy decide the security gate.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, Literal

import httpx
from pydantic import Field, JsonValue, field_validator

from neuralstrike import __version__
from neuralstrike.corpus.loader import Scenario, SuccessCriterion
from neuralstrike.evaluation.bundle import (
    MAX_BUNDLE_BYTES,
    MAX_TRIALS,
    BundleError,
    VerifiedBundle,
    _Document,
    _json,
    _read,
    load_bundle,
    replay_bundle,
    rescore_verified,
)
from neuralstrike.evaluation.identity import comparison_identity, configuration_digest
from neuralstrike.evaluation.runner import RunMeta, RunReport, _atomic_json, persist_report
from neuralstrike.evaluation.scoring import score_trials
from neuralstrike.oracles.base import Oracle
from neuralstrike.reports.model import CorpusRun, build_corpus_run

MAX_SCENARIOS = 1000


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def target_label(target: str) -> str:
    """Exclude URL credentials, query and fragment from evidence labels."""
    if target.lower().startswith(("http://", "https://")):
        return str(httpx.URL(target).copy_with(username=None, password=None, query=None, fragment=None))
    return target


class _Versioned(_Document):
    schema_version: Literal[1]

    @field_validator("schema_version", mode="before")
    @classmethod
    def exact_version(cls, value: Any) -> Any:
        if type(value) is not int:
            raise ValueError("schema version must be an integer")
        return value


class _Criterion(_Document):
    oracle: str
    severity: str
    forbidden_tools: list[str]
    pattern: str | None
    polarity: str
    schema_definition: dict[str, JsonValue] | None = Field(alias="schema")


class _Scenario(_Document):
    id: str
    owasp_category: str
    owasp_name: str
    mitre_atlas: list[str]
    severity: str
    delivery_vector: Literal["user_message", "tool_result", "retrieved_document", "memory", "system_prompt"]
    intent: str
    legitimate_task: str
    adversarial_payload: str
    success_criteria: list[_Criterion]
    mitigations: list[str]
    benign_task_markers: list[str]
    source_path: str | None
    source_sha256: str | None

    def restore(self) -> Scenario:
        data = self.model_dump(by_alias=True)
        for key in ("mitre_atlas", "mitigations", "benign_task_markers"):
            data[key] = tuple(data[key])
        data["success_criteria"] = tuple(
            SuccessCriterion(
                **{**criterion.model_dump(by_alias=True), "forbidden_tools": tuple(criterion.forbidden_tools)}
            )
            for criterion in self.success_criteria
        )
        return Scenario(**data)


class AssessmentPlan(_Versioned):
    assessment_id: str
    started_at: str
    base_seed: int
    trials: int = Field(ge=1, le=MAX_TRIALS)
    adapter: str
    target: str
    fail_on: Literal["never", "vuln", "regression"]
    scenarios: list[_Scenario] = Field(min_length=1, max_length=MAX_SCENARIOS)
    declared_scope: dict[str, JsonValue]

    def validate_selection(self) -> None:
        ids = [scenario.id for scenario in self.scenarios]
        if len(set(ids)) != len(ids) or len(ids) * self.trials > MAX_TRIALS:
            raise BundleError("duplicate scenarios or oversized assessment trial plan")


class _RunLink(_Document):
    scenario_id: str
    run_id: str
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class _Manifest(_Versioned):
    kind: Literal["neuralstrike-assessment"]
    assessment_id: str
    state: Literal["complete"]
    plan_digest: str
    completed_at: str
    execution_error: str | None
    provenance: dict[str, JsonValue]
    producer_version: str | None = Field(default=None, min_length=1)
    files: dict[str, str]
    runs: list[_RunLink]


@dataclass(frozen=True)
class VerifiedAssessment:
    path: Path
    assessment_id: str
    plan: AssessmentPlan
    report: CorpusRun
    runs: tuple[RunReport, ...]
    manifest_sha256: str
    children: tuple[VerifiedBundle, ...]


def _safe_run_id(run_id: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", run_id):
        raise BundleError("invalid child execution ID")


def _context(plan: AssessmentPlan, report: RunReport) -> None:
    selected = {scenario.id for scenario in plan.scenarios}
    if (
        report.meta.scenario_id not in selected
        or report.meta.base_seed != plan.base_seed
        or report.meta.trials != plan.trials
    ):
        raise BundleError("child run context differs from the frozen assessment plan")
    _safe_run_id(report.meta.run_id)
    expected = next(s for s in plan.scenarios if s.id == report.meta.scenario_id)
    expected_digest = configuration_digest(expected.model_dump(by_alias=True))
    for trial in report.trials:
        scenario = trial.inputs.get("scenario")
        if scenario is not None and configuration_digest(scenario) != expected_digest:
            raise BundleError("recorded scenario context differs from the frozen plan")


def _missing(plan: AssessmentPlan, scenario: Scenario) -> RunReport:
    meta = RunMeta(
        f"missing-{scenario.fingerprint[7:23]}",
        scenario.id,
        plan.base_seed,
        plan.trials,
        0.0,
        0.7,
        plan.started_at,
        category=scenario.owasp_category,
        severity=scenario.severity,
        provenance={"recording_status": "no committed run evidence; execution is not asserted"},
    )
    return RunReport(meta, (), score_trials([]))


def _assemble(
    plan: AssessmentPlan,
    runs: list[RunReport],
    execution_error: str | None,
    producer_version: str = __version__,
) -> CorpusRun:
    by_id = {report.meta.scenario_id: report for report in runs}
    scenarios = [scenario.restore() for scenario in plan.scenarios]
    reports = [by_id.get(scenario.id) or _missing(plan, scenario) for scenario in scenarios]
    report = build_corpus_run(
        scenarios=scenarios,
        reports=reports,
        base_seed=plan.base_seed,
        trials_per_scenario=plan.trials,
        adapter=plan.adapter,
        target=plan.target,
        started_at=plan.started_at,
    )
    health = report.health
    if execution_error and health is not None:
        health = replace(health, complete=False)
    return replace(
        report,
        health=health,
        assessment_id=plan.assessment_id,
        plan_digest=configuration_digest(plan.model_dump(by_alias=True)),
        execution_error=execution_error,
        gate_policy=plan.fail_on,
        tool_version=producer_version,
        declared_scope=plan.declared_scope,
    )


class AssessmentRecorder:
    """Freeze selection before target setup; commit results without shrinking scope."""

    def __init__(
        self,
        root: str | Path,
        *,
        scenarios: list[Scenario],
        base_seed: int,
        trials: int,
        adapter: str,
        target: str,
        fail_on: str,
        declared_scope: dict[str, JsonValue] | None = None,
        provenance: dict[str, JsonValue] | None = None,
    ) -> None:
        assessment_id = f"assessment-{uuid.uuid4().hex}"
        self.plan = AssessmentPlan.model_validate(
            _json(
                json.dumps(
                    {
                        "schema_version": 1,
                        "assessment_id": assessment_id,
                        "started_at": _now(),
                        "base_seed": base_seed,
                        "trials": trials,
                        "adapter": adapter,
                        "target": target_label(target),
                        "fail_on": fail_on,
                        "scenarios": [asdict(scenario) for scenario in scenarios],
                        "declared_scope": declared_scope or {"authorization": "not independently attested"},
                    }
                ).encode()
            )
        )
        self.plan.validate_selection()
        self.path = Path(root) / assessment_id
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.mkdir(mode=0o700, exist_ok=False)
        (self.path / "runs").mkdir(mode=0o700)
        self._runs: list[RunReport] = []
        self._links: list[_RunLink] = []
        self._finished = False
        self._provenance = provenance or {}
        _atomic_json(self.path / "plan.json", self.plan.model_dump(by_alias=True))
        self._commit_manifest(complete=False)

    def _commit_manifest(self, *, complete: bool, execution_error: str | None = None) -> None:
        documents = ["plan.json", "report.json"] if complete else ["plan.json"]
        _atomic_json(
            self.path / "manifest.json",
            {
                "schema_version": 1,
                "kind": "neuralstrike-assessment",
                "assessment_id": self.plan.assessment_id,
                "state": "complete" if complete else "running",
                "plan_digest": configuration_digest(self.plan.model_dump(by_alias=True)),
                "completed_at": _now(),
                "execution_error": execution_error,
                "provenance": self._provenance,
                "producer_version": __version__,
                "files": {name: hashlib.sha256(_read(self.path / name)).hexdigest() for name in documents},
                "runs": [link.model_dump(by_alias=True) for link in self._links],
            },
        )

    def add(self, report: RunReport) -> None:
        if self._finished:
            raise BundleError("assessment is already committed")
        _context(self.plan, report)
        if any(
            r.meta.scenario_id == report.meta.scenario_id or r.meta.run_id == report.meta.run_id
            for r in self._runs
        ):
            raise BundleError("duplicate scenario or child execution")
        if report.score is None:
            report = replace(
                report,
                score=score_trials(
                    report.trials, category_of={report.meta.scenario_id: report.meta.category}
                ),
            )
        child = persist_report(report, self.path / "runs")
        verified = load_bundle(child)
        self._runs.append(verified.report)
        self._links.append(
            _RunLink(
                scenario_id=report.meta.scenario_id,
                run_id=report.meta.run_id,
                manifest_sha256=verified.manifest_sha256,
            )
        )
        self._commit_manifest(complete=False)

    def finish(self, *, execution_error: str | None = None) -> CorpusRun:
        if self._finished:
            raise BundleError("assessment is already committed")
        if {p.name for p in (self.path / "runs").iterdir()} != {link.run_id for link in self._links}:
            raise BundleError("uncommitted child evidence prevents assessment commit")
        report = _assemble(self.plan, self._runs, execution_error, __version__)
        _atomic_json(self.path / "report.json", report.to_dict())
        self._commit_manifest(complete=True, execution_error=execution_error)
        self._finished = True
        return report


def is_assessment_bundle(path: str | Path) -> bool:
    try:
        document = _json(_read(Path(path) / "manifest.json"))
    except BundleError:
        raise
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        raise BundleError("invalid or unreadable bundle manifest") from exc
    return isinstance(document, dict) and document.get("kind") == "neuralstrike-assessment"


def _load_runs(
    path: Path,
    plan: AssessmentPlan,
    manifest: _Manifest,
    size: int,
    *,
    verify_oracles: bool,
) -> list[VerifiedBundle]:
    run_ids = [link.run_id for link in manifest.runs]
    scenario_ids = [link.scenario_id for link in manifest.runs]
    if len(set(run_ids)) != len(run_ids) or len(set(scenario_ids)) != len(scenario_ids):
        raise BundleError("duplicate assessment run links")
    if {p.name for p in (path / "runs").iterdir()} != set(run_ids):
        raise BundleError("missing or unlisted child bundles")
    reports = []
    for link in manifest.runs:
        _safe_run_id(link.run_id)
        child = path / "runs" / link.run_id
        if child.is_symlink() or not child.is_dir():
            raise BundleError("child bundle must be a real directory")
        # Count bytes across the entire assessment, not only per child.
        for item in child.iterdir():
            size += len(_read(item))
            if size > MAX_BUNDLE_BYTES:
                raise BundleError("assessment exceeds total size limit")
        verified = load_bundle(child)
        if (
            verified.manifest_sha256 != link.manifest_sha256
            or verified.report.meta.scenario_id != link.scenario_id
        ):
            raise BundleError("child bundle identity/hash mismatch")
        _context(plan, verified.report)
        if verify_oracles:
            replay_bundle(child, verify_oracles=True)
        reports.append(verified)
    return reports


def _load(path: Path, *, verify_oracles: bool) -> VerifiedAssessment:
    manifest_bytes = _read(path / "manifest.json")
    manifest = _Manifest.model_validate(_json(manifest_bytes))
    if set(manifest.files) != {"plan.json", "report.json"}:
        raise BundleError("invalid assessment file inventory")
    if {p.name for p in path.iterdir()} != {"plan.json", "report.json", "manifest.json", "runs"}:
        raise BundleError("missing or unlisted assessment entries")
    if (path / "runs").is_symlink() or not (path / "runs").is_dir():
        raise BundleError("assessment runs must be a real directory")
    documents = {}
    size = len(manifest_bytes)
    for name, digest in manifest.files.items():
        raw = _read(path / name)
        size += len(raw)
        if hashlib.sha256(raw).hexdigest() != digest:
            raise BundleError("assessment file hash mismatch")
        documents[name] = _json(raw)
    plan = AssessmentPlan.model_validate(documents["plan.json"])
    plan.validate_selection()
    if (
        plan.assessment_id != manifest.assessment_id
        or configuration_digest(plan.model_dump(by_alias=True)) != manifest.plan_digest
    ):
        raise BundleError("assessment plan identity mismatch")
    children = _load_runs(path, plan, manifest, size, verify_oracles=verify_oracles)
    reports = [child.report for child in children]
    stored_report = documents["report.json"]
    if not isinstance(stored_report, dict):
        raise BundleError("invalid assessment summary document")
    producer_version = (
        manifest.producer_version
        if manifest.producer_version is not None
        else stored_report.get("tool_version")
    )
    if type(producer_version) is not str or not producer_version:
        raise BundleError("invalid recorded producer version")
    result = _assemble(plan, reports, manifest.execution_error, producer_version)
    # Recording-status labels are derived metadata added to report schema 2.
    # Preserve known older snapshots without permitting omitted outcomes/evidence.
    for scenario in stored_report.get("scenario_results", []):
        if "recording_status" not in scenario:
            scenario["recording_status"] = "recorded" if scenario.get("trials") else "missing"
    if result.to_dict() != stored_report:
        raise BundleError("assessment summary contradicts its plan or child evidence")
    return VerifiedAssessment(
        path,
        plan.assessment_id,
        plan,
        result,
        tuple(reports),
        hashlib.sha256(manifest_bytes).hexdigest(),
        tuple(children),
    )


def load_assessment(path: str | Path, *, verify_oracles: bool = False) -> VerifiedAssessment:
    try:
        return _load(Path(path), verify_oracles=verify_oracles)
    except BundleError:
        raise
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        raise BundleError(f"invalid or unreadable assessment bundle ({type(exc).__name__})") from exc


def rescore_assessment(
    source: str | Path,
    oracles: list[Oracle],
    *,
    output_root: str | Path,
    oracle_version: str,
    fail_on: str = "vuln",
) -> VerifiedAssessment:
    """Derive every recorded child, retaining missing selections and source errors."""
    source_path, destination = Path(source).resolve(), Path(output_root).resolve()
    if destination == source_path or source_path in destination.parents:
        raise BundleError("derived assessment must be outside the source bundle")
    original = load_assessment(source_path)
    identity = comparison_identity(None, {}, [], oracles)
    if not oracle_version.strip() or not identity["comparable"]:
        raise BundleError("rescoring requires a version and representable oracle identity")
    recorder = AssessmentRecorder(
        destination,
        scenarios=[scenario.restore() for scenario in original.plan.scenarios],
        base_seed=original.plan.base_seed,
        trials=original.plan.trials,
        adapter=original.plan.adapter,
        target=original.plan.target,
        fail_on=fail_on,
        declared_scope=original.plan.declared_scope,
        provenance={
            "operation": "offline-assessment-rescore",
            "source_assessment_id": original.assessment_id,
            "source_manifest_sha256": original.manifest_sha256,
            "oracle_version": oracle_version,
            "oracle_digest": identity["oracle_digest"],
        },
    )
    for child in original.children:
        recorder.add(rescore_verified(child, oracles, oracle_version=oracle_version))
    recorder.finish(execution_error=original.report.execution_error)
    return load_assessment(recorder.path)
