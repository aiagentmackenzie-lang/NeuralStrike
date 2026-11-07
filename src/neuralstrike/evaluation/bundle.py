"""Strict, offline loading and derived rescoring of private run evidence.

Hashes detect corruption, not a malicious author who can rewrite the manifest.
No stored Python/import path is executed and no target/provider is constructed.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import time
import uuid
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, ValidationError, field_validator

from neuralstrike.evaluation.identity import comparison_identity
from neuralstrike.evaluation.probes import strongest_fidelity
from neuralstrike.evaluation.runner import RunMeta, RunReport, _score_to_dict, _trial_to_dict, persist_report
from neuralstrike.evaluation.scoring import score_trials
from neuralstrike.evaluation.verdict import (
    EvidenceFidelity,
    Finding,
    SutResponse,
    ToolCall,
    TrialResult,
    Verdict,
    normalize_trial,
)
from neuralstrike.oracles.base import Oracle, combine_oracle_results
from neuralstrike.oracles.evidence import upgrade_fidelity_from_traces
from neuralstrike.oracles.recipes import OracleRecipeError, oracle_policy, restore_oracles
from neuralstrike.oracles.tool_harness import TraceLog

MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_BUNDLE_BYTES = 256 * 1024 * 1024
MAX_TRIALS = 10000


class BundleError(ValueError):
    """Incomplete, incompatible, inconsistent or corrupt run evidence."""


class _Document(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)


class _Manifest(_Document):
    schema_version: Literal[1, 2]
    run_id: str
    state: Literal["complete"]
    comparison_key: str
    comparison_key_scope: str
    expected_trials: int = Field(ge=1, le=MAX_TRIALS)
    files: dict[str, str]
    evidence_policy: str

    @field_validator("schema_version", mode="before")
    @classmethod
    def exact_version(cls, value: Any) -> Any:
        if type(value) is not int:
            raise ValueError("schema version must be an integer")
        return value


class _Meta(_Document):
    run_id: str
    scenario_id: str
    base_seed: int
    trials: int = Field(ge=1, le=MAX_TRIALS)
    victim_temperature: float
    attacker_temperature: float
    started_at: str
    judge_model: str | None = None
    attacker_model: str | None = None
    intensity: str = "standard"
    comparison_identity: dict[str, Any] = Field(default_factory=dict)
    seed_derivation: str | None = None
    category: str = "uncategorized"
    severity: str = "high"
    provenance: dict[str, Any] = Field(default_factory=dict)
    completed_at: str | None = None


class _ToolCall(_Document):
    name: str
    arguments: JsonValue = None
    tool_call_id: str | None = None


class _Finding(_Document):
    oracle_id: str
    verdict: Literal["resisted", "succeeded", "inconclusive"]
    fidelity: Literal["verbal", "intent_to_act", "behavioral"]
    evidence_quote: str | None
    reason: str
    severity: str
    advisory: bool
    tool_name: str | None = None
    tool_call_id: str | None = None
    arguments_digest: str | None = None
    receipt_id: str | None = None
    evidence_origin: str | None = None


class _Score(_Document):
    total: int
    resisted: int
    succeeded: int
    inconclusive: int
    asr: float | None
    asr_ci_low: float | None
    asr_ci_high: float | None
    coverage: float
    risk_index: float | None
    flaky: bool
    per_category: dict[str, float]
    per_category_counts: dict[str, list[int]]
    headline: str


class _Trial(_Document):
    trial_index: int = Field(ge=0)
    scenario_id: str
    seed: int
    temperature: float
    verdict: Literal["resisted", "succeeded", "inconclusive"]
    fidelity: Literal["verbal", "intent_to_act", "behavioral"]
    payload: str
    inputs: dict[str, JsonValue]
    exchanges: list[dict[str, JsonValue]]
    response_present: bool | None = None
    response_text: str
    tool_calls: list[_ToolCall]
    traces: list[dict[str, JsonValue]]
    response_error: str | None
    error: str | None
    iterations: int = Field(ge=0)
    trajectory_fingerprint: str
    findings: list[_Finding]
    evidence_id: str | None = None
    oracle_policy: dict[str, Any] = Field(default_factory=dict)

    def result(self) -> TrialResult:
        # Schema 1 did not distinguish an absent response from an empty one.
        present = (
            self.response_present
            if self.response_present is not None
            else bool(
                self.response_text or self.tool_calls or self.traces or self.exchanges or self.response_error
            )
        )
        response = (
            SutResponse(
                text=self.response_text,
                tool_calls=tuple(ToolCall(**call.model_dump()) for call in self.tool_calls),
                traces=tuple(self.traces),
                error=self.response_error,
                exchanges=tuple(self.exchanges),
            )
            if present
            else None
        )
        if not present and any(
            (self.response_text, self.tool_calls, self.traces, self.exchanges, self.response_error)
        ):
            raise BundleError("absent response contradicts recorded response evidence")
        TraceLog.from_list(tuple(self.traces))
        findings = tuple(
            Finding(
                oracle_id=f.oracle_id,
                verdict=Verdict(f.verdict),
                fidelity=EvidenceFidelity(f.fidelity),
                evidence_quote=f.evidence_quote,
                reason=f.reason,
                severity=f.severity,
                advisory=f.advisory,
                tool_name=f.tool_name,
                tool_call_id=f.tool_call_id,
                arguments_digest=f.arguments_digest,
                receipt_id=f.receipt_id,
                evidence_origin=f.evidence_origin,
            )
            for f in self.findings
        )
        result = TrialResult(
            trial_index=self.trial_index,
            seed=self.seed,
            temperature=self.temperature,
            verdict=Verdict(self.verdict),
            fidelity=EvidenceFidelity(self.fidelity),
            findings=findings,
            payload=self.payload,
            inputs=dict(self.inputs),
            oracle_policy=self.oracle_policy,
            response=response,
            error=self.error,
            scenario_id=self.scenario_id,
            iterations=self.iterations,
            trajectory_fingerprint=self.trajectory_fingerprint,
        )
        if normalize_trial(result) != result:
            raise BundleError("recorded negative outcome contradicts execution error")
        if self.evidence_id is not None and self.evidence_id != _trial_to_dict(result)["evidence_id"]:
            raise BundleError("observation evidence ID mismatch")
        return result


@dataclass(frozen=True)
class VerifiedBundle:
    """Verified bytes reconstructed as data; not an authenticity attestation."""

    report: RunReport
    manifest_sha256: str
    schema_version: int
    limitations: tuple[str, ...]


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BundleError("duplicate JSON object key")
        result[key] = value
    return result


def _read(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
            raise BundleError("bundle entry is not a bounded regular file")
        data = stream.read(MAX_FILE_BYTES + 1)
        if len(data) > MAX_FILE_BYTES:
            raise BundleError("bundle file exceeds size limit")
        return data


def _json(data: bytes) -> Any:
    document = json.loads(data, object_pairs_hook=_unique_object)

    # Python's JSON parser accepts NaN/Infinity; the wire contract does not.
    def finite(value: Any) -> None:
        if isinstance(value, float) and not math.isfinite(value):
            raise BundleError("nonfinite JSON number")
        if isinstance(value, dict):
            for item in value.values():
                finite(item)
        if isinstance(value, list):
            for item in value:
                finite(item)

    finite(document)
    return document


def _category(meta: RunMeta, report: dict[str, Any], version: int) -> str:
    if version == 2 or "category" in report["meta"]:
        return meta.category
    # Old runner wrote one scenario/run and retained the category in its score.
    categories = report.get("score", {}).get("per_category_counts", {})
    if not categories and report["score"]["succeeded"] + report["score"]["resisted"] == 0:
        return "uncategorized"  # Legacy zero-coverage bundles did not retain a category.
    if len(categories) != 1:
        raise BundleError("legacy bundle has no unambiguous scoring category")
    return str(next(iter(categories)))


def _verified_documents(directory: Path, manifest: _Manifest, manifest_bytes: bytes) -> dict[str, Any]:
    expected = {"meta.json", "report.json", *(f"trial-{i}.json" for i in range(manifest.expected_trials))}
    if set(manifest.files) != expected:
        raise BundleError("manifest file inventory does not match the declared trial plan")
    if {entry.name for entry in directory.iterdir()} != expected | {"manifest.json"}:
        raise BundleError("bundle contains missing or unlisted entries")
    documents: dict[str, Any] = {}
    size = len(manifest_bytes)
    for name, digest in manifest.files.items():
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise BundleError("invalid manifest digest")
        data = _read(directory / name)
        size += len(data)
        if size > MAX_BUNDLE_BYTES:
            raise BundleError("bundle exceeds total size limit")
        if hashlib.sha256(data).hexdigest() != digest:
            raise BundleError("bundle file hash mismatch")
        documents[name] = _json(data)
    return documents


def _load(directory: Path) -> VerifiedBundle:
    manifest_bytes = _read(directory / "manifest.json")
    manifest = _Manifest.model_validate(_json(manifest_bytes))
    documents = _verified_documents(directory, manifest, manifest_bytes)
    meta_document = _Meta.model_validate(documents["meta.json"])
    meta = RunMeta(**meta_document.model_dump())
    if meta.run_id != manifest.run_id or meta.trials != manifest.expected_trials:
        raise BundleError("manifest execution identity or plan mismatch")
    comparison_key = hashlib.sha256(
        json.dumps(
            {
                "seed": meta.base_seed,
                "scenario": meta.scenario_id,
                "intensity": meta.intensity,
                "identity": meta.comparison_identity,
            },
            sort_keys=True,
        ).encode()
    ).hexdigest()
    if comparison_key != manifest.comparison_key:
        raise BundleError("comparison identity mismatch")
    document = documents["report.json"]
    if not isinstance(document, dict) or set(document) != {"meta", "trials", "score"}:
        raise BundleError("invalid report document")
    if document["meta"] != documents["meta.json"]:
        raise BundleError("report metadata mismatch")
    trial_documents = [documents[f"trial-{i}.json"] for i in range(meta.trials)]
    if document["trials"] != trial_documents:
        raise BundleError("report/trial evidence mismatch")
    trials = tuple(_Trial.model_validate(t) for t in trial_documents)
    if manifest.schema_version == 2 and any(
        t.evidence_id is None or t.response_present is None for t in trials
    ):
        raise BundleError("schema-2 trial lacks observation identity or response presence")
    if manifest.schema_version == 2 and not {"category", "severity", "provenance"}.issubset(
        documents["meta.json"]
    ):
        raise BundleError("schema-2 metadata lacks scoring context")
    if any(t.trial_index != i or t.scenario_id != meta.scenario_id for i, t in enumerate(trials)):
        raise BundleError("trial identity does not match the declared plan")
    _Score.model_validate(document["score"])
    category = _category(meta, document, manifest.schema_version)
    meta = replace(meta, category=category)
    results = tuple(t.result() for t in trials)
    score = score_trials(results, category_of={meta.scenario_id: category})
    if document["score"] != _score_to_dict(score):
        raise BundleError("recorded score contradicts trial outcomes")
    limitations: tuple[str, ...] = ("hashes establish byte consistency, not author authenticity",)
    if manifest.schema_version == 1:
        limitations += ("legacy schema lacks explicit response-presence/scoring-context guarantees",)
    return VerifiedBundle(
        RunReport(meta, results, score),
        hashlib.sha256(manifest_bytes).hexdigest(),
        manifest.schema_version,
        limitations,
    )


def load_bundle(directory: str | Path) -> VerifiedBundle:
    """Read only complete, bounded, hash-checked known-schema bundles."""
    try:
        return _load(Path(directory))
    except BundleError:
        raise
    except (OSError, ValueError, TypeError, KeyError, RecursionError, ValidationError) as exc:
        # Do not echo raw validation inputs, which can contain sensitive evidence.
        raise BundleError(f"invalid or unreadable run bundle ({type(exc).__name__})") from exc


def _rescore_trial(trial: TrialResult, oracles: list[Oracle]) -> TrialResult:
    checks = [oracle.check(trial.response) for oracle in oracles] if trial.response is not None else []
    verdict, fidelity, findings = combine_oracle_results(checks)
    if trial.response is not None:
        trace = TraceLog.from_list(trial.response.traces)
        findings = upgrade_fidelity_from_traces(findings, trial.response, trace)
    return normalize_trial(
        replace(
            trial,
            verdict=verdict,
            fidelity=strongest_fidelity(findings) if findings else fidelity,
            findings=tuple(findings),
            oracle_policy=oracle_policy(oracles),
        )
    )


def replay_bundle(directory: str | Path, *, verify_oracles: bool = False) -> RunReport:
    """Recompute recorded scores, optionally verifying the original local policy."""
    report = load_bundle(directory).report
    if verify_oracles:
        try:
            for trial in report.trials:
                oracles = restore_oracles(trial.oracle_policy)
                verified = _rescore_trial(trial, oracles)
                if (verified.verdict, verified.fidelity, verified.findings) != (
                    trial.verdict,
                    trial.fidelity,
                    trial.findings,
                ):
                    raise BundleError("original oracle evaluation does not match recorded outcomes")
        except OracleRecipeError as exc:
            raise BundleError(f"original oracle verification failed: {exc}") from exc
        except Exception as exc:
            raise BundleError(
                "original oracle verification failed; invalid policy or unavailable implementation"
            ) from exc
    return report


def rescore_bundle(
    directory: str | Path,
    oracles: list[Oracle],
    *,
    output_root: str | Path,
    oracle_version: str,
) -> RunReport:
    """Apply explicitly supplied local oracles and persist a new derived run.

    Never imports oracle code from the bundle. Callers supply trusted Python
    oracle objects; the CLI offers only built-in deterministic policies.
    """
    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    source = Path(directory).resolve()
    destination = Path(output_root).resolve()
    if destination == source or source in destination.parents:
        raise BundleError("derived output must be outside the source bundle")
    bundle = load_bundle(source)
    report = rescore_verified(bundle, oracles, oracle_version=oracle_version, started_at=started_at)
    persist_report(report, destination)
    return report


def rescore_verified(
    bundle: VerifiedBundle,
    oracles: list[Oracle],
    *,
    oracle_version: str,
    started_at: str | None = None,
) -> RunReport:
    """Derive from already verified observations without writing or target calls."""
    started_at = started_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    identity = comparison_identity(None, {}, [], oracles)
    if not identity["comparable"] or not oracle_version.strip():
        raise BundleError("rescoring requires a version and representable oracle identity")
    try:
        results = [_rescore_trial(trial, oracles) for trial in bundle.report.trials]
    except Exception as exc:
        raise BundleError("local oracle evaluation failed; no derived report committed") from exc
    meta = replace(
        bundle.report.meta,
        run_id=f"rescore-{uuid.uuid4().hex}",
        started_at=started_at,
        completed_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        comparison_identity={
            **bundle.report.meta.comparison_identity,
            "oracle_digest": identity["oracle_digest"],
            "oracle_composition_digest": identity["oracle_composition_digest"],
        },
        provenance={
            "operation": "offline-rescore",
            "source_run_id": bundle.report.meta.run_id,
            "source_manifest_sha256": bundle.manifest_sha256,
            "oracle_version": oracle_version,
            "oracle_digest": identity["oracle_digest"],
            "execution": "caller-supplied local oracle objects; no target constructed",
        },
    )
    return RunReport(
        meta, tuple(results), score_trials(results, category_of={meta.scenario_id: meta.category})
    )
