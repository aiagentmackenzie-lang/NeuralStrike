# Assessment report contract (schema 2)

Corpus JSON declares `schema_version: 2`. SARIF remains SARIF 2.1.0 and declares
the NeuralStrike profile in invocation properties. Unversioned legacy reports
remain readable by the dashboard. Unsupported declared profiles are rejected.

Each scenario contains one `trials` entry for each recorded trial. Its verdict
is the canonical trial outcome. Individual oracle annotations live in that
entry's `findings` array and do not add trials, findings counts or coverage.
The primary excerpt comes from a non-advisory oracle matching the displayed
trial outcome. Scenario summaries select the actual worst trial's evidence.
Full inputs, observations and annotations remain under the private `evidence`
run, including error details that presentation excerpts may abbreviate.

An explicit execution error changes negative resistance to Inconclusive.
A confirmed Succeeded observation remains Succeeded when a later step fails;
execution health still records incomplete execution. No format suppresses the
confirmed violation to make a failing transport look like a successful fix.

`overall.total` counts recorded trial outcomes, including errored attempts.
ASR uses Succeeded / (Succeeded + Resisted). With no conclusive trials, exported
ASR, confidence bounds and risk are unavailable (`null`) and human reports say
`unavailable`. The computational ScoreCard keeps its numeric `asr`/risk fields
for API compatibility; use `measured_asr` to distinguish absent measurement.
Coverage is conclusive / recorded trials; selected and attempted counts are
separate health fields. A 100% fraction among recorded outcomes cannot establish
complete selected-plan coverage. Gate on health and policy, not the fraction.

JSON and SARIF carry authoritative overall trial counts and health. JUnit emits
one testcase per recorded trial: Succeeded maps to failure, execution-error
Inconclusive to error, other Inconclusive to skipped, and Resisted to pass.
Suite properties retain canonical counts and assessment health. Skipped tests
alone are insufficient for a security gate: use the CLI exit and health state.
Markdown/PDF show canonical rows and separate oracle annotations. The dashboard
uses canonical totals when available and labels unidentified legacy SARIF rows
as rows; those rows are not evidence of a complete trial count.

All formats identify their output as **private raw evidence**, not sanitized
sharing artifacts. Corpus output files use atomic mode-0600 writes. The separate allowlisted `export-summary` profile omits raw evidence and is
non-replayable; full reports remain unsanitized. PDF provides a text preview using standard fonts;
Unicode/full request fidelity remains in the JSON evidence. No report format is
a redaction boundary or an independently signed provenance statement.

## Provider seed migration

`blake2b-63bit-v2` derives nonnegative seeds fitting signed 64-bit provider fields.
The former unsigned derivation was rejected by the local Ollama endpoint for
base seed 123. Actual runners record the derivation in metadata and modern
comparison identity. Baselines with the old identity require a fresh trusted
reference run after upgrading; retain the old evidence. Do not replace a trusted
reference with a candidate merely to make a comparison pass. A sent seed is a
best-effort control, not proof of a deterministic live rerun.

## Evidence links and provenance

Canonical trials now carry observation `evidence_id`, execution `source_run_id`,
evidence origin and optional receipt ID. JSON/SARIF/JUnit/Markdown/PDF and the
dashboard expose these links; the actual worst trial supplies the displayed
link. Reports include selected scenario/trial scope and limitations, not a
permission attestation. Corpus locations come from the recorded source file,
with a file hash and normalized scenario fingerprint; ID-prefix guesses were
removed. Recorded completion time is retained when available; legacy absence is
explicitly unrecorded. This is an additive report-schema-2 extension, distinct
from the run-manifest schema-2 migration documented in REPLAY.md.

## Assessment-level context

Parent assessment ID, plan digest, original producer version and recorded policy
now travel across report formats and the dashboard. `recorded_gate` describes
the source's standalone policy, not a replay invocation override or a baseline
comparison. Global execution errors force incomplete health and are retained in
limitations and machine properties. JUnit does not invent a failing testcase for
unrecorded work; gate on process exit and assessment-health properties. Selected
scenarios without committed evidence retain `recording_status: missing`, empty
trial lists and zero recorded counts. SARIF rules/scope and the dashboard retain
those missing selections without adding result rows to trial totals.
