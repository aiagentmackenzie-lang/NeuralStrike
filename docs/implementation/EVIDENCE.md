# Phase 0 evidence contract

`scan` and `corpus` preserve private per-scenario evidence under
`runs/<unique-run-id>/` (override with `--run-dir`). Corpus JSON also embeds the
original run under each scenario's `evidence` key. Run manifests enumerate hashed
files. A manifest's `complete` state means persistence finished; it does not mean
assessment coverage was complete or the target was secure. Execution health is
reported separately.

OpenAI-compatible evidence includes sent request JSON for every round, returned
JSON and HTTP status/errors, alongside adapter inputs and execution/delivery
traces. Each request is captured before the next round alters its messages.
Headers and URL userinfo/query/fragment are excluded; raw request/response bodies may
contain sensitive target data. Directories use mode 0700 and files 0600 on POSIX.
Corpus reports use atomic private writes. These files are **private raw evidence**.
Use `export-summary` for a validated allowlisted, non-replayable sharing summary;
do not treat full report formats as sanitizers. Embedding or publishing the JSON can disclose target content.

Runner seeds/temperatures are task-local and supplied to supported OpenAI and
LiteLLM requests. Recording a sent seed does not prove a provider honored it or
that a live rerun will match. Other adapters currently preserve planned inputs,
not complete provider envelopes. Integrity-checked offline replay and derived
rescoring are now available for per-run bundles; see REPLAY.md for modes and
compatibility limits.

Modern adapter baselines bind scenario, target configuration, tool definitions,
oracle configuration and implementation digests. Credentials are excluded from
target configuration. Remote application builds are not authenticated by these
digests. Different configuration or missing modern identity is non-comparable;
regenerate old scan baselines with the current command before using them to gate.
Programmatic legacy baselines remain readable but lack those assurances.

Schema 2 reports separate canonical trial outcomes from oracle annotations and
label their content private/raw. Zero-conclusive exported measurements are null;
human summaries say unavailable. See REPORT_CONTRACT.md for the migration and
JUnit semantics. Seed derivation is now versioned and bounded to signed-64-bit
provider compatibility; old modern baseline identities require a trusted rerun.

Imported pack comparisons additionally bind the ordered selected probe plan,
complete probe fields, model/local endpoint, iteration budget and judge identity.
Changing `--limit` cannot reuse the comparison scope of the full plan. Duplicate
probe IDs and portable baseline filename collisions are rejected before model
setup. Pack judge decisions remain advisory benchmark evidence; recorded planned
inputs do not establish provider delivery or an application boundary violation.

New baseline snapshots declare schema 1, reference their source execution ID and
use atomic mode-0600 writes. Declared schemas require their comparison metadata;
unsupported versions are rejected. Unversioned legacy snapshots remain readable
with their documented weaker guarantees. Replacing a baseline is an explicit
reference update, not an immutable run-evidence write; retain trusted references.
Smoke, NeuralGuard benchmark and purple-report JSON exports also use private
atomic writes. This does not make optional integration state or raw bodies safe
to publish.

Phase 1 run manifests now declare schema 2, retain completion/scoring context and
separate observation IDs from evaluation policies. Behavioral promotion requires
an exact call ID/name/argument digest and a unique local receipt; prose and legacy
unbound traces cannot promote fidelity. Reports retain the receipt origin so
local fixture execution is not mistaken for production side effects. Corpus
sources record their actual portable file path, file hash and normalized scenario
fingerprint. Baselines whose scenario/oracle identities changed require a trusted
reference rerun; preserve the old evidence rather than overwriting it to pass.

Corpus execution now also preserves a self-contained assessment-level bundle
with a frozen complete selection plan and hashed child bundles. Persistence
completion and security completeness are separate. Missing children retain
selected scope, no fabricated attempts and incomplete health; global execution
errors cannot disappear during replay/rescore. REPLAY.md documents profile
versions, producer-version preservation and bounded compatibility behavior.
