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

## Where evidence lives, and where it may not

**The declared durable root is `~/Documents/Codex/2026-11-08/neuralstrike-phase3`** (on this
machine: `/Users/agentmackenzie/Documents/Codex/2026-11-08/neuralstrike-phase3`). Review packets,
native observations, receipts and isolated environments that a reviewer is expected to open live
there, outside the repository, because they are private raw evidence and must not be committed.

### The rule

- A document may describe a path under `/tmp` **as an instruction** — a command you are about to
  run — inside a fenced code block. That is a scratch location by design.
- A document may **not** cite `/tmp` as the location where a record is preserved. If a reviewer
  is told to open it, it must be under the durable root.
- `docs/implementation/PROGRESS.md` is a dated history of what ran and where. Its `/tmp` paths are
  records of the truth at the time, not citations; rewriting them would falsify the log. It is
  exempt by name and by nothing else.
- `tests/test_evidence_paths.py` enforces the first three rules: it strips fenced code blocks and
  `PROGRESS.md`, then fails on any surviving `/tmp` reference in any document.

### Evidence that is gone

This repository has lost `/tmp` evidence twice, and both losses are recorded rather than
papered over:

| Artefact | Cited from | State |
|---|---|---|
| `/tmp/neuralstrike-agentdojo-observations` — the two exploratory AgentDojo trials (non-prefetched benign, later replacement-bill) excluded from the final cohort | `AGENTDOJO_LOCAL_PROFILE.md` | **gone.** The 2026-11-08 note recorded the first loss; the sentence that still claimed the packet was "preserved at" `/tmp` was corrected on 2026-11-12 (ENGINEERING_BACKLOG.md E-9) |
| `/tmp/neuralstrike-phase0-acceptance/` — the Phase 0 probe copy, full-suite log, build log and wheel smoke | `PHASE0_ACCEPTANCE.md` | **gone.** The probe script it names, `evidence/deep_probe.py`, is also absent from this repository, so the Phase 0 reproduction claim cannot be re-run from what is committed — a stated limit, not a resolved one |

Neither artefact can be reconstructed: a fresh run is a fresh run, and substituting it for the
missing bytes would be fabrication. What exists is what is committed under
`docs/implementation/evidence/` plus what is under the durable root now.

