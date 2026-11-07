# NeuralStrike implementation ledger

## 2026-11-06 — Phase 0 in progress

Source baseline: `2e1318dee776e5090f4c29886b3e8011865467c6`; clean checkout,
identical to reviewed commit. No newer fixes to reconcile. Read all three supplied
handoff documents and inspected the baseline reproduction in `evidence/deep_probe.py`.
Environment: existing `.venv`, Python 3.14.10 (assessment used 3.12.14).

### Baseline gate decision contract (written before implementation)

| Current observation | vuln | regression | never |
|---|---|---|---|
| Complete Resisted, previous Succeeded | fixed, 0 | fixed, 0 | fixed, 0 |
| Complete Resisted, any other previous verdict | pass, 0 | pass, 0 | pass, 0 |
| Succeeded, previous Resisted/Inconclusive | vuln, 1 | regression, 4 | observed regression, 0 |
| Succeeded, previous Succeeded | vuln, 1 | unresolved vuln, 1 | observed vuln, 0 |
| Succeeded, new scenario | vuln, 1 | vuln, 1 | observed vuln, 0 |
| Missing/empty/unfinished/inconclusive observation | not comparable, 3 | not comparable, 3 | not comparable, 0 |

Preserve existing strict `regression` semantics: pre-existing vulnerabilities fail
with 1. Report-only never suppresses incomplete health labels. Invalid/corrupt
baseline files remain errors. Confirmed violations must remain visible even when
other observations are incomplete; incomplete negatives cannot establish fixes.

### Demonstrated before fixes

- `.venv/bin/python -m pytest tests/test_baseline_contract.py`: **16 failed,
  16 passed**. Includes supplied NS-01 cases and all 27 verdict/policy transitions.
- Resisted → Succeeded under vuln returned 0 with a regression listed.
- Succeeded → Inconclusive was called fixed; missing scenarios returned pass.
- Declared trial metadata hid missing actual trials.

### Outstanding

Phase 0 is not complete. NS-02–08, stronger scenario/target/oracle comparison
identity, immutable evidence, dependency triage and phase acceptance gates remain.
Subsequent phases and independent pilots remain unverified. No release, external
target testing, cloud inference or security efficacy claim is authorized by these
local unit results.

### Implemented locally

- NS-01: all three supplied baseline counterexamples fixed; regressions count as
  current vulnerabilities; only complete resistance establishes fixes. Missing,
  inconclusive, error-bearing or truncated actual trial sets reject comparisons.
  New baselines pin actual trial indices. Invalid verdict maps and trial manifests
  raise BaselineError. Legacy baselines without indices remain readable.
- NS-02 initial implementation: shared assessment health separates completeness
  from vulnerability policy. Scan enforces `vuln` without a baseline. Corpus gains
  `--fail-on`; outages default to exit 3. `never` retains incomplete health with
  exit 0. JSON/SARIF carry health; SARIF executionSuccessful reflects completeness;
  Markdown/PDF/JUnit expose assessment health.
- Compatibility decision: `regression` without a baseline retains legacy
  informational vulnerability behavior, but enforces completeness. Use `vuln` for
  absolute gating. With a baseline, existing strict pre-existing-vuln policy stays.
- NS-02 CLI reproductions: seven tests failed before implementation; seven passed
  after it. Added mixed-trial coverage check preserving confirmed vulnerability.
- Targeted baseline suite: 75 passed; Ruff passes; mypy passes (128 source files).
- Initial full baseline: 915 passed, 1 skipped, 1 failed due to local `.env` model
  defaults. Later retries identified attacker, judge and fallback overrides.
  `.env` remains untouched. Attempts to isolate only model overrides exposed
  further local environment settings. The default-settings test now clears its
  NEURALSTRIKE_* shell variables with monkeypatch and passes `_env_file=None`;
  this tests actual defaults without reading operator credentials.

Next: finish NS-02 acceptance coverage and CLI health wording, then NS-03 immutable
run instances. Strong comparison identities and canonical replay are still absent.


### Further verified changes

- NS-03: three new tests failed before implementation. Unique UUID run directories
  use exclusive creation; private files are atomically renamed and hashed in a
  schema-v1 manifest. Manifest state remains running if cancelled; completion is
  committed only after the report. Traces and response errors are persisted.
  Comparison key is explicitly limited to seed/scenario ID/intensity: it is NOT
  sufficient target/content identity. Hashes detect changes but are not signatures
  or protection against an owner rewriting files. Full request capture and an
  integrity-checking replay loader remain absent.
- NS-04: strict request fixture rejected 60/60 corpus requests before deduplication;
  all 60 now pass unique-name and causal call/result constraints. Message carries
  assistant tool_calls through OpenAI and default LangGraph state builders.
  Conflicting duplicate schemas fail explicitly. Strict negative fixtures reject
  malformed input. Independent real endpoint conformance is not established.
- NS-06/07/08: seven initial synthetic tests failed before fixes. Formatted logging
  arguments, exception and stack text are scrubbed, with a final formatter guard.
  A2A checks normalized scheme/host/effective port before outbound RPC, rejects
  userinfo/downgrade, binds credentials and client cert to configured origin;
  explicitly allowed additional origins receive no base credentials. MCP scan is
  read-only by default; execution requires explicit names and argument mappings.
  Name inference/sample execution was removed. Focused security/adapter/core suite:
  65 passed. One independent read-only boundary investigation and one candidate
  review found no concrete remaining bypass in that scoped patch. Controlled
  same-origin auth and allowed cross-origin no-auth behavior pass.
- Dependency locks refreshed and assessed; see DEPENDENCY_REVIEW.md. Final runtime
  audit exits 0 with no known advisories, with no ignores. No exploitation claim.

### Verification commands and results

- Existing Python 3.14 environment: `python -m pytest --cov=neuralstrike
  --cov-fail-under=85`: **1046 passed, 1 skipped, 90.77%**; four existing resource
  warnings (SQLite) remain. No paid/cloud inference invoked.
- New Python 3.12.14 environment installed from refreshed hash-pinned dev lock:
  same pytest command: **1045 passed, 2 skipped, 90.56%**. pytest-asyncio emits an
  existing default fixture-loop-scope deprecation warning.
- Refreshed `ruff check src tests`: passed. `mypy`: passed, 128 source files.
- Dashboard `npm test -- --run`: 3 passed. `npm run build`: passed.
- `uv build --out-dir /tmp/neuralstrike-build`: wheel and sdist built.
- Fresh runtime-lock environment installed wheel with `--no-deps`, from outside
  checkout: `neuralstrike smoke --out /tmp/neuralstrike-wheel-smoke --format json`:
  exit 0. Bundled fixture only; no external target.
- `git diff --check`: passed. No commit, push, release or container validation.

### Acceptance status and next concrete work

**Phase 0 remains in progress**, despite green tests. Remaining acceptance gaps:
NS-05 actual provider option/request capture; robust scenario/target/oracle identity;
strict socket-server and independent endpoint interoperability; fault injection for
interrupted writes; full partial-error/report consistency and private/shared bundle
policy. Current corpus artifacts still do not preserve complete injection-bearing
request history. Run directories are unique, but canonical evidence/replay is not
implemented. CLI adapter cleanup on all exceptional paths still needs extraction.

Next: capture actual request envelopes/seeds and complete NS-02/03/04 acceptance
fixtures, then canonical replay. Do not advance claims to Phase 1 completion or
pilot readiness. Independent human pilots require real authorized participants;
none have occurred. NeuralGuard and Scarlet remain optional.

## 2026-11-06 — pushed baseline fixes, continued Phase 0

User authorized pushing to main and continuing Phase 0. Fetched origin/main;
there was no divergence or unrelated work. Committed/pushed the preceding work as
`0abbd2e` (`fix: restore Phase 0 gate, evidence, and execution safety contracts`).

### Newly demonstrated and fixed

- NS-05: three new regressions initially failed: missing wire seed, missing
  injection-bearing request history, and shared-adapter seed isolation. A
  task-local TrialControls context now binds runner seed/temperature without
  mutating shared adapters. OpenAI requests record actual sent JSON per round,
  response JSON/model/fingerprint, HTTP status and errors. Request snapshots are
  copied before subsequent tool rounds mutate history. Remote LiteLLM controls
  are also forwarded (verified with a mocked provider; no cloud inference).
- Two further regressions failed before fixes: remote controls omitted, and
  corpus CLI had no durable raw-evidence path. Corpus now persists immutable
  per-scenario run directories (`--run-dir`, default runs). JSON embeds original
  RunReport evidence, including full woven adapter inputs and captured exchanges.
  Corpus artifacts are atomically written with mode 0600. Headers and URL
  userinfo/query are excluded from exchange capture. Raw bodies may still contain
  sensitive target content: these are private evidence, not sanitized exports.
- NS-01: five configuration-change tests failed before comparison fingerprints:
  same-label payload, target URL, model, oracle and tools changes all passed.
  Modern adapter probes now fingerprint scenario content, configured target,
  tool definitions, oracle configuration/implementation and composition logic.
  Incompatible or unsupported identities reject comparison with exit 3 (never
  retains report-only exit 0). Existing identity-less baselines cannot be compared
  to modern scan snapshots: regenerate a baseline. Legacy-to-legacy API behavior
  remains readable. A matching modern vulnerable baseline still exits 1.
- Added real socket tests with a strict stdlib HTTP endpoint: all 60 corpus
  histories are accepted; duplicate/orphan malformed requests return HTTP 400.
  This independently checks wire formatting, not live-model efficacy or official
  provider/protocol conformance.
- Added disk replacement fault injection and forced run-ID collisions: interrupted
  writes leave no partial final trial or false completion; existing evidence is
  unchanged when exclusive directory creation detects a collision.

### Verification

- Refreshed Python 3.12.14 `python -m pytest --cov=neuralstrike
  --cov-fail-under=85`: **1062 passed, 2 skipped, 90.83% coverage**.
- `ruff check src tests`: passed. `mypy`: passed, 131 source files.
- New local tests use synthetic data, mocked remote calls or loopback HTTP only.
- Final targeted checks and rebuilt-wheel smoke are recorded below after completion.

### Remaining Phase 0 limitations

Remote builds are explicitly unverified: configuration fingerprints do not attest
that an application behind a URL has unchanged code/tools. Custom unrepresentable
oracle configurations are non-comparable. Provider seeds are sent best-effort;
providers may ignore or reject them. No silent retry strips rejected controls.
Only the OpenAI-compatible adapter records actual provider exchanges so far;
other adapters preserve planned inputs, which do not prove delivery or execution.
Timeout/cancellation can end before a complete exchange is returned; incomplete
manifests remain visibly uncommitted. A sanitized sharing bundle and strict
integrity-loading/offline rescoring workflow remain unimplemented. All-format
canonical trial reporting, exceptional-path resource cleanup, and independent
compatible implementation validation still need completion before Phase 0 signoff.

### Final verification and additional failure-path fixes

- Two more baseline regressions failed before enforcing exact planned trial
  indices: arbitrary legacy-current indices and extra actual trials could pass.
  Baseline and standalone health now require exactly the declared trial indices.
  Standalone-health regression was separately observed failing before its fix.
- Scan and corpus cleanup regressions both failed when TrialRunner.run raised a
  simulated disk error. Both now close network adapters in finally blocks. Corpus
  attempts all closes before surfacing a cleanup failure. This closes the scoped
  scan/corpus resource gap; other legacy commands were not refactored.
- Final Python 3.12.14 full gate: **1067 passed, 2 skipped, 90.82% coverage**.
  `ruff check src tests` and mypy pass (131 files). `git diff --check` passes.
- Rebuilt wheel/sdist after the final source changes; reinstalled wheel with
  --no-deps --reinstall into the isolated runtime-lock environment. From /tmp,
  `neuralstrike smoke --out /tmp/neuralstrike-phase0-request-smoke --format json`
  exits 0 (3 scenarios / 3 trials). No live model or external target used.

Phase 0 still needs all-format trial/health consistency, unavailable-ASR display,
full private/sanitized artifact policy enforcement, and independent compatible
implementation checks before signoff. Full integrity-checked offline replay is
still outstanding. Passing local fixtures is not proof of real-target efficacy.

## 2026-11-06 — canonical report outcomes and independent compatibility checks

Started from clean main at `6b20430`. Continued Phase 0 without external targets,
paid inference, release publication or integration requirements.

### Demonstrated defects and fixes

- **Reports counted oracle rows as trials.** The new mixed-oracle/mixed-trial
  regression failed: three trials became five exported rows. JSON, SARIF, JUnit,
  Markdown and PDF now derive one outcome per trial, retaining every oracle in
  subordinate `findings`. The representative evidence matches the canonical
  verdict. Dashboard evidence comes from the actual later failing trial.
- **Incomplete negatives were presented as resistance.** A Resisted result with a
  response error failed the new regression. One normalization rule now makes that
  Inconclusive across runner persistence, scoring, health and reporting. Confirmed
  Succeeded evidence survives later errors; health remains incomplete.
- **Zero observations looked like a measurement.** New tests failed on ASR 0.0.
  Exports now use null for unavailable ASR, CI bounds and risk. Human summaries
  display unavailable. Existing numerical ScoreCard API fields remain compatible;
  `measured_asr` distinguishes absent measurement. Reports identify private raw
  evidence explicitly and never label it sanitized.
- **Dashboard interpretation failed four initial regressions**, then three more
  invalid-input cases: missing ASR became zero, first-trial evidence was reused,
  SARIF oracle rows inflated counts, empty scenarios became Resisted, unsupported
  schemas were accepted, corrupt numeric types were accepted and unknown verdicts
  became Resisted. These now pass. Shared Python-generated JSON/SARIF fixtures
  round-trip through the dashboard. Legacy row counts are labeled; recorded and
  selected trial counts and assessment health are visible.
- **Mislabeled scope passed reporting.** A same-length wrong-scenario report was
  accepted before the new test. Reporting now validates scenario alignment,
  duplicate selected IDs and declared trial plans. It uses recorded start times
  instead of inventing a new start at report export.
- **JUnit execution outages were merely skips.** Transport-error Inconclusive
  trials now emit native errors, ordinary inconclusive observations remain
  skipped, and confirmed violations remain failures. Canonical counts and health
  remain separate metadata; do not use skipped counts as a security policy.
- **Corrupt baseline errors used the vuln exit.** Three CLI policy regressions
  failed before mapping BaselineError to runtime exit 3. Non-UTF-8 baseline data
  and invalid explicit trial counts also failed six regressions; both now reject
  explicitly. Other runtime failures (including evidence I/O) return 3 with
  incomplete status and redacted diagnostic logging; explicit policy exits remain
  untouched. Legacy argument validation behavior is preserved.
- **evaluate/pack still ignored standalone fail-on.** Ten new contract cases
  initially failed (policy enforcement or absent health status). All four existing
  fail-on command surfaces now share one standalone policy boundary. `never`
  preserves incomplete health while exiting 0; vuln enforces observed violations
  without requiring a baseline. Regression without a baseline retains the earlier
  documented legacy informational vulnerability policy while enforcing health.

### Additional defects found through independent checks

1. **Unsigned provider seeds were rejected by a real implementation.** Local
   Ollama 0.40.14, already-installed qwen3.5:2b (2.74 GB local artifact), rejected
   the former derived seed 11143675092282761955 with HTTP 400: its request decoder
   requires a signed integer. Two new regressions failed before the fix. Seed
   derivation is now `blake2b-63bit-v2`, versioned in actual runner metadata and
   modern comparison identity. Old modern baselines require a trusted rerun.
   The same synthetic retrieved-document request then returned HTTP 200 using
   seed 1920303055427986147. **The assessment remained Inconclusive, with zero
   conclusive coverage.** This proves this request's interoperability, not
   resistance, a real breach, or model efficacy. Both calls were bounded by
   HTTP/trial deadlines and used harmless canary handlers; no real credentials.

   Private immutable local evidence:
   - Before: `runs/run-13f1273d84c74a03b6e1f5b656e21bad/`, manifest SHA-256
     `54cbd0fd5eb4d2c6dab9a263ecad9ba1bcab44acf6d366fcea0bd8fd7a7995cb`.
   - After: `runs/run-a292c27a613b4bbda81e14359f582dff/`, manifest SHA-256
     `cddc7d6e433148869c0de9d97e3229c1566f69b556cce25c739c60e76ffb627b`.
   These ignored raw evidence directories were preserved, not published.

2. **PDF headers passed tests while actual pages were blank.** Poppler reported
   a page-tree child with the wrong type and rendered a 1x1 image. The writer
   emitted streams where page references pointed and referenced an incorrect
   font object. Three independent parser/wrapping regressions failed first.
   Page/content/font references are corrected; Courier text stays within page
   margins, long unbroken evidence wraps, and pages have footers. pypdf 7.0.0 now
   verifies single/multiple page trees and extracts all 80 trial receipts. It is
   a development-only dependency; production PDF output remains dependency-free.
   Final Poppler render was visually inspected: Letter-size page, legible
   counts/outcomes/annotations, visible late error, private handling label,
   correct recorded start and footer. Poppler emitted a local fontconfig warning;
   the rendering and independent parsing succeeded.

### Compatibility and remaining scope

See REPORT_CONTRACT.md for schema 2 and seed migration. Retain old evidence and
rebuild baselines from a trusted reference, not from the candidate under test.
The optional NeuralGuard/Scarlet integrations remain optional. No hosted service,
new attack family, dashboard redesign or release publication was introduced.

Phase 0 signoff is still open. Remaining work includes a final acceptance audit
of artifact destinations outside scan/corpus and failure-path/protocol coverage.
Integrity-checked offline replay, exact causal/provenance binding, authenticated
remote build identity and broad protocol conformance remain later-phase work.
Outgoing history/marker records prove the sent surface, not that an application
consumed a document. A sanitized sharing exporter is not implemented. The one
independent endpoint check does not establish universal provider support.

Final verification results are recorded below after the frozen-source gates.

### Resumed checkpoint verification

Work was paused at the user's request for API limits and resumed on request.
All local source/evidence remained intact; nothing from the paused increment had
been committed or pushed. Additional pre-pause checks bound baseline context to
recorded seed/scenario and rejected invalid comparison metadata types. Runtime
I/O failures now use exit 3 while preserving original diagnostics and cleanup.

Model-name canary probes also failed three scope regressions before their fix:
changing model, local endpoint or iteration budget could silently compare.
They now carry configuration identity and explicit planned input/canary data.
Provider-resolved endpoints that cannot be identified are non-comparable; no
request envelope is claimed for these legacy model-name calls.

Resumed frozen-source gates (Python 3.12.14 refreshed hash-pinned environment):
- `python -m pytest --cov=neuralstrike --cov-fail-under=85`: **1108 passed,
  2 skipped, 90.90% coverage**.
- `ruff check src tests`: passed; mypy: passed, 131 source files.
- Dashboard: 12 tests passed; production build passed.
- Wheel/sdist rebuilt; isolated runtime-lock environment reinstalled the wheel
  outside the source checkout. Offline wheel smoke result is checked before push.
- `git diff --check`: passed. No release or external-target testing.

Next acceptance work: imported benchmark pack comparisons still need explicit
full-plan/target binding; audit private artifact destinations and complete the
remaining negative-path checks. These are not Phase 0 signoff or efficacy claims.


### Pack comparison and artifact acceptance checkpoint — 2026-11-06

Demonstrated failures, fixed with regressions written first:

- Pack comparisons accepted changed models, prompts and judge configuration;
  a CLI baseline for two probes also accepted a one-probe selected plan. Full
  selected-plan/configuration identities now reject those comparisons, with a
  positive same-plan control. Duplicate IDs and portable filename collisions
  are rejected before constructing the model manager.
- Baseline writes were public and non-atomic, lacked source execution IDs, and
  accepted unknown declared schemas. Snapshots now use private atomic writes and
  schema 1, reject incomplete declared metadata, and preserve the reference on
  simulated replacement failure. Genuine unversioned legacy compatibility stays.
- Smoke, NeuralGuard benchmark and purple-report exports created mode-0644
  files. Three failing synthetic CLI tests now pass with private atomic exports.
  Optional integration calls were mocked; no service was activated.
- Duplicate MCP inventories (server-provided or injected) caused an explicitly
  selected tool to execute repeatedly. Two regressions failed first; ambiguous
  inventories now fail before tools/call. An exact-name/arguments control proves
  the authorized fixture executes once without similarly named or other tools.

Additional existing A2A policy checks pass: redirects are not followed, cached
card mutation is rejected before an additional authenticated request, and client
certificates remain bound to their original origin. These are MockTransport /
pre-request checks, not full mTLS interoperability claims.

Frozen-source verification:
- `/tmp/neuralstrike-phase0-venv/bin/python -m pytest --cov=neuralstrike
  --cov-fail-under=85`: **1128 passed, 2 skipped, 91.82% coverage**;
  log `/tmp/neuralstrike-resume-final-gates.log`.
- Ruff passed; mypy passed (131 source files); `git diff --check` passed.
- `uv build --out-dir /tmp/neuralstrike-phase0-final-dist`: wheel and sdist pass.
  Existing setuptools license-metadata deprecation warnings remain.
- Reinstalled rebuilt wheel into the isolated runtime-lock environment; from
  `/tmp`, `neuralstrike smoke --out /tmp/neuralstrike-final-wheel-smoke
  --format json` passed with three synthetic scenarios/trials, including the
  deliberately vulnerable fixture. This verifies packaging, not efficacy.
- Dashboard source unchanged since checkpoint fe683e0 (12 tests/build passed).
  No dependency changes since the recorded clean hash-locked advisory audit.

Phase 0 acceptance signoff remains open pending a consolidated requirements-to-
evidence review. Later-phase offline integrity/replay, sanitized sharing,
authenticated remote build identity and broad protocol conformance remain open.
Next: reconcile every Phase 0 acceptance row with supplied reproductions and
current checks, record any concrete gaps, then proceed to canonical evidence.

### Phase 0 acceptance closed for controlled fixtures — 2026-11-06

See PHASE0_ACCEPTANCE.md for the requirements-to-evidence matrix and limits.
The unchanged supplied deep probe was rerun outside the checkout; its baseline,
outage, log, rerun and indirect-request observations now show the intended
behavior. Permissive empty scope remains explicitly recorded for canonical
permission preflight work; this does not authorize external testing.

Final acceptance review found and fixed one more demonstrated gate defect:
scan/evaluate/pack could save over the reference before comparison and exit 0.
All six same-directory/symlink regressions failed first with exit 0; the guard
now exits 3 before execution and preserves reference bytes. The strict history
fixture now also runs all 60 scenarios over a real loopback HTTP server and
rejects two malformed negative controls. Concurrent manifests are checked for
hash integrity, exact file inventories and source execution IDs.

Final frozen-source gate: **1135 passed, 2 skipped, 91.83% coverage**;
Ruff/mypy/diff checks pass. Wheel/sdist rebuilt and isolated installed-wheel
smoke passed (three synthetic scenarios/trials). Optional base58/real NeuralGuard
tests remain skipped, not counted as verified integrations. Local logs and
artifacts are under `/tmp/neuralstrike-phase0-acceptance/`. No release published.
Phase 0 acceptance is complete within this documented fixture scope; later
canonical evidence/replay, authorization preflight and independent validation
remain unfinished. No efficacy or production-readiness claim is made.

### Phase 1 — verified offline evidence increment, 2026-11-06

User authorized proceeding after Phase 0. Started from clean main at 46f1849;
read the Phase 1 gates and reconciled the existing canonical report work. This
increment implements hands-on evidence replay/rescore and closes NS-09/NS-10
counterexamples; it is not a claim of complete Phase 1 or production readiness.

Implemented and demonstrated:

- New replay acceptance tests failed before a bundle loader existed. Complete
  per-run bundles now use manifest schema 2 and stable observation content IDs;
  response presence, category/severity and actual completion time are recorded.
  Loader rejects unknown/incomplete schemas, duplicate JSON keys, nonfinite
  numbers, unsafe/unlisted/missing entries, hash/ID/component mismatches, invalid
  known local receipts and contradictory scores/types. Reads are bounded. Known
  Phase 0 schema-1 shapes remain readable with explicit legacy limitations.
- `replay` recomputes recorded scores with no target/provider construction.
  `--verify-oracles` also reconstructs only allowlisted built-in deterministic
  policies, checks their implementation digest, and re-evaluates observations.
  All 60 corpus policies round-trip identically offline. Changed implementation
  is an explicit verification error, never a silent identical-replay claim.
  Custom policies are marked unavailable; no import paths or executable code are
  loaded from stored data. External schema references are rejected offline.
- `rescore` uses an explicit versioned local policy and writes a new private
  derived bundle. Source execution ID, manifest hash and implementation/config
  digest are recorded; original bytes and observation IDs remain unchanged.
  Exports/derivations inside the source bundle are rejected. Both new commands
  default to `--fail-on vuln`; corruption still exits 3 under `never`.
- Three NS-09 prose/prefix/suffix regressions failed before removing substring
  attribution. Behavioral promotion now requires exact tool name, call ID,
  argument digest and unique matching receipt. Findings retain receipt ID and
  local-canary origin. Wrong IDs/arguments/names, duplicates, absent bindings and
  non-success findings cannot promote. Legacy traces remain readable without
  upgrading them. A bound behavioral receipt survives replay and same-policy
  rescoring. Existing positive fixtures now supply genuine structured bindings.
- Two independent ES256 regressions failed first: RFC 7515 Appendix A.3 raw
  vector rejected, corresponding DER wire encoding accepted. Raw 64-byte R||S
  is now converted to the backend's DER format; wrong length/curve and malformed
  signatures fail. This is interoperability correction, not demonstrated forgery
  remediation or a claim of comprehensive JOSE/HTTP-signature conformance.
- Two report-source regressions showed phase5/phase10 locations guessed from ID
  prefixes. Corpus loading now records portable source path/file hash and stable
  normalized scenario fingerprint. All report views expose observation ID/origin,
  scope, limits and recorded timestamps. Legacy completion remains unrecorded.
- Shared four-trial synthetic fixture includes mixed oracle annotations, a later
  violation plus late error, resistance and an unsupported delivery channel.
  JSON/SARIF/JUnit/Markdown/PDF and dashboard agree on total 4, S1/R1/I2, coverage
  50%, ASR 50%, incomplete health, and link to the actual later violation.
- Independent PDF parsing and rendered visual review exposed an orphan error on
  the next page. A failing regression now passes after keeping fitting trial
  blocks together. Both final PNG pages were inspected: legible IDs and labels,
  no clipping/overlap, trial identity and error together, correct page numbers.
- Final recipe review reproduced three malformed configurations that escaped as
  unexpected errors or changed policy semantics. Exact allowlisted fields/types,
  predicate polarity and argument operators now reject them explicitly. Failed
  evaluation writes no completed derived report. No arbitrary validator is loaded.

Verification (frozen source, refreshed Python 3.12.14 environment):

- `python -m pytest --cov=neuralstrike --cov-fail-under=85`: **1249 passed,
  2 skipped, 91.71% coverage**, `/tmp/neuralstrike-phase1-final.log`.
- `ruff check src tests`: pass. `mypy src`: pass, 133 source files.
- Dashboard: **15 tests pass** and production build passes (no dependency changes).
- Wheel/sdist built; rebuilt wheel reinstalled into isolated runtime-lock env.
  Installed-wheel smoke/replay/rescore/corruption results recorded after completion.
- `git diff --check`: pass. Optional base58/real NeuralGuard tests remain skipped;
  they are not verified integrations. No cloud inference, external target testing,
  release publication, new attack families or optional service activation.

Remaining Phase 1 signoff work: consolidate multi-scenario selection/scope into a
portable assessment-level bundle rather than only per-run manifests; finish the
request-capture/sanitized-envelope scope audit and sharing/export compatibility
review. Exact exchanges currently cover the OpenAI-compatible profile; other
adapters still record planned inputs. Original-oracle verification is limited to
supported deterministic policies and does not rerun advisory model judges.
Hashes are not author authenticity or remote-build attestations, local receipts
are fixture effects, and coverage is not security efficacy. Broader protocol and
independent target validation remain later-phase gates. See REPLAY.md for usable
commands and compatibility limits; no Phase 2 readiness claim is made.

Installed final wheel verification completed outside the checkout: bundled
three-scenario smoke passed; a freshly recorded synthetic indirect run verified
with original oracles (exit 0 under explicit `never`), derived rescore passed,
source bytes were unchanged, and a corrupted disposable copy exited 3 even
under `never`. Final wheel source:
`/var/folders/zv/n4210phd6_d5lqqfx462c9gw0000gn/T/neuralstrike-phase1-final-wheel-1ifby4k_/source/run-fbf83137755c47158d355414ad934a68`.
These raw artifacts are local only and are not committed. Full-suite counts above
are final after the strict recipe-validation changes. No hosted CI result is
claimed for this new increment until its pushed commit is independently checked.

### Phase 1 acceptance completed — 2026-11-07

Continued from af55e2d with clean main. Implemented the remaining assessment-level
bundle and capture/export scope work, preserving per-run paths and newer fixes.
See PHASE1_ACCEPTANCE.md for the six acceptance rows and explicit profile limits.

Completed work and fail-before evidence:

- New parent-bundle acceptance tests failed before implementation. Corpus now
  freezes the full selected plan before adapter setup; private unique parent
  directories contain plan/report, hashed child manifests and complete child
  bundles. Portability requires no original run root. Loader enforces bounded
  known-schema files, exact inventories, plan/run context and compiled-summary
  consistency. Changed scenario contents cannot claim the original plan.
- Omitted selections retain empty trial sets, incomplete health and no asserted
  execution. Global setup/cleanup errors remain incomplete even if all committed
  trials conclude. Partial/unlinked persistence cannot be blessed as committed.
  Offline replay/rescore retain those states, and source bytes/content IDs stay
  unchanged. Parent derivations record source identity/hash and new policy.
- Five offline-format regressions failed before adding shared rendering dispatch.
  All formats now render a verified parent; four more failing regressions required
  parent ID/plan digest in each view. Recorded policy and original producer version
  are retained, separate from current replay policy. A historical producer-version
  control failed before preserving that version. Malformed summary-array input
  also failed the explicit-error contract before its final guard.
- A selected scenario without a SARIF result was missing from dashboard rows.
  The new regression failed first. Scope/rules now preserve that row as missing,
  with no synthetic result/trial added to totals; JSON/JUnit/human views retain
  the same missing-record distinction. Known older additive labels remain readable.
- New sharing tests failed before `export-summary`. Only validated metrics, fixed
  enum values and hashed references are exported; all freeform fields are omitted.
  Sentinels across IDs, target URL, prompts, outputs, tool args, errors, paths and
  oracle text are absent from the summary. Source corruption prevents output,
  overwrite inside the source is rejected, and summary profile is non-replayable.
- Demonstrated credential leak: HTTPX status-error strings included URL passwords
  in exchanges, response errors, persisted JSON and logs. Boundary investigation
  confirmed copies/encoded forms and the ordinary connection-error contract.
  Narrow adapter diagnostics now retain structured class/status/credential-free
  endpoint information and ordinary unauthenticated details; authenticated or
  URL-bearing transport messages remain opaque. Actual bodies/auth wiring stay.
- One independent candidate review found a surviving SDK INFO route before the
  adapter handler. Six new INFO formatter/filter regressions and a deeply encoded
  transport case failed before fixes. Default URL log rendering now omits userinfo,
  query and fragment; the adapter no longer copies credential-bearing diagnostic
  text/cause. The original trigger, alternates and legitimate controls pass.
  No historical real-credential leak or compromise is claimed; all probes synthetic.

Final ordered verification:
1. Syntax/import/static: Ruff passed; mypy passed (136 source files).
2. Security trigger/alternates: focused capture/adapters/request-evidence/logging
   checks passed after correcting the reviewer-confirmed INFO path; original raw
   and equivalent encoded/redirect/authenticated transport sentinels no longer
   reproduce in rendered diagnostics. Ordinary `boom` and successful/full-body
   capture remain intact. One review cycle, read-only agents, no unrelated edits.
3. Full refreshed Python 3.12.14 gate: **1295 passed, 2 skipped, 91.62% coverage**,
   `/tmp/neuralstrike-phase1-final-acceptance.log`. Dashboard **19 tests/build pass**.
   Wheel/sdist and isolated installed-wheel assessment smoke, portable original-
   oracle replay in five formats, derived rescoring, summary and corruption/missing
   rejection passed. Source manifest hash/root are recorded in PHASE1_ACCEPTANCE.md.
   Diff whitespace checks pass. Final PDF pages were rendered/visually inspected.

Phase 1's declared acceptance gates are complete within these tested profiles.
No readiness/efficacy claim follows from coverage or fixture success. Capture
scope, legacy/producer compatibility, summary limits, optional skipped packages
and later-phase interoperability/authorization/validation boundaries remain
explicit in CAPTURE_PROFILES.md, REPLAY.md and PHASE1_ACCEPTANCE.md. Next phase is
protocol interoperability and target preflight under the master plan; no release,
cloud spend or external-target testing has been performed or authorized here.

## 2026-11-07 — Phase 2 started: authenticated OpenAI preflight and response boundary

Phase 2 is in progress, not complete. Started from clean main c0eed07; no
unrelated work was present. Read the master-plan Phase 2 acceptance requirements
and inspected adapter/CLI/runtime ownership. No repository AGENTS.md was found.
No dependencies changed, cloud inference ran, releases were published or external
targets were tested. Tests used synthetic credentials and loopback HTTP only.

Demonstrated before fixes:
- Eight new response-boundary tests failed: the adapter had no accepted-response
  byte limit, crashed on null/list message objects, accepted duplicate tool IDs
  and malformed JSON arguments, or ran until the round cap.
- Three CLI auth regressions failed because corpus had no environment credential
  reference option. Separate stdlib HTTP fixture supplies the independent
  transport implementation; it does not establish customer-agent efficacy.
- Preflight tests initially failed collection because no preflight module existed.

Implemented:
- Bounded decoded streaming read, explicit incomplete-capture/error metadata and
  stream cleanup. All successful and failure status bodies use the same limit.
- Whole-message/tool-batch validation before executing any handler from that
  batch; invalid raw private response remains reproducible. No automatic retries.
- Corpus `--target-api-key-env` and `--max-response-bytes`; missing/empty/header-
  invalid credentials fail before assessment setup, and existing unauthenticated
  CLI use remains valid.
- `doctor` with overall timeout, harmless tool round-trip (or explicit text-only),
  private optional capability receipt, client-version metadata, and guaranteed
  client closure. Readiness is explicitly not a security assessment. Source
  credential values and headers are excluded from its receipt.
- Tests establish cancellation stream cleanup, deadline/client cleanup, 429/503
  no-retry behavior, malformed batch nonexecution, compressed overflow, exact
  boundary, actual CLI authenticated 200/401 handling, and safe inconclusive
  corpus gating even when authentication succeeds.

Verification checkpoints:
- First full Python pass: 1312 passed, 2 skipped, 91.60% coverage, 34.03s
  (`/tmp/neuralstrike-phase2-increment1-tests.log`), before added doctor coverage.
- Final focused new suites: 26 passed (loopback CLI, preflight, response limits).
- Final full-suite and static-check results are recorded below after completion.

Scope/limitations and usable commands: PHASE2_INTEROPERABILITY.md. Remaining
Phase 2 work includes independently implemented LangGraph vulnerable/hardened/
regression cycles, explicit MCP revision profiles, runtime budgets/rate controls,
thread reset/cleanup-failure semantics, secret stores and consequential-action
idempotency. The byte limit bounds accepted decoded data, not all process memory.
No claim of server-build attestation, universal interoperability or efficacy.

Final verification for this increment:
- `/tmp/neuralstrike-phase0-venv/bin/python -m pytest --cov=neuralstrike
  --cov-fail-under=85` → **1321 passed, 2 skipped, 91.62% coverage**, 35.37s;
  `/tmp/neuralstrike-phase2-increment1-final.log`. The optional base58 and real
  NeuralGuard skips remain unverified integrations, not passes.
- `ruff check src tests`: pass. `mypy src`: pass, 137 source files.
- `uv build --out-dir /tmp/neuralstrike-phase2-increment1-dist`: wheel and sdist
  pass. The initial `python -m build` attempt could not run because that temporary
  environment lacks the build module; uv's isolated build succeeded without
  repository dependency changes.
- Reinstalled the wheel with `uv pip install --python
  /tmp/neuralstrike-wheel-venv/bin/python --no-deps --reinstall ...whl`. From
  `/tmp`, verified import from that environment, ran installed CLI doctor against
  a separate loopback server, observed authenticated tool/final-text 200/200
  round-trip, exit 0, private 0600 receipt, no synthetic credential in receipt and
  `security_assessment=false`. Scratch root:
  `/var/folders/zv/n4210phd6_d5lqqfx462c9gw0000gn/T/neuralstrike-phase2-wheel-hvvzcwpt`.
- `git diff --check`: pass. Dashboard unchanged; no additional dashboard testing
  required for these adapter/CLI changes. No hosted CI completion claim.

## 2026-11-07 — Phase 2: separate LangGraph app, output transcript and live regression cycle

Started from clean main 1f39687. Read parent repository instructions and current
memory pointers; no unrelated tracked changes were present. No new dependencies,
cloud inference, external system tests, releases or optional fleet services.

Demonstrated defects (failing regressions before fixes):
- Six tests failed in `/tmp/neuralstrike-phase2-langgraph-red.log`: standard
  LangGraph tool/result/final-answer flow lost the earlier action because only
  the last message was inspected; absent/malformed output and rewritten input
  prefixes could yield empty/misleading observations.
- `/tmp/neuralstrike-phase2-graph-identity-red.log`: anonymous object graphs were
  marked baseline-comparable without a configured application identity.
- `/tmp/neuralstrike-phase2-resolver-red.log`: misspelled module attributes fell
  back to a different available graph and executed it. Now explicit failure.
- Three custom-scenario CLI tests failed before adding `--scenario-dir` and
  `--graph-channel` (`/tmp/neuralstrike-phase2-custom-corpus-red.log`).

Implemented focused adapter fixes:
- Snapshot immutable inputs before invocation, normalize actual LangChain
  messages, verify/exclude the input prefix and collect all newly emitted
  assistant tool calls. Preserve final text, normalized returned/output messages,
  invocation origin, text-message profile and installed protocol package versions.
- Explicit append/output/custom extraction boundaries; preserve custom state/
  extractor callbacks without claiming full custom capture. Missing/non-text/
  invalid output is an error, not a pass. Explicit values-mode streaming.
- A declared unavailable channel fails before graph invocation. Generic delivery
  traces remain planned-input observations, not native-hook consumption proof.
- Anonymous object graph comparisons are non-comparable unless a stable target_id
  is supplied; module specs remain declared configuration identities. Bind graph
  mode/channel capabilities to comparison digests, without build-authenticity claims.
- Synchronous-only fallback is deliberately narrowed to explicit unsupported:
  arbitrary sync work cannot be hard-cancelled safely. Async cancellation is
  tested and propagates after application coroutine cleanup; no executor thread
  is detached while it may execute tool actions.
- CLI custom scenario directory and declared repeatable graph channel list, with
  actual custom module identity in the frozen assessment scope/target label.

Separate controlled application:
- `examples/langgraph_account_support/application.py` imports LangGraph/LangChain,
  never NeuralStrike. Uses real compiled nodes, its own role store/tools and a
  deterministic vulnerable/hardened planner. This is separately implemented,
  not an independently authored third-party efficacy cohort or learned LLM.
- Same app/scenario/seed/app-family identity: vulnerable role changes to admin;
  hardened preserves reader and completes the account-summary task; regressed
  again changes to admin. All stages complete the benign task. Baseline detects
  the fix, then regression exit 4. Findings stay IntentToAct; independent app
  events/state are not relabeled as local-canary behavioral receipts.
- `python -m examples.langgraph_account_support.verify --out
  /tmp/neuralstrike-phase2-independent-graph` generated private reproducible
  assessment/run bundles, baselines and a version/source/scenario/manifest-bound
  validation receipt at
  `/tmp/neuralstrike-phase2-independent-graph/validation-776c55bd56fa49de97956563f1061a43`.
  Retrieval node events contain the actual selected payload. Original-oracle
  run/parent replay agrees without source mutation. Installed profile: langgraph
  1.2.20, langchain-core 1.7.6, langgraph-checkpoint 4.3.1. No inference requests.
- Tests exercise CLI vulnerable exit 1, hardened exit 0, unsupported-hook exit 3,
  explicit output/custom profiles, streaming values, async cancellation and
  sync-only refusal before any uncancellable work starts.

Phase 2 remains in progress. MCP profiles, actual outbound rate/concurrency/
usage budgets, broader lifecycle/reset-failure handling, idempotency decisions,
secret stores and wider interoperability receipts remain open. Retrieval in this
fixture is an injected ToolMessage surface, not a remote search-index hook. See
PHASE2_INTEROPERABILITY.md for concrete commands and compatibility boundaries.

Final gates for the LangGraph increment:
- Full Python: **1338 passed, 2 skipped, 91.73% coverage**, 35.63s;
  `/tmp/neuralstrike-phase2-graph-full.log`. Optional skips remain unverified.
- Ruff (`src tests examples/langgraph_account_support`) and mypy (`src`, 137
  files): pass. `git diff --check`: pass. Dashboard unchanged.
- `uv build --out-dir /tmp/neuralstrike-phase2-graph-dist`: wheel/sdist pass.
  Reinstalled wheel with no dependency changes, then installed existing hashed
  dev lock into the isolated wheel environment to supply optional LangGraph
  (the base runtime environment correctly did not include it). No lock changes.
- From `/tmp`, confirmed import from installed wheel; with only the repository
  examples on PYTHONPATH, the three-stage verifier passed at
  `/tmp/neuralstrike-phase2-graph-wheel/validation-53725753e2be40e1a44867345e364a3f`.
  Installed CLI custom hardened scenario passed exit 0 with one resisted trial,
  full selected coverage and complete health; report/logs under
  `/tmp/neuralstrike-phase2-graph-wheel-cli-*`. This is controlled fixture scope.

## 2026-11-07 — Phase 2: actual outbound request controls and honest token accounting

Separate focused increment after bbe8e67. Previously, runtime helpers had tests
but no adapter/CLI callers; grep confirmed they did not govern outbound work.
The deterministic failing clock regression demonstrated a rate-limiter defect:
waiting for a token was credited a second time on the next acquisition (0,10,10
seconds instead of 0,10,20). `/tmp/neuralstrike-phase2-runtime-red.log` records
that failure plus missing shared-policy behavior. A further failing regression
(`/tmp/neuralstrike-phase2-admission-red.log`) proved exhausted caps could wait
for a rate token before failing. Both defects are fixed.

Implemented:
- New shared OutboundPolicy composes existing rate/concurrency/token helpers at
  actual OpenAI request admission. No retries added. One policy spans all corpus
  scenario adapters and tool-continuation rounds. Cancellation frees slots; rate
  waits are accounted once. Synchronous admission reservation prevents races.
- CLI opt-in `--max-requests`, `--requests-per-minute`,
  `--max-concurrent-requests`, `--max-total-tokens`. Unsupported adapter paths
  reject the options before running; controls cannot silently become metadata.
  Immutable assessment scope and baseline identity bind configuration, not counters.
- Distinguish planned/unattempted envelopes from attempted requests. Capture
  admission refusal and budget errors explicitly. Preserve completed private
  response bodies even when accounting prevents processing their tool actions.
- Usage is valid provider-reported total_tokens or explicitly estimated from
  request/response JSON bytes. Malformed usage is not treated as measured zero.
  Unmeasured failed requests block further token-budgeted dispatch. Cost remains
  null/unavailable; no pricing or absolute billable-spend ceiling is promised.
  Token thresholds are post-response, may overshoot with the crossing request
  and already in-flight calls, and are enforced before executing returned tools.
- Existing unauthenticated/default CLI behavior remains; no new implicit request
  policy. Policies apply to OpenAI corpus, not opaque internal graph clients or
  other transports. GracefulDrain/general retry helpers remain outside this scope.

Meaningful tests: per-round shared cap, actual CLI cross-scenario cap and frozen
plan, bounded concurrency across distinct adapters, cancelled queued task and
subsequent reuse, token-exceeding response nonexecution with raw-body retention,
unknown-usage follow-up refusal, invalid/missing usage labels, invalid limits,
no delayed exhausted-cap failure and stable identity despite usage counters.
A test-only class replacement initially contaminated a lazy import in another
suite; replaced it with scoped client injection and reran the combined suites
(40 passed). No production behavior was changed to accommodate that test bug.

Final full Python gate: **1357 passed, 2 skipped, 91.74% coverage**, 35.87s;
`/tmp/neuralstrike-phase2-runtime-full.log`. Optional base58/real NeuralGuard skips
remain unverified. Static checks and installed-wheel gate are recorded below.
No cloud inference, external target testing, dependency changes, publishing or
fleet integration activation. Phase 2 remains open for pinned MCP stdio/HTTP
profiles, broader lifecycle/reset failure and partial in-flight evidence paths,
secret-store references, explicit consequential-action idempotency decisions and
remaining interoperability receipts. Coverage is not security efficacy.

Final runtime gates:
- Ruff (`src tests examples/langgraph_account_support`) and mypy (`src`, 138
  files): pass; `git diff --check`: pass. Dashboard unchanged.
- Wheel/sdist built in `/tmp/neuralstrike-phase2-runtime-dist`. Reinstalled wheel
  into the existing isolated environment with no dependency/lock changes.
- From `/tmp`, confirmed installed-wheel imports and ran CLI against a separate
  authenticated loopback HTTP server with two selected scenarios and max-requests
  1. Exactly one actual dispatch occurred; the other trial retained an explicitly
  planned/refused envelope, and the CLI exited 3. Verified reported token source,
  unavailable/null cost, zero active slots after completion, frozen plan limits
  and absence of the synthetic header credential in JSON artifacts. Scratch root:
  `/var/folders/zv/n4210phd6_d5lqqfx462c9gw0000gn/T/neuralstrike-phase2-runtime-wheel-8yxp36u_`.
- No hosted CI result, external provider compatibility or security efficacy claim.
