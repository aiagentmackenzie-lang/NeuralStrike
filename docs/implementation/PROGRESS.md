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
