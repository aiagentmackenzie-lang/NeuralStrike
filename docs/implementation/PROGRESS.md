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
