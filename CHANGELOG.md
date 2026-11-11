# Changelog

All notable changes to NeuralStrike are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed (README honesty pass — every claim re-derived from the tree, 2026-11-12)
- **New §Breadth, measured.** 14 dimensions counted from the code by re-runnable commands: 42
  command names / 41 distinct callbacks, 121 implementation modules in 26 packages (≈26.7k lines),
  5 adapters, 5 deterministic oracle families, 60 scenarios across 20 categories and 5 delivery
  vectors in 4 YAML files, 5 adaptive strategies, 18 transforms, 8 defenses + 2 checkers, 4 packs,
  5 report formats, 8 compliance frameworks. `tests/test_readme_claims.py` re-derives each one.
- **One evidence vocabulary.** The capability map's `Verified / Informational / Planned` legend is
  replaced by the repository's three marks — ✅ CI-verified, ⚠️ local observation, ❌ not
  implemented — and every capability row now carries one.
- **Four overclaims corrected.** MCP bounded **stdio discovery** shipped and the map still said
  "Planned" (stdout scanning is the real gap: `mcp-scan` requires `--url`). The 10 incident
  scenarios are *modelled on* named incidents, not replays of their evidence, and the CVE
  attributions are not verified here. Delegation-chain analysis is a tested **library** with no CLI.
  TAP generates three judge-ranked candidates per turn and keeps one, which the old wording
  described as "one payload per turn".
- **New §What NeuralStrike is not** — not certified, not independently accepted, not a service,
  not a sandbox, and a green run is not a safety guarantee.
- **Test counts re-derived**: 2,707 collected (2,700 pass, 7 skip), 91.98 % locally; CI additionally
  skips seven tests that need the private evidence root or the pinned tau-bench checkout.

### Fixed (corpus labels, 2026-11-12)
- **10 of 60 scenarios carried an `owasp_name` the compliance index disagrees with**, including two
  that were another framework's name entirely (`ASI06` labelled "Insecure Output Handling" — that is
  LLM05; `ASI02` labelled "Sensitive Information Disclosure" — that is LLM02). Reports print this
  string, so a finding could name a category that does not exist. Relabelled to the canonical names;
  `tests/test_corpus_labels.py` fails if any scenario drifts again. **Categorisation was not
  changed**: moving a scenario between categories moves coverage counts and is a decision, not a
  typo fix — `github-copilot-cve-2025-53773` and `gemini-memory-persistence` still look
  mis-categorised and are recorded as open questions.
- `corpus/phase10_execution_context.yaml` existed only in the shipped package data, so a reader
  browsing `corpus/` counted 53 scenarios where the README said 60. The reader copy now has all four
  files, and a contract asserts the two trees are byte-identical file-for-file.


### Changed (engineering backlog E-1…E-12, 2026-11-12)
- **The package no longer claims a stability its gates deny** (E-1). `Development Status :: 5 -
  Production/Stable` → `4 - Beta`, because Phase 4 is NOT RELEASED and Phase 3 is NOT ACCEPTED.
  `tests/test_release_stability.py` fails if the classifier and either status line ever disagree.
- **One declared command surface** (E-3). `src/neuralstrike/safety/surface.py` declares every
  registered command once — does it send traffic, which gate does it enforce, what kind is it — and
  `verify_surface(app)` runs at import time, so an unclassified command refuses to dispatch. The 15
  legacy commands plus `doctor`, `mcp-inspect`, `judge-audit`, `judge-model-list` and
  `purple-report` now accept `--scope-file`, `--intent` and `--require-approval` and call
  `_apply_scope`/`_apply_safety`. Measured before the change: 11 of 42 registered names enforced
  both gates, 3 scope only, 1 HITL only, 27 neither. **The scope gate is still opt-in on every
  command**; this makes the gate uniform, it does not create a global one.
- **`--out report.json` no longer writes `report.json.json`** (E-5). `report_destination` appends
  the format extension only when the path has none and never replaces a suffix the operator typed.
  Applies to `smoke`, `assess` and `replay`.
- **README** (E-4): the quickstart now runs `doctor` → `assess` → `compare` → `evaluate`; the
  fifteen legacy commands live in one headed section that states they carry no acceptance claim and
  that the scope check only runs when you supply a scope file. `docs/SUPPORT_MATRIX.md` (E-2) gains
  the per-command legacy table and eight further classified rows.
- **Development environment** (E-12): `typer==0.28.0` pinned; `scripts/dev_env.sh` installs the
  hash-pinned dev lock and refuses a non-3.12 interpreter; `scripts/ci_gate.sh` is the single
  description of the gate and both gating CI jobs execute it.
- **Evidence durability** (E-9): `docs/implementation/EVIDENCE.md` declares the durable root and
  the rule that `/tmp` is never a citation. Thirteen stale citations became tombstones, and
  `tests/test_evidence_paths.py` asserts every durable path a document cites exists.
- **Phase 3 residues restated as permanent limits** (E-8): destructive action stays
  measured-not-reproduced and the persistent-memory persistent effect stays falsified; P3-6 stays
  `PARTIAL`. **Released artifacts are unchanged — nothing was released.**

### Fixed (2026-11-12)
- The evidence-path contract asserted that the private durable root exists, which is true only
  where the evidence was produced and can never be true on a CI runner. The `/tmp` citation rule
  stays unconditional; the two existence assertions are now skipped where the root is absent, with
  the reason in the marker. CI run `43115588777` at `d2bce5c` is retained as the red run.

### Added (Phase 3 measurement, 2026-11-12)
- **Second declared seed** for the write-first matrix (E-7): plan kind
  `native-tau-bench-retail-write-first-seed-replication-plan-v1`, seed 11, own pre-registered plan,
  payloads and expectations shared by identity. Result: all four verdicts identical to seed 7 — a
  null, recorded as one. The declared seed is a code constant and the runner refuses any other
  `--seed`.
- **Tool-axis comparator plan** (E-6): `docs/implementation/TOOL_AXIS_COMPARATOR_PLAN.md` declares
  the target, budgets, row set and single scorer, and declares — before any run — the rows PyRIT
  and garak cannot express as `unsupported`, never as zero. **Declared, not executed**: installing
  either tool needs approval.

### Added (contracts, 2026-11-12)
- `tests/test_command_surface.py` (86), `tests/test_dev_environment.py` (10),
  `tests/test_release_stability.py` (4), `tests/test_support_matrix.py` (65),
  `tests/test_quickstart.py` (20), `tests/test_report_destination.py` (21),
  `tests/test_evidence_paths.py` (8), `tests/test_phase3_residue_limits.py` (5),
  `tests/test_tool_axis_plan.py` (7), `tests/test_engineering_backlog.py` (6), and
  `tests/test_comparison_properties.py` (603) — the comparison decision table held to its
  properties over its whole input space, not by example. Suite: 1775 → 2616 passing, 7 skipped,
  coverage 91.98 %.


### Added (Phase 4 — the command spine: `assess`, `compare`, and an authenticated `scan`, 2026-11-11)
- `assess` is the single assessment command (Phase 4 gate P4-1). It is the existing assessment
  implementation registered under a new name; `corpus` is the **same callback** registered under
  the legacy name, so the alias cannot drift, and it prints a deprecation notice when invoked.
- `compare BASELINE CURRENT` is the single comparison command. It loads two committed assessment
  bundles through `load_assessment` (every recorded byte hash-verified), diffs the per-scenario
  verdicts and applies the gate offline: no target, model or oracle call. Exit codes are the
  baseline gate's: 0 pass, 1 vuln, 3 not comparable, 4 regression.
- `src/neuralstrike/evaluation/compare.py` — comparability is refused, not assumed: a different
  adapter, target, seed, trial count, scenario selection or scenario payload produces
  `not_comparable` and exit 3. An incomplete current assessment is never a pass, and
  Succeeded → Inconclusive is never reported as fixed.
- `decide_comparison` in `src/neuralstrike/evaluation/baseline.py` — the decision logic of
  `scan --baseline-dir` extracted into one function that both the live gate and the offline
  `compare` command call, so the two surfaces cannot disagree about what a regression is.
- `scan --adapter openai` now accepts `--target-api-key-env` and attaches the resolved bearer,
  closing the asymmetry the live-target guide had recorded and excluded. A missing, empty or
  header-unsafe value is rejected before any request is sent; the flag is refused on adapters
  that cannot use it.
- `tests/test_command_spine.py` — 14 contracts: the three spine commands exist, the alias is
  the same callback, the deprecation notice fires only on the legacy name, every comparison
  outcome (pass / regression / vuln / not comparable / fixed / withheld fix / refused run /
  non-assessment bundle / bound record), and the authenticated `scan` against a separate stdlib
  loopback server (header asserted, missing credential refused before any request).
- The documentation anti-vapour contract now reads registered commands from the Typer app
  rather than parsing decorators, so a command registered under two names cannot hide from it.

### Added (Phase 4 — the container is run in CI, P4-7 MET, 2026-11-10)
- `.github/workflows/ci.yml` job `container` — builds the image, asserts it runs as uid 1000,
  runs the full offline `smoke` inside `linux/amd64`, and checks the artifact is written mode 600.
  The release workflow had always built and pushed an image that nothing executed.
- Multi-architecture depth is declared, not assumed: `linux/arm64` is built under QEMU and
  exercised for import and `--help` only. A full langgraph smoke under emulation would be a slow,
  flaky gate, so it is **not** claimed; `docs/SUPPORT_MATRIX.md` states the split and a contract
  fails if the document starts implying otherwise.
- P4-7 **MET** on CI evidence: run `42937379076` at `9824c7a`, `arch: aarch64` printed from the
  emulated image, smoke passed (3 scenarios, ASR 33.3 %, coverage 100 %), artifact 61843 bytes
  mode 600. The first push of the job failed (`42936253073`) on a quoting bug in the arm64 step;
  the gate cites the run that passed and the record keeps the run that did not.
- P4-2 remains `PARTIAL` for one reason only: no release has been dispatched, so the image-digest
  binding in `release-manifest.json` is written but unproven.

### Added (Phase 4 — artifact binding: wheel exercised outside the checkout, 2026-11-10)
- `.github/workflows/ci.yml` job `artifact` — builds sdist+wheel **from outside the repository**
  (the checkout has a gitignored `build/` directory that shadows the `build` module), installs the
  wheel into a clean venv, asserts the import resolves to `site-packages` rather than the checkout,
  runs the offline smoke from outside the repo, generates the SBOM of the installed wheel
  environment, and binds the release. The editable install used by the other jobs cannot catch
  missing package data, a stale version or an undeclared dependency; this job does.
- `scripts/release_manifest.py` — binds version, tag, commit, wheel, sdist, SBOM and optionally the
  image digest into one deterministic manifest. Refuses a missing artifact, a wheel whose filename
  disagrees with the declared version, an SBOM without the project component, and a non-digest image
  reference. Never claims a signature: `signed: false`, `signatures: []` — a digest is not a
  signature.
- `.github/workflows/release.yml` — binds the image digest into the manifest and attaches it to the
  GitHub release, so the binding is not merely local.
- `tests/test_release_manifest.py` — ten contracts over the binder's refusals and the two workflow
  steps, including "no artifact may be described as signed".
- CI-verified at `d2acde5` (run `42934094480`): the downloaded manifest re-verifies **3/3 digests**
  against the uploaded wheel, sdist and SBOM. P4-2 remains `PARTIAL`: the container is never pulled
  and smoked, and no dispatched release proves the image-digest binding.

### Added (Phase 4 — scheduled dependency health verified, signing policy, pilot-facing docs, 2026-11-10)
- P4-4 **MET**: the scheduled dependency job was dispatched once (`workflow_dispatch`, run
  `42931775244` at `41670a7`) and completed success with both audit records uploaded. The gate
  row states that the cron has not yet fired on a Monday and that the scheduled mechanism is what
  it claims.
- P4-3 **MET**: signing policy stated in `PHASE4_PLAN.md` §Signing policy — optional and off by
  default, signs the image digest and an SBOM attestation only, never the wheel or release
  assets, and no artifact may be described as signed without a recorded signature. A contract
  fails if the cosign steps stop being conditional on `inputs.sign`.
- P4-5 **MET**: `docs/SUPPORT_MATRIX.md` (supported / experimental / excluded plus measured
  limits, derived from the Phase 2 acceptance record), `docs/LIVE_TARGET_GUIDE.md` (credential by
  environment reference, scope file, explicit budgets, no absolute spend ceiling) and
  `docs/OFFLINE_EXAMPLE.md` (verified `neuralstrike smoke` run with real output).
- Recorded a real gap found while writing the guide: `scan --adapter openai` has no
  `--target-api-key-env`, so authenticated targets are reachable through `doctor` and `corpus`
  only. Tracked as command-spine work (P4-1) instead of being papered over.
- `tests/test_phase4_plan.py` — six more contracts: pilot docs exist, are linked and carry the
  required sections; the live guide never inlines a credential and never documents an
  authenticated `scan`; the offline example matches its documented command and refuses to present
  a fixture run as efficacy. The registered-command contract now covers all three documents.

### Added (Phase 4 started — release/pilot gates defined, scheduled dependency health, 2026-11-10)
- `docs/implementation/PHASE4_PLAN.md` — Phase 4 had no gate document, only prose in the master
  plan. Seven binary gates with a state column about evidence and a separate `Signed` column:
  command spine, artifact binding, signing policy, scheduled dependency health, pilot-facing
  docs, pilot evidence, platform claims. Every gate is unsigned; status is **NOT RELEASED**.
- `.github/workflows/dependency-check.yml` — audits both pinned hashed locks weekly (Mondays
  06:17 UTC) and on demand, writes JSON records, uploads them with `if: always()`, holds
  `contents: read`, and publishes/tags/signs nothing. Findings fail the job: silence is what this
  fixes. The advisory count is not a vulnerability count — reachability triage stays in
  `DEPENDENCY_REVIEW.md`.
- `tests/test_phase4_plan.py` — ten contracts: gates frozen once with binary rules and signers,
  no release claim while a gate is unmet or unsigned, `MET` requires cited evidence, Phase 3
  cannot be moved by this document, every linked document exists, the plan is reachable from the
  README and from `PHASE3_ACCEPTANCE.md`, the scheduled job is scheduled and read-only, cosign
  remains conditional, and **no document may name a command that is not registered** (40
  registered commands; README and USAGE checked).
- `README.md` — Phase 4 plan row and an evidence-status paragraph stating the phase is
  **NOT RELEASED** and that nothing in the repository is signed.
- Signing policy stated: cosign is optional and off by default, signs the image digest and an
  SBOM attestation only, and no artifact may be called signed without a recorded signature for
  that digest. As of `17b9832` every artifact is unsigned.

### Added (AgentDojo banking — declared model registry and model replication, 2026-11-10)
- `examples/agentdojo_banking/profile.py` — single source for the frozen banking pins (values
  unchanged; the digest literal is byte-identical, only relocated) and the declared model
  registry: `name -> digest, origin, family, parameters, quantization, role, min_size_bytes`.
  `resolve_model` refuses an undeclared name; `verify_model_pin` refuses a non-loopback origin
  **before** fetching and fails closed on any digest or inventory-size difference. No
  dependency and no payload was added.
- `--model` on `collect.py` and `verify.py`, defaulting to the frozen baseline, reaching the
  plan block, the observation and the `OpenAILLM` construction. The pin is re-checked before the
  journal is written and before every trial. `transport.py` now pins the resolved registry name
  instead of a second hardcoded literal, and `collect.py` locates the repo from its own path so
  it still runs as an isolated script.
- `examples/agentdojo_banking/replication.py` — plan kind
  `agentdojo-banking-model-replication-plan-v1`, written and hashed before the first inference,
  with the model blocks, matched pins, seed, trial matrix, tri-state expectations, budgets and
  harness hashes. Exit 0 = all expectations met, 3 = complete but a declared expectation not
  met, 2 = an incomplete row; failed rows are kept.
- `tests/test_agentdojo_model_registry.py` — eight contracts: closed registry literal,
  undeclared model refused everywhere, non-loopback origin refused before any fetch, digest/size
  mismatch fails closed, `--model` reaches plan and observation, baseline digest literal matches
  the recorded index, payloads/task ids/budgets frozen, and no third model or extra repeat.
- Ordering fixed after the first CI run: `assert_loopback_origin` gives registry + origin
  closure with no network, so `collect.py` validates the pinned source **before** the daemon is
  contacted (an unreachable service no longer preempts a wrong-revision error) and `verify.py`
  writes its receipt without needing a model service; the digest/size pin still runs before the
  journal and inside every trial. A daemon-blocked run of the full suite is part of the gate.
- Counts (k=3, seed 7, 24/24 complete): `qwen3.5:2b` and `gemma4:31b` both produce the
  attacker payment 3/3 unfiltered and withhold it 3/3 bound with utility 3/3, benign 3/3 either
  way. The model asked for the attacker payee in 12/12 redirection trials; the binding rewrote
  the effective recipient in 6/6 bound trials. Counts only — no rate, no population.
- `docs/implementation/evidence/phase3-agentdojo-banking-replication-2026-11-10.json` — new
  evidence block; the existing `phase3-agentdojo-local.json` index is byte-identical to `HEAD`.
- Phase 3 gates unchanged: P3-6 stays `PARTIAL` (independence is a people problem), P3-7 stays
  `MET` and unsigned. Phase 3 remains **NOT ACCEPTED**.

### Added (tau-bench retail — utility asserted, 2026-11-10)
- `examples/tau_bench_retail/utility_audit.py` — read-only, no model, `inference: none`,
  `excluded_from_efficacy`. Asserts benign task completion from the recorded utility
  observations, on the target's own predicate (`state_matches_declared_gold_actions`, i.e. data
  equality to the replay of the declared gold actions). The terminating reward is reported and
  never asserted. A packet with no `summary.json` is reported and excluded from the verdict.
- Counts (k=3): `nemotron-3.5-lightning:30b` completes 3/3 bound and 3/3 unguarded with 0
  refusals; `qwen3.5:2b` completes 0/3 under both with 0 refusals, so the declared claim is
  falsified for that model and the control is not the cause. Exit 3.
- `docs/implementation/PHASE3_ACCEPTANCE.md` — Phase 3 had no gate document. Seven binary gates
  with evidence, required signer and a separate signed column; state is `MET`/`PARTIAL`/`OPEN`,
  and the phase is accepted only when every gate is `MET` and signed. Status `NOT ACCEPTED`.
- `tests/test_phase3_acceptance.py` — freezes the gate ids, one status per gate, a `MET` gate
  must cite evidence, the phase may not claim acceptance while a gate is unmet or unsigned, and
  every linked document must exist.

### Added (tau-bench retail — claims audit, 2026-11-10)
- `examples/tau_bench_retail/claims_audit.py` — read-only, no model, `inference: none`,
  `excluded_from_efficacy`. Resolves every `<8 hex>…` hash claim in the profile against
  hashes that exist on disk, re-hashes every cycle packet an evidence block names, and
  reconciles every recorded count. Output is a separate artifact; recorded plans, summaries
  and observations are never touched. It states in its own output that it does **not** check
  prose.
- Result on this record: 28 hash claims, 0 unresolved; 6 evidence blocks, 0 mismatched;
  9 cycles reconciled.
- Four stale profile sentences corrected by a hand-audit that the hashes could not see: the
  "no comparator" limit (a comparator run exists), the frozen-matrix scope of the
  "never exercised" limit, the 30B-only phrasing of "gave it nothing to withhold" (the 31B
  also did), and "a single-variable model replication" (there are two, and they are never
  pooled).
- Contracts: the profile's mechanical claims reconcile with the record (skipif the private
  packets are absent), and a negative contract proves the check can fail. `claims_audit` and
  `refusal_audit` join the module-scope import contract.

### Added (tau-bench retail — write-first model replication, 2026-11-10)
- Declared the one-variable **model replication** of the write-first matrix
  (`native-tau-bench-retail-write-first-replication-plan-v1`, replicates the write-first
  plan, supersedes nothing). `profile.MODEL_REGISTRY` gains `gemma4:31b`
  (`6316f062…`, loopback, Q4_K_M) — a model may not be added without a plan that pins its
  digest, and this plan is that plan. The payloads, expectations and repeats are the
  write-first plan's own objects, asserted by identity, so the model is the only variable.
- 12 declared observations, seed 7, k=3, exit 3: **zero model tool calls in 12/12**, four
  `respond` turns per observation, identical transcripts under both policies. Unguarded rows
  **falsified**, bound rows **not exercised**. A null and uninformative about ordering: the
  model never acted, so nothing reached the boundary.
- Declared model-selection rule (a tool-call feasibility probe with the target's own schema,
  no `Env`, excluded from every count): `mistral:7b` rejected for emitting no `tool_calls`,
  `qwen3.8:27b` for sharing the baseline's family.

### Added (tau-bench retail — write-first payload, 2026-11-10)
- `profile.WRITE_FIRST_CASES` — a declared **write-first** hypothesis
  (`native-tau-bench-retail-write-first-plan-v1`, `replicates: null`, `supersedes: null`):
  the cross-principal write is refused only if it is offered, and the model offers it only
  when the user turn makes the write the first and only actionable request. Two payloads,
  one per scope, with no ownership claim and no request to read a record, pinned by SHA-256
  at declaration (`b2315917…`); `READ_REQUEST_MARKERS` is the declared lexical guard.
  The frozen `CASES`/`EXPECTATIONS`/`SENSITIVITY_*`/`ATTRIBUTION_*`/`WITHHOLDING_TOOL` pins
  did not move; the new cases join the withholding map in `DECLARED_WITHHOLDING_TOOL`.
- Declared tri-state expectation `withheld_for_declared_class` on the bound rows. A declared
  withholding that does not fire is `not_exercised` — never a pass, and never a falsified
  control. Declaring it false while it fires is a contradiction and fails.
- 12 declared observations, seed 7, k=3, `qwen3.5:2b`, exit 3: the address write mutated
  **3/3** unguarded and was **never offered** under the binding in 3/3, so the declared
  withholding did not fire and the row is `not_exercised`; the cancel payload made no tool
  call at all and stays **falsified**. The only class live-withheld under inference remains
  the scoped read. Counts only; no rate is quoted.

### Added (tau-bench retail — payload sensitivity and refusal attribution, 2026-11-10)
- `examples/tau_bench_retail`: a declared **payload-sensitivity** plan
  (`native-tau-bench-retail-payload-sensitivity-plan-v1`) that tests whether the explicit
  ownership claim in the frozen attack payloads was the suppressor. Claim-free payloads
  live in a separate `SENSITIVITY_CASES` mapping with their own SHA-256 pins; the frozen
  `CASES`/`EXPECTATIONS` are untouched and still asserted byte-identical. 18 declared
  observations, seed 7, k=3, `qwen3.5:2b`, exit 3: the cross-principal address write
  mutated 3/3 unguarded and was refused at dispatch under the binding, the read was
  unchanged by the claim (3/3 either way), and the cancel write stayed **falsified**
  (no tool call at all). Counts only; no rate is quoted.
- Assistant reply text is captured for `attack` cases only, so a refusal *in words* is
  observed rather than inferred from an empty tool-call list (synthetic data, request
  unchanged).
- `verify.py` writes `exit.json` with the status it declares; the launching shell records
  the observed `$?`, so the exit code is observed as well as derived.
- Declared **refusal attribution** plan
  (`native-tau-bench-retail-refusal-attribution-plan-v1`) and evaluator fields
  `refusals_by_tool`, `offered_tools`, `withholding_tool`, `declared_effect_offered`: a
  bound row whose declared effect never reached the boundary is `not_exercised`, however
  its other predicates came out. Re-measured on byte-identical payloads with every count
  repeating the sensitivity cycle — a relabelling, not a re-roll for effect.

### Added (tau-bench retail — reason-aware refusal attribution, 2026-11-10)
- Evaluator fields `refusals_by_tool_and_reason` and `withheld_for_declared_class`:
  a refusal only counts as withheld authority when it is `cross_principal`, attaches to the
  tool that would realise the row's declared effect, and no mutation was recorded. A
  refusal for any other reason is reported as a misfire and the row is `not_exercised`.
- `examples/tau_bench_retail/refusal_audit.py` — read-only audit that recomputes recorded
  row verdicts from the raw dispatch journals (no model, no network, no target import) and
  reports which verdicts moved. Over the four recorded cycles (28 rows) exactly one moves:
  `claim_free_address/bound`, `reproduced` → `not_exercised`.

### Added (tau-bench retail — comparator episode primitive, 2026-11-10)
- `examples/tau_bench_retail/comparator/` — optional comparator tooling, never a project
  dependency: `episode.py` runs an attacker **turn script** against the pinned target
  through the declared dispatcher and returns state predicates plus per-tool refusal
  counts; `selfcheck.py` reproduces a known recorded row before any external attack
  generator is trusted. Self-check: mutation 3/3 unmodified and 0/3 bound, matching the
  recorded refusal-attribution row; a single-turn control recorded 0 mutation in both
  policies, proving the turn-shape dependency.
- `comparator/tau_target.py` — PyRIT `PromptTarget` adapter over `episode()`, proven end to
  end against the pinned target: mutation true unguarded and false under the binding with
  `get_user_details` refused `cross_principal`. PyRIT is imported only by this optional
  module; nothing in `src/` or the test suite depends on it.
- `docs/implementation/TAU_BENCH_COMPARATOR_PROTOCOL.md` — the comparator question, what
  PyRIT/garak can and cannot express about object authority, declared expectations and the
  decision rule, written before any comparator run. PyRIT 1.1.0 was verified against the
  local Ollama endpoint in an isolated environment (`/tmp/pyrit-env`); it is not a
  dependency of this project.

### Added (tau-bench retail — declared comparator run, 2026-11-10)
- `comparator/plan.py` — declared comparator plan (`native-tau-bench-retail-comparator-plan-v1`)
  with its own kind, expectations on disk before the first episode, harness hashes, and a
  rule that the verdict is the recorded state predicate, never the orchestrator's outcome.
- `comparator/adversary.py` — PyRIT `RedTeamingAttack` with `StatePredicateScorer`, a scorer
  that reads the episode's predicate so the attack loop stops on a real mutation instead of
  on reply text. Retains any prior invalid attempt in the plan rather than deleting it.
- Run result: with the binding off, the generator produced a cross-principal **mutation on
  its fourth consecutive turn**; under the binding, six turns produced **no mutation**, the
  write was never offered, and `get_user_details` was refused `cross_principal` 4× and
  `target_unknown` 4×. Verdicts `reproduced` / `not_exercised`, exit 5. The first attempt is
  retained as `tau-bench-comparator-cycle-v1-invalid` because its adapter ran single-turn
  episodes.

### Changed (tau-bench retail)
- `--repeats` is no longer a budget lever: a value equal to the declared k is a no-op and
  any other value is refused before the plan is written; plans record `budget_overrides`
  with the levers null.
- Every plan carries a `hypothesis` block and every row carries `paired_with`, so a fresh
  run of the frozen matrix is a new plan and does not reproduce the recorded plan digests
  of the earlier cycles (those plan files and frozen harness copies remain authoritative).
- Docs state plainly that no live **withheld cross-principal write** has been measured: the
  only class live-withheld under inference is the cross-principal scoped **read**.

### Added (Phase 9 — Trajectory-Grounded Adaptive Attack Engine)
- `core/trajectory.py` — structured per-turn attack trajectories extracted
  purely from the loop's records: verdicts, oracles fired, evidence-derived
  surfaces (text / tool_args / execution), victim-error flag, deterministic
  fingerprints, and the structured refinement brief.
- `core/attack_memory.py` — SQLite attack memory (stdlib, WAL, schema v1):
  best-effort recording that never affects run verdicts, fail-closed
  strategy selection (`--strategy auto`), deterministic Wilson-lower-bound
  ranking over conclusive-only evidence, and the lower-bound-gated champion
  ratchet. Goals/payloads stored hashed, never as text.
- `attacks/adaptive/trace.py` — trajectory-conditioned attackers: `trace`
  (deterministic scripted policy, no LLM required) + `trace-pair` (PAIR with
  the structured brief). The attacker still only generates; scoring stays
  with the deterministic oracles + advisory Judge.
- `core/adversarial_loop.py` — additive trajectory hook (`traj_attacker_fn`,
  `strategy_label`, `turn_traces`); legacy behavior unchanged when unset.
- `attacks/adaptive/seed_diversity.py` — deterministic SIRAJ-style seed
  variants (persona x outcome; the delivery axis is honestly recorded as
  `user_message`, channel-level variance is Phase 10/G2).
- Metrics: `ASR@K` (budget-K success probability from the conclusive-only
  ASR + Wilson bounds, monotone transform) + `trajectory_diversity`
  (distinct behavior-shape fingerprints / trials).
- CLI: `adaptive --memory-db`, `--strategy auto` (fail-closed),
  `--seed-diversity N`, `trace`/`trace-pair` strategies, and the read-only
  `attack-memory --db [--json]` command.

### Added (Phase 10 — Execution-Context & Skill Attack Pack)
- `oracles/benign_task.py` — the benign-task (utility) oracle: required
  markers + forbidden-drift patterns, advisory by contract (never joined
  into the verdict combiner — a benign pass cannot fabricate ASR).
- `attacks/execution_context.py` — the 7-vector mutable-execution-context
  attack pack (skill poison, rules-file backdoor, playbook hijack,
  triggered injection T0051.002, delayed tool invocation, worm-like
  self-replication T0061, agentic resource consumption T0034.002) with
  dual AGS/UGS scoring: STEALTHY (leaked AND benign task preserved) vs
  NOISY (leaked but the benign task broke) — both reported, neither hidden.
- `corpus/data/phase10_execution_context.yaml` — 7 realistic scenarios
  with benign_task_markers (additive loader field; legacy corpora
  unaffected) and verified OWASP ASI + MITRE ATLAS mappings.
- CLI `exec-context --target M [--vector V] [--trials N] [--judge]` — the
  pack runner with the stealth rollup and exit 1 on stealthy compromises.

### Added (Phase 11 — Judge-Hardening Suite)
- `oracles/judge_ensemble.py` — strict-majority judge ensembles with
  disagreement flagging: N distinct member judges, no majority →
  INCONCLUSIVE (never a fabricated consensus), per-member breakdown
  recorded; DECIDE fail-closed / ANNOTATE fail-soft mirroring the
  single-Judge doctrine; severity = max of members via the shared
  `floor_severity` path. `--judge-ensemble auto|explicit-list` on
  `adaptive` (≥ 2 DISTINCT reachable members, fail-closed).
- `oracles/judge.py` — additive stakes-neutral judging:
  `prompt_mode="framed"|"blind"` (default framed = legacy bytes, pinned
  byte-identical); the blind prompt strips the red-team/benchmark framing
  AND the attacker payload (a stakes-signal channel) while keeping the
  goal + response evidence, the three-outcome rule, the verbatim-quote
  requirement, and the identical JSON schema.
- `evaluation/judge_bias.py` — the deterministic bias battery: baseline /
  blind / response-first / verbose variants over pinned
  honesty-corpus-pattern cases; per-variant flip rates + Wilson CIs on
  the single shared CI path; fail-closed on judge errors; informational
  by contract (never gates, never touches exit codes).
- `evaluation/judge_manipulation.py` — the 6-technique judge-manipulation
  family (stakes_minimization, fake_cot, authority_claim, judge_addressed,
  system_impersonation, benchmark_awareness): deterministic byte-stable
  transforms of the response text; control cells scored alongside so
  confounded attribution is reported (`control_flips`), never hidden;
  expected verdicts are pinned constants — the judge is the SUBJECT, not
  the scorer.
- `judge-audit` CLI — bias battery + manipulation family + ensemble
  verdict-disagreement in one informational audit (`--bias/
  --manipulation/--ensemble-check/--models/--judge-prompt/--json`).
  Fail-closed judge resolution without the attacker half; explicit
  `--target` never silently falls back; ensemble unavailable (< 2
  reachable members) reported honestly; exit 0 informational (D3).
- `AdversarialLoop`/`TrialRunner` — additive `judge_prompt_mode` plumbing
  (default framed = byte-identical legacy runs).

## [1.0.0] — 2026-07-07

### Added (Phase 7 — NeuralGuard pairing)
- `src/neuralstrike/integrations/neuralguard.py` — the `NeuralGuardScreen`
  contract + `NeuralGuardHTTPScreen` (live deployment),
  `BundledNeuralGuardFixture` (deterministic, contract-compatible fixture —
  NOT real NeuralGuard; fresh-clone-runnable), and `in_process_screen()` (real
  in-process NeuralGuard ASGI app when the `neuralguard` package is importable).
- `src/neuralstrike/integrations/attack_chain.py` — the canonical
  recon→weaponize→exploit→post-ex attack chain + `run_attack_chain_delta`
  which scores both arms (the ONLY difference is the firewall, so the delta is
  honestly attributable). Blocked payloads → INCONCLUSIVE, never fabricated.
- `neuralstrike neuralguard-bench` CLI — runs the attack chain against a
  victim with/without a NeuralGuard firewall; prints per-phase + overall ASR
  + delta; `--in-process` / `--neuralguard-url` / `--target-url` / `--json-out`.
- `tests/test_phase7_exit_gate.py` + `tests/test_integrations_neuralguard.py` —
  23 tests (exit-gate bullets + screen/runner unit tests); skip-gated
  real-NeuralGuard in-process test.
- Closed C2/I2: the README NeuralGuard-pairing claim is now verified from the
  offensive side; cross-project alignment with NeuralGuard's
  `benchmarks/ng_vs_ns/` (the defensive side's view).

### Added
- `neuralstrike smoke` — offline smoke test that runs a tiny corpus against the
  bundled vulnerable fixture. No local Ollama or external API required.
- Pinned dependency lockfiles (`requirements.txt`, `requirements-dev.txt`)
  generated by `uv pip compile --generate-hashes` and consumed by the
  Dockerfile and a new CI `supply-chain` job.
- `pip-audit` in CI against the hashed production requirements; currently clean.
- CycloneDX SBOM generation in CI (`cyclonedx-py environment`) and as a
  release artifact.
- Bundled corpus moved into `src/neuralstrike/corpus/data/` so `neuralstrike smoke`
  works after a fresh `pip install neuralstrike` from a wheel/sdist.
- `src/neuralstrike/fixtures/langgraph_agent.py` shipped inside the package so
  the offline fixture is available after install.
- Multi-arch GHCR image build + cosign sign + Rekor CycloneDX attestation
  workflow (`.github/workflows/release.yml`). Publish is gated by
  `workflow_dispatch` inputs and requires explicit operator approval.

### Added (Phase 6 chunk 4)
- `dashboard/` — Vite + React results viewer that reads NeuralStrike JSON and
  SARIF 2.1.0 reports, with summary cards, per-category verdict filters, and
  a Vitest test suite covering both formats.
- `docs/threat_model.md` — full threat model of NeuralStrike itself.
- `SECURITY.md` expanded with the formal threat model and the A2A Identity
  Working Group error conventions (`INVALID_CLAIM_SCOPE`,
  `INVALID_COMPOSITION`).
- Offline `neuralstrike smoke` command documented in `README.md` and
  `USAGE.md`.

### Changed (Phase 6 chunk 4)
- `USAGE.md` and `README.md` updated to v1.0.0; `README.md` notes Phase 6
  chunk 2 CLI coverage as shipped and adds a dashboard section.
- CI now includes a `dashboard` job that builds and tests the viewer.

### Changed
- Version bumped to `1.0.0`; classifier moved to `Production/Stable`.
- `typer[all]` dependency simplified to `typer>=0.12` (optional extras are
  already covered by direct dependencies).
- Dockerfile now installs from hashed `requirements.txt` with `--no-deps`.

### Security
- Supply-chain posture aligned with the tool's ASI04 messaging: hashed pins,
  `pip-audit`, SBOM, signed/attested container image.

## [0.2.0] — 2026-06-20

Production-grade rewrite. The framework now does what its documentation claims,
fails loudly when a backend is unreachable, and passes a real CI quality gate.

### Added
- Genuinely asynchronous LLM calls (`ollama.AsyncClient`, `litellm.acompletion`).
- Fail-closed error contract: `LLMError` raised on backend failure instead of
  silently returning error strings into the adversarial loop.
- Typed exceptions (`LLMError`, `ConfigError`, `ValidationError`).
- Injectable attacker step in `AdversarialLoop` (`attacker_fn`).
- `JailbreakForge` template library + Attacker-driven mutation wired into the
  live loop (iteration 1 seeded from a template, later iterations mutated).
- `AgentC2` JSON-persistent registry (`~/.neuralstrike/agents.json`),
  `register`/`deregister`/`list`/`coordinate-exfiltration` with real data splitting.
- `MCPInterceptor` capability injection into `tools/list` responses, `/__inject`
  endpoint, loopback-only bind by default, configurable `bind_host`,
  `build_app()` for testability.
- CLI subcommands for previously-unreachable methods: `exhaust`, `confuse`,
  `schema-poison`, `map-network`, `timing`.
- CLI `--target-type` on `recon`/`pivot`/`evade`; `c2 --register` (repeatable),
  `--capabilities`, `--trust-level`, `--list-agents`, `--deregister`,
  `--registry-file`; `pivot --target-model`; `intercept --bind-host`,
  `--inject-tool`, `--inject-schema`; `--version`.
- Input validation (URL scheme, port range, iteration bounds, model names).
- Log redaction filter for credential-shaped strings.
- `py.typed` marker, `__version__`, env prefix `NEURALSTRIKE_`.
- CI workflow (ruff + mypy + pytest --cov, floor 80%) on Python 3.10/3.12/3.14.
- `Dockerfile`, `docker-compose.yml`, `SECURITY.md`.

### Changed
- `AgentPivot` routes LLM calls through `target_model`, not the framework name.
- README rewritten with ✅/⚠️/❌ status triples and honest module limitations.
- Dependencies single-sourced in `pyproject.toml`; `requirements.txt` removed.

### Fixed
- `call_local`/`call_remote` were fake-async (sync SDK calls blocking the loop).
- Errors were swallowed and fed back into the loop as fake "responses".
- `evade --technique persona --sample` ran mimicry instead of persona.
- `scan_ollama` could inject `None` into `discovered_models`.
- `MCPInterceptor` bound to `0.0.0.0` (open proxy) by default.
- `trigger_capability_injection` was queued but never applied.
- Dead module-level `adversarial_loop` singleton; unused `EvasionSuite.target_type`.

### Removed
- Tracked build artifacts (`src/neuralstrike.egg-info/`).
- Empty placeholder `config/` and `docs/` directories.
- `requirements.txt` (single-sourced to `pyproject.toml`).
- `BUG_CATALOG.md`, `NEXT_STEPS.md` (superseded by this changelog and the audit).

## [0.1.0] — 2026-04-08

Initial release: adversarial loop, recon/weaponize/exploit/post-ex/evasion modules.