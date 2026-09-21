# Changelog

All notable changes to NeuralStrike are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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