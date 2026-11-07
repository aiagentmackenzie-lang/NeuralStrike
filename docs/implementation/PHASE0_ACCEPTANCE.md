# Phase 0 acceptance — 2026-11-06

Status: the master plan's Phase 0 acceptance gates pass for the controlled local
fixtures and tested environment below. This closes the Phase 0 engineering gate,
not production readiness, security efficacy, or broad protocol certification.
Prior progress entries recording open acceptance work are historical checkpoints.

| Master-plan requirement | Current evidence |
|---|---|
| Every verdict transition and failure policy | `test_baseline_contract.py`: all 27 verdict/policy combinations, incomplete/missing/corrupt/context cases. `never` explicitly overrides process failure, while retaining incomplete status. |
| Missing scenarios, partial failures, corrupt baselines and zero coverage cannot pass the default gate | `test_assessment_health.py`, `test_gate_command_consistency.py`, `test_baseline_contract.py`, `test_pack_comparison_identity.py`, `test_report_contract.py`. Supplied reproduction returns exit 3 for outages/missing/unresolved and exit 1 for a new vulnerability under `vuln`. |
| Concurrent runs and shorter reruns preserve separate consistent bundles | `test_run_evidence.py`: byte-preserving 3→1 rerun, unique concurrent directories, complete file hashes and execution IDs, interrupted writes/cancellation cannot claim committed evidence. |
| Strict local OpenAI-compatible server accepts supported histories and rejects malformed controls | `test_request_contract.py`: all 60 corpus scenarios accepted over loopback HTTP, duplicate-tool and orphan-result requests rejected HTTP 400; per-scenario mock-transport checks also pass. This is the supported request profile, not every provider protocol feature. |
| Synthetic secrets absent from rendered logs; raw handling explicit | `test_security_boundaries.py` positional/mapping/exception redaction and normal/disabled controls. `test_private_cli_artifacts.py`, `test_baseline_persistence.py`; EVIDENCE.md and REPORT_CONTRACT.md label outputs private/raw. |
| Changed A2A destination rejected before credentials leave unless explicitly allowed | `test_security_boundaries.py` origin/userinfo/redirect/card-mutation checks, explicit authorization control and client-certificate origin restriction. MockTransport policy checks; no live mTLS claim. |
| Discovery does not invoke tools; explicit declared fixture plan works | `test_security_boundaries.py`, `test_mcp_execution_plan.py`: read-only discovery, insufficient heuristic opt-in, exact selected name/arguments, duplicate inventories rejected before execution. |
| Fresh wheel smoke and complete unit/integration gates | 1,135 passed, 2 skipped, 91.83% Python coverage; Ruff/mypy pass; wheel/sdist build and isolated installed-wheel smoke pass. Dashboard unchanged since its recorded 12-test/build pass. Runtime/dev hashed-lock audits recorded in DEPENDENCY_REVIEW.md. |

The final review demonstrated an additional reference-overwrite defect: all
three baseline-capable CLI commands saved the candidate before comparing when
both directories were identical (including symlink aliases), then exited 0.
Six meaningful regressions failed before the fix. The commands now reject this
configuration with exit 3 before execution and preserve reference bytes.

## Reproduction and verification record

The supplied `evidence/deep_probe.py` was copied unchanged to
`/tmp/neuralstrike-phase0-acceptance/deep_probe.py` and run with the refreshed
Python 3.12 environment. Script SHA-256:
`f9d0a2ff9924810d8149e693c12a523b270475fc9439fda7c11e2677ca5c31a9`.
Original handoff evidence was not modified. New raw outputs remain outside git.

Observed: Succeeded→Inconclusive is not comparable (exit 3, no fixed label);
omitted scenario is not comparable (exit 3); Resisted→Succeeded under `vuln`
exits 1; both outage commands exit 3; outage SARIF reports unsuccessful
execution; rendered sentinel is redacted; reruns have distinct IDs/no stale
trials; indirect request is accepted. A plain synthetic text response still
exits 3 because it establishes no conclusive security outcome. The reproduction
also reports permissive empty scope: this is an unresolved authorization-policy
limitation, not an assertion that arbitrary external testing is authorized.
Mandatory target/scope preflight belongs to the next canonical-plan work.

Commands and local outputs:

- `python -m pytest --cov=neuralstrike --cov-fail-under=85` →
  `/tmp/neuralstrike-phase0-acceptance/full-suite.log`.
- `ruff check src tests`; `mypy src`; `git diff --check` → pass.
- `uv build --out-dir /tmp/neuralstrike-phase0-acceptance/dist` → build.log.
- Runtime-lock environment: reinstall the rebuilt wheel with `--no-deps
  --reinstall`; run from `/tmp`: `neuralstrike smoke --out
  /tmp/neuralstrike-phase0-acceptance/wheel-smoke --format json` → three
  scenarios/trials, including the intentionally vulnerable control.

The two skipped tests require optional base58 and real NeuralGuard packages.
Their absence does not count as successful validation of those optional paths.
Build metadata and pytest fixture-loop deprecation warnings remain; they do not
change observed gate results. No cloud inference, external target exercise,
release publication, or optional service activation was performed.

## Boundaries carried forward

Integrity-checked offline replay and rescoring, sanitized sharing exports,
authenticated remote build identity, mandatory canonical target/permission
preflight, complete request capture for every adapter, current protocol
interoperability, independent efficacy validation and pilot readiness remain
open. Model-name pack judge results are advisory benchmark evidence, not proof
of unauthorized application behavior. Raw evidence can contain sensitive data.
Coverage measures executed code, not security efficacy. See the master plan's
subsequent phases; no readiness claim is inferred from this acceptance record.
