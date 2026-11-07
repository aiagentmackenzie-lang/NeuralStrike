# Phase 2 engineering acceptance — 2026-11-07

Status: **candidate; final hosted verification pending**. This review covers the
explicit controlled profiles below. It does not establish customer security
efficacy, production readiness, universal framework compatibility, independent
reset attestation or authenticated remote build identity. Phase 3 efficacy/pilot
work is separate and has not been performed.

## Declared support matrix

| Profile | Supported interface and observations | Ownership, capabilities and exclusions |
|---|---|---|
| OpenAI-compatible finite Chat Completions JSON | Environment bearer reference via `doctor`/`corpus`; bounded actual JSON bodies; validated text/tool batches; supplied history and local canary receipts; shared corpus request/rate/concurrency/token admission | `text` never runs tools; `function-calling` serves inert local acknowledgments; only `instrumented` can execute explicitly supplied local canaries. No customer tool execution or remote reset. History markers prove supplied input, not native retrieval/memory consumption. Client close failures remain incomplete. |
| Local compiled LangGraph text-message profile | Real MessagesState graphs; `ainvoke` or explicit values-mode `astream`; verified/excluded input prefix; newly emitted actions and final text; append/output profiles | Explicit declared channel allowlist; fresh thread configuration and async reset/cleanup hooks are opt-in. Hook signatures are checked before graph resolution. Default extraction captures intermediate streamed observations; custom extractors retain explicit limitations. Graph/store lifetime belongs to the caller. |
| Modern MCP inspection | SDK 2.3.0, protocol 2026-07-28, bounded stdio and exact-endpoint Streamable HTTP JSON/SSE; real discovery, version/server receipts and offline integrity checking | Capability inspection, **not a security assessment**. Discovery is read-only; whole-plan explicit execution authorization; no inferred dangerous-name execution, continuation or retry. Static HTTP bearer references and explicitly selected stdio environment only. |
| Other adapters/profiles | Existing CLI/library compatibility remains available where previously supported | A2A identity, legacy MCP and LangGraph Server HTTP/SSE remain experimental. They do not inherit these acceptance claims. OAuth/extensions, secret-store backends and arbitrary native/detached work are excluded. |

The installed controlled graph profile is LangGraph **1.2.20**, langchain-core
**1.7.6**, langgraph-checkpoint **4.3.1**. The application receipt binds
`account-support-fixture/1`, source/scenario hashes and package versions. MCP
receipts retain actual negotiated revision and self-reported server version;
these are not signed build attestations. OpenAI records the declared JSON profile,
requested model and actual response metadata when supplied in private exchanges;
it does not invent a server revision/build from connectivity. Backend build
identity remains unavailable/unverified when the endpoint does not expose it.

## Master-plan gate review

| Required gate | Reproduction/acceptance evidence | Conclusion and scope |
|---|---|---|
| Same app/scenario: vulnerable → hardened → regression | `test_langgraph_application_cycle.py`, now through configured reset hooks and both real compiled `ainvoke`/values-stream paths; `examples.langgraph_account_support/verify.py` | Succeeded → Resisted → Succeeded; role admin → reader → admin; benign account task completes in all stages. Comparable fix exits 0; regression exits 4; original-oracle replay preserves source bytes. App imports no NeuralStrike code; this is a separately implemented controlled app, not a third-party efficacy cohort. |
| Real authenticated endpoint works from CLI without source editing | `test_corpus_target_auth.py`: separate stdlib loopback HTTP server, synthetic environment bearer, correct/incorrect credentials, doctor and corpus | Authenticated capability doctor exits 0; rejected credentials exit 3. Corpus connectivity alone remains Inconclusive/exit 3. No commercial provider or cloud inference claim. |
| Versioned protocol/server receipts; valid/invalid/timeout/auth paths | `test_mcp_protocol.py`, `test_mcp_profile_cli.py`, `test_mcp_receipt_integrity.py`, `test_target_preflight.py`; graph cycle's version/source-bound validation receipt | Modern MCP revision/server metadata are checked against independent stdlib and official SDK fixtures. Graph fixture/application versions are pinned. Missing OpenAI backend identity is explicitly unverified, not inferred. Wider revision/provider support is excluded. |
| No direct-prompt substitution for unavailable hooks | Declared-channel negative tests in `test_langgraph_transcript.py` and corpus CLI tests; `IndirectHarness.build_inputs` exhaustively constructs the selected vector | Unavailable declared channels fail before graph invocation; unknown vectors fail explicitly. Conversation history is labeled as that surface, not native retrieval or persisted memory. |
| Timeouts, cancellation, rates/budgets, reset/cleanup failures yield honest partial results and shutdown evidence | `test_openai_response_limits.py`, `test_openai_completion_health.py`, `test_partial_trial_evidence.py`, `test_outbound_runtime.py`, `test_langgraph_lifecycle.py`, `test_langgraph_stream_evidence.py`, `test_mcp_transport_cleanup.py` | Errors prevent complete negative/resistance/fix claims; confirmed observations survive later failure. Stream/client/child cleanup is attempted and failures recorded, never presented as clean shutdown. Cancellation propagates; incomplete journals remain uncommitted/replay-rejected. No hard cancellation or remote rollback claim. |
| Unknown usage is not zero/exact cost or a spend ceiling | `test_outbound_runtime.py`, MCP cost/receipt tests; PHASE2_INTEROPERABILITY.md and MCP_PROFILES.md | Provider-reported counts stay labeled; missing OpenAI counts use a named byte heuristic; MCP tool-internal usage/cost is unavailable/null. Token thresholds can overshoot on dispatched requests. No absolute spend ceiling. |

## Defects closed during this acceptance review

Failing-first tests exposed explicitly truncated/unsupported completion reasons
being scored as complete, invalid cleanup signatures allowing graph execution,
canary dispatch outside the instrumented tier, continuation after handler failure,
invalid handler results becoming corrupt receipts, preflight close exceptions
preventing durable receipts, and streamed actions being lost before termination.
A further regression froze streamed arguments against later application mutation.
See PROGRESS.md for red logs, commands and final verification evidence.

Complete finite HTTP capture and completed model generation are distinct facts.
An explicit `length`, `content_filter`, null, unknown or invalid `finish_reason`
now stops tool execution/continuation and records an error while preserving
validated emitted intent. Legacy endpoints omitting this optional profile metadata
remain compatible; omission does not attest untruncated backend generation.
Malformed batches are not executed. Local receipts prove only completed local
fixture handlers; emitted intent alone is not production execution.

## Verification

- Frozen Python 3.12.14 source suite: **1445 passed, 2 skipped, 91.79% coverage**
  (49.41s). Log: `/tmp/neuralstrike-phase2-accepted-full.log`.
- Ruff (`src tests examples/langgraph_account_support`), strict mypy (143 source
  files) and `git diff --check`: passed. Existing optional base58/real NeuralGuard
  skips remain unverified integrations. Coverage is not security efficacy.
- Wheel and sdist rebuilt at `/tmp/neuralstrike-phase2-acceptance-dist`; all 147
  checked packaged Python/JSON/YAML files match source. Separate hash-lock wheel
  environment, outside checkout: **133 Phase 2 checks passed** (10.88s).
  Log: `/tmp/neuralstrike-phase2-acceptance-wheel-tests.log`.
- Installed-wheel separate application cycle:
  `/tmp/neuralstrike-phase2-acceptance-cycle/validation-5e0df61fe7544321bdd375223b236c3d/validation.json`.
  Roles admin/reader/admin, task completion all three stages, reset completed,
  original-oracle replay agrees, fix exit 0 and regression exit 4. Installed CLI
  offline smoke also passes (three scenarios/trials).
- Hosted verification for the frozen implementation commit is pending. No Release
  workflow is part of acceptance. Do not infer results for a later source commit
  from an older green run.
