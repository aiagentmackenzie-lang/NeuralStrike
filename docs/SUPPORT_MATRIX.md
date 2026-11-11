# Supported, experimental and excluded

What this repository claims to work, what it does not, and the limits that were actually
measured. Derived from [PHASE2_ACCEPTANCE.md](implementation/PHASE2_ACCEPTANCE.md), which is the
only engineering acceptance this project has; nothing here widens it.

Status: **Phase 4 is NOT RELEASED** — [PHASE4_PLAN.md](implementation/PHASE4_PLAN.md). A profile
listed as supported is supported **for the declared interface and observations only**, not as a
statement about any customer system's security.

## Supported

These carry the Phase 2 acceptance claims.

| Profile | Interface | What is observed | Limits that stay true |
|---|---|---|---|
| OpenAI-compatible finite Chat Completions JSON | `--adapter openai`; bearer supplied by environment **reference**, never inline (`--target-api-key-env`) | Bounded actual JSON bodies, validated text/tool batches, supplied history, local canary receipts, shared corpus request/rate/concurrency/token admission | `text` never runs tools; `function-calling` serves inert local acknowledgments; only `instrumented` executes explicitly supplied local canaries. No customer tool execution and no remote reset. History markers prove supplied input, not native retrieval or memory consumption. |
| Local compiled LangGraph text-message profile | `--adapter langgraph --module pkg.mod:attr` | Real `MessagesState` graphs, `ainvoke` or explicit values-mode `astream`, verified/excluded input prefix, newly emitted actions, final text | Explicit declared channel allowlist. Fresh thread configuration and async reset/cleanup are opt-in, and hook signatures are checked before graph resolution. Graph/store lifetime belongs to the caller. |
| Modern MCP inspection | `mcp-scan`, `mcp-inspect`, `mcp-receipt` | SDK 2.3.0, protocol revision 2026-07-28, bounded stdio and exact-endpoint Streamable HTTP JSON/SSE, real discovery, version/server receipts, offline integrity check | Capability inspection, **not a security assessment**. Discovery is read-only; explicit whole-plan authorization is required to execute; no inferred dangerous-name execution, continuation or retry. |
| Offline deterministic checks | `smoke`, `replay`, `rescore`, `efficacy` | Bundled-fixture scan, byte-verified bundle replay, deterministic-policy re-evaluation, label/prediction export | No model and no network participate. Replay proves the recorded evidence is intact; it does not re-run the target. |
| One-command assessment and offline comparison | `assess` (legacy alias `corpus`), `compare` | Frozen selection, committed hash-bound bundle, gate decision; two committed assessments diffed offline with the same decision function | Comparison refuses a different target, seed, trial count or scenario payload, and refuses an incomplete current assessment; it never turns a missing or inconclusive result into a fix. `corpus` prints a deprecation notice. |

## Experimental

Available, and deliberately **not** covered by the acceptance claims above. A result from these
is a local observation, not evidence.

| Surface | Why experimental |
|---|---|
| A2A identity (`a2a-scan`, `--adapter a2a`) | Identity and signature handling have not been exercised against an independent implementation |
| Legacy MCP revisions | Only 2026-07-28 is declared; older lifecycle behaviour is untested and must not be assumed |
| LangGraph Server HTTP/SSE (`--adapter langgraph-server`) | Not the compiled local graph path that Phase 2 accepted |
| `attack-memory`, judge hardening (`judge-audit`) | Measured locally, no independent labels or review |
| Adaptive attacks (`adaptive`: PAIR, TAP beam=1, Crescendo, trajectory-conditioned trace) | Iterative strategies against a real adapter; no acceptance record, and every result is a local observation |
| `evaluate` | k-trial canary-extraction probe. Its baseline gate is implemented and tested, but the probe's accuracy has no independent labels |
| `exec-context` | Execution-context and skill attack pack (poisoned skills, rules-file backdoors, triggered injection). No acceptance record |
| `minja`, `rag-poison` | Memory-injection and retrieval-corpus poisoning. Measured locally on declared profiles; corroborated nowhere outside this repository |
| `pack` | Benchmark packs (HarmBench / JailbreakBench / CyberSecEval). Correctness is bounded by the third-party corpus and its licence, not by this repository |
| `judge-model-list` | Operator utility: lists the models an Ollama endpoint has. Sends a request and attacks nothing |
| `purple-report` | Detection-coverage join against a live SecurityScarletAI deployment. Read-only there, but it needs that deployment to exist; a report without one is not a result |

## Legacy offensive commands — no acceptance claim

These fifteen commands are in the CLI, they are not in any acceptance record, and they are named
here so that "it isn't excluded, so it must work" is not the only available reading. Every row
below sends traffic to a model, a server or a network target. **None of them carries a Phase 2
acceptance claim**, none has an efficacy record, and a result from any of them is a local
observation — not evidence, and never a statement about a customer system.

The table is not prose: it is generated from `COMMAND_SURFACE` and `LEGACY_EFFECT` in
`src/neuralstrike/safety/surface.py`, and `tests/test_command_surface.py` fails if a legacy
command appears in the CLI without appearing here, or if either table is edited alone.

| Command | What it is | Effect class | Gate |
|---|---|---|---|
| `forge` | Iterative jailbreak loop (attacker → victim → judge) | local simulation | `--scope-file` / `--intent` / `--require-approval` |
| `poison` | Context manipulation and system-prompt extraction | local simulation | same |
| `exhaust` | Context-window exhaustion (DoS class) | local simulation | same |
| `recon` | Scans LLM endpoints and enumerates capabilities | informational | same |
| `hijack` | Tool-use parameter injection | local simulation | same |
| `confuse` | Tool-confusion attack (redirect to a decoy tool) | local simulation | same |
| `schema-poison` | Redefines a tool's purpose through its schema | local simulation | same |
| `intercept` | MCP interception proxy — forwards and can rewrite tool traffic | local simulation | same |
| `pivot` | Lateral movement across agent trust boundaries | experimental | same |
| `map-network` | Discovers agents and trust levels in a multi-agent system | informational | same |
| `extract` | Fingerprinting prompts against a model | informational | same |
| `timing` | Average response latency; **not** a model identifier | informational | same |
| `c2` | Persistent compromised-agent registry and dispatch (local JSON state, no daemon) | experimental | same |
| `evade` | Persona wrap, mimicry, delimiter wrap, invisible-Unicode steganography | local simulation | same |
| `neuralguard-bench` | Canonical attack chain against a NeuralGuard-defended victim | experimental | same |

Effect classes: **local simulation** drives a real model but has no independent acceptance record ·
**informational** reports an observation and asserts no vulnerability · **experimental** is an
attack technique with no efficacy record at all.

### What the gate on these commands does and does not do

It is the same gate the supported commands use — `_apply_scope` then `_apply_safety` — and it is
**opt-in**: `--scope-file` is enforced only when you supply one, exactly as on `scan` and
`assess`. This table does not create a global gate, and no document in this repository may claim
one. What it does create is uniformity: before this table existed, **11 of the 42 registered
command names** enforced both gates, **3** enforced the scope gate only (`doctor`, `mcp-inspect`,
`scope-check`), **1** enforced the HITL gate only (`safety-check`), and **27** enforced neither —
15 of which send traffic. Nothing in the repository said which was which.

Given a scope file, an out-of-scope target is refused before the attack code is constructed — a
contract proves this with a poisoned implementation that fails the test if it is ever reached.
Given `--intent`, an irreversible intent is refused without `--require-approval`. Neither check
sandboxes anything: they are operator controls, not containment.

## Excluded

Not supported, not claimed, and not to be inferred from a passing run:

- OAuth and MCP extensions, secret-store backends, arbitrary native or detached work.
- Customer tool execution, remote reset/rollback, hard cancellation, and any absolute spend
  ceiling: token thresholds can overshoot on a request that was already dispatched.
- Cloud inference in the bundled examples. Those run against local or synthetic targets only.
- Container depth is declared per architecture, not assumed: `linux/amd64` runs the full offline
  `smoke` in CI, while `linux/arm64` is built and exercised for startup and import only — a full
  langgraph smoke under QEMU would be a slow, flaky gate rather than a meaningful one. A full
  smoke on `arm64` is **not exercised** and must not be claimed.

## Measured limits

Numbers here come from the acceptance record, not from aspiration.

- Python: CI runs 3.11, 3.12 and 3.14 on `ubuntu-latest`; development and all Phase 3 local runs
  are on **macOS arm64, Python 3.12.14**. Nothing else is claimed.
- Container: `linux/amd64` image built and smoke-tested in CI, runs as uid 1000, artifact written
  mode 600. `linux/arm64` image built and started under emulation (import + `--help`) only.
- Coverage gate: **85 %** enforced, **91.98 %** measured locally on 2026-11-12 (2,700 passed, 7
  skipped of 2,707 collected). CI runs the same suite and skips seven more tests that need the
  private evidence root or the pinned tau-bench checkout; it reported 91.88–91.92 % in the last
  green run.
- Bundled offline smoke: 3 scenarios, 3 trials, ASR 33.3 %, coverage 100 % — a fixture check, not
  an efficacy result.
- Response bodies are bounded (default 16 MiB decoded, `--max-response-bytes`); provider-reported
  token counts are labeled, and missing counts use a named byte heuristic that is explicitly not
  exact cost.
- Partial failures stay partial: an incomplete or error-bearing trial cannot produce a
  resistance or fix claim, and confirmed earlier observations are retained rather than upgraded.

## How to check a claim

A claim in this repository should carry one of three marks: ✅ CI-verified, ⚠️ local observation,
❌ not implemented. If a document states a capability with no evidence path, treat it as a
defect in the document and report it.
