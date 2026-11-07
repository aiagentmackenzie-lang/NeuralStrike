# Phase 2 interoperability — work in progress

Current implementation increments: 2026-11-07. Phase 2 is **not accepted** yet.
Phase 1 evidence gates remain the prerequisite; see PHASE1_ACCEPTANCE.md.

## Implemented OpenAI boundary

`corpus --adapter openai` accepts `--target-api-key-env NAME`, resolving the
bearer credential from the process environment before creating an assessment.
Missing/empty values and header newlines are rejected. No credential value is
written into the plan or default diagnostic receipts. Header capture remains
excluded. Private provider bodies can still contain sensitive data or provider
echoes; this is not automatic secret removal from raw evidence.

`--max-response-bytes` defaults to 16 MiB per response, counting decoded streamed
bytes on both successful and failed HTTP responses. It does not trust
Content-Length. An oversized body records incomplete capture and an explicit
error without writing a misleading truncated JSON body. HTTP status and request
context remain available. This bounds accepted response data, not total process
memory: transport buffers, a decompressor's current chunk and parsed JSON have
additional memory costs. It is not a total assessment disk or spending budget.

Before any local tool handler runs, the complete returned message/tool batch is
validated: text/null content, function objects, nonempty unique IDs, names and
JSON-object arguments. Invalid batches retain their exact bounded private
response but produce an error with no handlers executed from that batch. Earlier
rounds, if any, are preserved; this cannot undo already executed actions.

No automatic request retry has been added. HTTP 429/503 are explicit errors, not
retried completions or security passes. Cancellation propagates and closes the
in-flight response stream; adapter ownership still requires client closure.

## Doctor capability receipt

Use an authorized endpoint and a credential already supplied through your
process environment (synthetic examples below):

```sh
neuralstrike doctor --url http://127.0.0.1:8000 --model local-fixture \
  --target-api-key-env TARGET_TEST_KEY --timeout 10 \
  --max-response-bytes 1048576 --out preflight.json
neuralstrike corpus --adapter openai --url http://127.0.0.1:8000 \
  --model local-fixture --target-api-key-env TARGET_TEST_KEY \
  --max-response-bytes 1048576 --timeout 10 --limit 1 --fail-on vuln
```

Doctor sends completion requests, potentially incurring inference cost when
pointed at a paid provider. Default `--tools` asks for a harmless
`neuralstrike_preflight({"value":"probe"})` call and serves a canned local result.
`--text-only` checks completion shape without requiring a tool call. The overall
deadline covers all completion rounds, and the client closes on success, failure
and cancellation. It does not run customer tools or canary handlers.

Receipt kind `neuralstrike-target-preflight`, schema 1, is deliberately distinct
from assessment evidence. Exit 0 means the requested capability was observed;
exit 3 means incomplete. `security_assessment` is always false. Missing tool calls
are reported as capability not demonstrated, without asserting universal lack of
support. Authentication configured is not authentication/authorization attested.
Client package versions are recorded; server build identity and protocol revision
are not independently established. Raw completion bodies/headers are omitted.
The receipt is private when written with `--out`, but is not a replay bundle.

## Demonstrated fixture scope

- A separate Python standard-library loopback HTTP server accepts/rejects a
  synthetic bearer credential and serves an OpenAI-shaped tool round-trip.
  CLI doctor succeeds only for the authenticated capability case.
- CLI corpus records actual 200/401 exchanges. A valid authenticated completion
  without the scenario's required evidence remains inconclusive, exit 3 under
  `--fail-on vuln`. Connectivity is not resistance.
- Controlled transport tests cover streaming overflow, exact boundary, compressed
  overflow, malformed message batches, cancellation, deadline, rate limits,
  outage, credential omission from artifacts and no automatic retry.

These HTTP checks establish transport handling, not hosted-provider certification
or an efficacy cohort. The separate controlled LangGraph cycle is described below.

## Separate LangGraph application cycle

`examples/langgraph_account_support/application.py` contains a real compiled
LangGraph/MessagesState app with an application-owned role store and tools. It
imports neither NeuralStrike nor its canary harness/oracles. Its deterministic
planner deliberately models a trust defect: a retrieved instruction can cause a
privilege change. Hardened mode treats that document as data and still executes
an authorized account lookup. The same graph, scenario, seed and application
identity produce Succeeded → Resisted → Succeeded; baseline comparison reports a
fix and then regression exit 4. The task-completion marker remains present in all
three stages. The app also records which retrieval document the node consumed
and which tool changed its store. This is local fixture evidence, not a learned
model, third-party efficacy cohort or production compromise.

```sh
python -m examples.langgraph_account_support.verify --out /tmp/account-validation
neuralstrike corpus --adapter langgraph \
  --graph-module examples.langgraph_account_support.application:vulnerable \
  --scenario-dir examples/langgraph_account_support \
  --graph-channel retrieved_document --graph-channel user_message \
  --format json --out /tmp/account-vulnerable --run-dir /tmp/account-runs --fail-on vuln
```

Use `:hardened` for the hardened CLI target. The script creates a unique private
validation directory with frozen parent assessments for each stage, per-run
bundles, baselines and `validation.json`. The receipt binds source/scenario
hashes, installed package versions, assessment manifest hashes, observation IDs,
independent app events, role state, task completion and comparison outcomes.
Offline original-oracle verification agrees without modifying source bundles.
The app/events are controlled by the same local operator, not signed or remote
attestations. Retrieval is an explicit conversation ToolMessage surface, not a
remote database/index hook. Findings stay IntentToAct: app state observations do
not impersonate the local-canary receipt format or automatically promote fidelity.

The default adapter profile `langgraph-messages-v1` now verifies the returned
input prefix, excludes supplied history calls and extracts every new assistant
call, including calls before a final plain-text answer. It retains normalized
input/returned/output messages and installed LangGraph/LangChain/checkpoint
versions in the private exchanges. Unknown/missing/non-text states and changed
input prefixes fail explicitly. The snapshot is a text-message transcript,
not every internal graph state field or model/provider wire envelope.

Compatibility rules:

- Append-mode is the default. A graph that returns only new messages must choose
  `messages_mode="output"` explicitly through the Python API. A graph that edits
  or removes its input history needs an application-specific extractor/profile;
  it cannot silently reinterpret supplied calls as fresh output.
- Existing `state_builder`/`result_extractor` callbacks remain usable with custom
  states. Their capture is explicitly incomplete; generic full-state capture is
  not claimed. These callbacks execute trusted local Python code.
- Async invocation and explicit values-mode streaming are supported. A synchronous-
  only graph now fails before execution, rather than blocking the event loop or
  leaving an uncancellable executor thread executing tools after timeout. Provide
  a cooperatively cancellable `ainvoke` integration. This deliberately narrows
  the legacy sync fallback; no hard cancellation of arbitrary application code
  is promised. The adapter does not take ownership of external app resources.
- `--graph-channel` is a repeatable declared capability allowlist. Unsupported
  selections return an explicit error before invoking the graph, never a direct
  prompt substitution. With no declaration, the legacy conversation-state
  surface is retained; sent markers alone do not prove target consumption.
- Missing `module:attribute` names no longer fall back to another module graph.
  Baseline comparability for anonymous object graphs requires a stable explicit
  `target_id`; a module spec also supplies configuration identity. This is a
  declared app family, not source/build authenticity. Profile/channel changes
  change the comparison digest; old fingerprints are not silently upgraded.

The transcript profile follows the installed real MessagesState/add_messages
semantics ([official reference](https://reference.langchain.com/python/langgraph/graph/message)).
Verified local versions: LangGraph 1.2.20, langchain-core 1.7.6 and
langgraph-checkpoint 4.3.1. These receipts establish this local version profile,
not support for every framework revision.

## Actual OpenAI outbound limits

The existing `RateLimiter`, `ConcurrencyLimiter` and `Budget` helpers are now
wired to OpenAI request dispatch through one shared `OutboundPolicy` per corpus
assessment. This includes every tool continuation and every scenario adapter.
Controls remain opt-in, preserving existing CLI defaults:

```sh
neuralstrike corpus --adapter openai --url http://127.0.0.1:8000 --model local-fixture \
  --target-api-key-env TARGET_TEST_KEY --max-requests 20 \
  --requests-per-minute 30 --max-concurrent-requests 1 --max-total-tokens 10000 \
  --timeout 10 --fail-on vuln
```

`--max-requests` limits admissions before transport; failed/cancelled admitted
requests count conservatively. Exhausted caps fail immediately, without waiting
for another rate token. Rate admission is evenly spaced, with one initial token;
concurrency is shared across adapter instances and released on cancellation.
Corpus still runs scenarios sequentially; the concurrency setting does not claim
a parallel corpus scheduler. Limit configuration is frozen in declared scope
and baseline comparison identity; mutable counters do not change identity.
Adapters that cannot enforce these outbound options reject them explicitly.
This increment applies to `corpus --adapter openai`, not opaque graph-internal
clients, model-name workflows or MCP. There are no automatic request retries.

`--max-total-tokens` is a **post-response stopping threshold**. Valid nonnegative
integer `usage.total_tokens` is labeled provider-reported, not independently
metered. Missing/malformed counts use an explicit JSON-byte/4 heuristic labeled
estimated. Mixed sources remain labeled. Usage is accounted before any tool
handler processes that response. Exceeding the threshold preserves the bounded
raw response and produces a budget error; no tool from that response is executed.
At/above the threshold, further dispatch is refused. Concurrent in-flight calls
and the request that crosses the threshold can overshoot. Unknown usage after a
failed request prevents further token-budgeted dispatch rather than assuming zero.

Cost is `null`/unavailable: no price table or exact provider billing is inferred.
There is no absolute token or spend ceiling. The older Budget helper's numeric
accumulators are internal accounting, not proof of zero cost when usage is absent.
Request-level receipts record source, count, limit semantics, shared-policy
snapshot and available response evidence. `request_status=planned` distinguishes
an admission-refused planned envelope from an attempted request; this is not a
proof of remote receipt. Budget and transport errors remain incomplete trial
results, never confirmed fixes or resistance. CLI `--fail-on never` retains its
explicit report-only exit behavior and does not change recorded health.

The rate helper's wait-accounting defect has a permanent deterministic clock
regression: one request per ten seconds admits at 0, 10, 20, rather than 0, 10,
10. Concurrency statistics no longer introduce a second cancellation-sensitive
lock after semaphore acquisition. Tests cover shared caps, tool continuations,
unknown usage, post-response tool nonexecution, waiting-task cancellation,
malformed usage, invalid configuration and actual CLI cross-scenario wiring.

## Pinned modern MCP profile

The optional maintained Python MCP SDK is pinned at 2.3.0. Modern
`mcp-inspect` supports explicit 2026-07-28 stateless discovery over real stdio
and Streamable HTTP; `mcp-receipt` validates its immutable capability receipts
offline without the SDK. Independent stdlib and official SDK fixture checks cover
JSON/SSE, synthetic auth, version/inventory failures, no automatic tool retries,
request/rate controls and cancellation/cleanup failures. Execution is opt-in with
a whole-plan validation boundary, not inferred from advertised tools.

The existing `mcp-scan`/MCPHTTPAdapter API remains experimental legacy compatibility,
now explicitly labeled as descriptor observations. Modern receipt completion is
never a security verdict, and the dashboard does not score such receipts. See
[MCP_PROFILES.md](MCP_PROFILES.md) for runnable commands, precise limits, unsupported
features, evidence and lifecycle semantics. These tests establish a narrow local
protocol profile, not complete MCP/OAuth conformance or customer-agent efficacy.

## Remaining Phase 2 gates

The controlled LangGraph app gate now has runnable evidence. The master plan
now has a pinned, locally verified MCP stdio/HTTP profile. Phase 2 still requires
remaining application reset/thread lifecycle and cleanup-failure cases, preservation
of earlier observations when an OpenAI/graph trial times out in flight, and broader
explicit hook/capability interoperability checks. Arbitrary application-owned
resources and detached processes are not guaranteed cancellable. Credential/build/
principal identity remains unverified beyond declared configuration and captured
self-reports; the protocol receipts do not establish live remediation. Environment
references are supported; secret-store adapters are optional and unimplemented. A2A identity and other framework/protocol profiles remain
experimental. Provider usage/cost unavailable means unknown/estimated, not zero
and not an absolute spend ceiling.
