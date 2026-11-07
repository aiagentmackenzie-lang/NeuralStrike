# Phase 2 interoperability — work in progress

First implementation increment: 2026-11-07. Phase 2 is **not accepted** yet.
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

This is independent HTTP protocol handling, **not** an independently validated
LangGraph customer agent, hosted-provider certification or efficacy cohort.

## Remaining Phase 2 gates

The master plan still requires an independently implemented LangGraph app with
vulnerable → hardened → regression evidence; pinned MCP stdio and declared HTTP
revision profiles using appropriate maintained libraries; explicit unsupported
hook/capability behavior; actual outbound rate/concurrency/budget controls;
reset/thread lifecycle and cleanup-failure verification; idempotency decisions
for consequential actions; and versioned interoperability receipts across valid,
invalid, timeout and authentication paths. Secret-store references are not yet
implemented. A2A identity and other framework/protocol profiles remain
experimental. Provider usage/cost unavailable means unknown/estimated, not zero
and not an absolute spend ceiling.
