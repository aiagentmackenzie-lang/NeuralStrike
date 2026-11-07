# MCP protocol profiles — 2026-11-07

Phase 2 supports a deliberately narrow modern inspection profile alongside the
existing experimental legacy API. An inspection is a protocol/capability receipt,
**never a security assessment, resistance result or remediation verification**.

| Entry point | Declared profile | Verified local scope |
|---|---|---|
| `mcp-inspect --url ...` | MCP 2026-07-28, Streamable HTTP; Python SDK 2.3.0 | Exact endpoint, static bearer reference, finite JSON and SSE responses; independent stdlib and official SDK servers |
| `mcp-inspect --stdio-command ...` | MCP 2026-07-28, bounded newline-framed stdio; SDK protocol engine 2.3.0 | Trusted local executable, POSIX process group, minimal inherited environment; independent stdlib and official SDK servers |
| `mcp-scan` / `MCPHTTPAdapter` | Experimental legacy JSON-RPC/2025-06-18 compatibility | Existing descriptor heuristics and controlled old fixtures; no modern transport or behavioral security verdict claim |
| `mcp-receipt DIRECTORY` | Data-only capability receipt schema 1 | Offline inventory/hash/status verification; no SDK, target import, model call or tool execution |

The modern implementation uses the maintained SDK for typed protocol validation,
request metadata, correlation and result handling. It explicitly selects the
[2026 protocol era](https://github.com/modelcontextprotocol/python-sdk/blob/main/docs/protocol-versions.md),
performs actual `server/discover`, and requires the selected version in the
response. The pinned client mode alone is not treated as evidence of server
support. No legacy `initialize`/session fallback is allowed. HTTP requests carry
the modern protocol/method headers; stdio requests carry the SDK's modern metadata.
This is not a claim of every revision, extension or OAuth flow's conformance.

## Controlled local commands

Install the project's MCP extra or use its hashed runtime/development locks.
The examples require the checkout; third-party server code is never bundled into
an inspection or automatically imported during receipt verification.

```sh
# No inference and no tool execution: launch the controlled server over stdio.
neuralstrike mcp-inspect --stdio-command python \
  --stdio-arg=examples/mcp_profile/server.py --run-dir /tmp/mcp-evidence

# Explicitly authorized read-only fixture tool call (JSON map order is preserved).
printf '%s\n' '{"read_account":{"id":"synthetic"}}' > /tmp/mcp-call-plan.json
neuralstrike mcp-inspect --stdio-command python \
  --stdio-arg=examples/mcp_profile/server.py \
  --execution-plan /tmp/mcp-call-plan.json --run-dir /tmp/mcp-evidence

# Offline verification; DIRECTORY is the printed mcp-<uuid> directory.
neuralstrike mcp-receipt DIRECTORY
```

For the authenticated HTTP fixture, start a local server in one terminal:

```sh
MCP_FIXTURE_BEARER=synthetic-local-only python -m examples.mcp_profile.server \
  --transport http --port 8765
```

In another terminal, explicitly supply the matching synthetic credential:

```sh
export LOCAL_MCP_KEY=synthetic-local-only
neuralstrike mcp-inspect --url http://127.0.0.1:8765/mcp \
  --target-api-key-env LOCAL_MCP_KEY --max-requests 20 \
  --requests-per-minute 60 --timeout 10 --run-dir /tmp/mcp-evidence
```

`--stdio-env CHILD_NAME=SOURCE_ENV` passes an explicitly selected process
environment value to a stdio child. Default inheritance is limited to HOME,
LOGNAME, PATH, SHELL, TERM and USER, excluding shell-function values. Bearer
credentials are HTTP-only. Header/environment values are excluded from the
configuration receipt; raw target bodies may still echo sensitive values.
Stdio executable/argument paths are private configuration data, not redacted
sharing output. Starting a server executes trusted code; this is not a sandbox.

Exit 0 means the requested protocol workflow completed. Exit 3 means incomplete,
invalid or corrupt evidence. Missing optional SDK/configuration fails before a
server is started. None of these exit codes establishes a security pass. The
legacy command remains available, with experimental descriptor-only labels;
its heuristic findings do not establish unauthorized application behavior.

## Execution authorization and no-retry boundary

Default requests are `server/discover` and paginated `tools/list` only. Discovery
never infers permission from a name, description or advertised capability.

An explicit execution plan maps each exact advertised name to its complete
arguments. All selections and schemas are checked before any selected tool is
called; an invalid later selection cannot execute a valid prefix. Repeated JSON
keys, non-finite numbers, unknown names, duplicate inventories and invalid
arguments are rejected. Map order is frozen separately in `execution_order` so
sorted JSON serialization cannot reorder consequential operations.

Only a bounded structural JSON Schema 2020-12 subset is accepted for execution.
Input/output regexes, references, composition, header annotations and other
unsupported constructs fail explicitly; they remain visible in discovery.
Depth is limited to 16 and property/enum lists to 128. This is a conservative
execution support boundary, not a demonstrated exploit of every excluded schema.
Remote schema resolution is not performed.

The SDK may correctly filter an invalid tool descriptor. We compare its usable
inventory with the actual bounded replies: a filtered/changed/omitted descriptor
makes inspection incomplete and is retained as a raw name, rather than silently
presenting a smaller complete inventory. The original bodies remain private.

Selected calls use the SDK's low-level single-dispatch method, bypassing its
high-level input-required retry driver. Input-required, extension/unknown result,
`isError`, timeout and transport failures stop further execution. No automatic
sampling, elicitation, MRTR continuation or retry is authorized. A started call
may have acted even if its reply failed; this is not rollback or exactly-once
remote execution. Operators must establish target state before a manual retry.

HTTP redirects, including self-redirects, are rejected before the SDK can resend
a POST. Requests outside the exact configured URL/method fail before dispatch.
Proxy environment settings are disabled. Userinfo/query/fragment credentials are
not accepted by this profile; TLS verification remains enabled. OAuth discovery,
legacy SSE/GET sessions, subscriptions, Tasks and MCP Apps are outside this matrix.

## Bounds, lifecycle and private evidence

- Overall deadline defaults to 10 seconds; cleanup can add bounded grace time.
  RPC admission defaults to 64 requests and concurrency 1, using the existing
  shared request/rate/concurrency controls. Inventory is capped at 10 pages and
  1,000 unique tools, with repeated cursors rejected. A budget exhausted before
  inventory or execution completes remains incomplete.
- Default accepted request/response size is 1 MiB, configurable up to 16 MiB.
  HTTP bodies and stdio lines are bounded before protocol parsing. Finite SSE
  bodies also have the SDK event bound. This limits accepted data, not total RSS:
  transport/decompressor chunks and typed/JSON copies require additional memory.
  Oversized/incomplete input is explicitly labeled, not a complete truncated body.
- Transcript capture stops at 128 records / 32 MiB of compact observation data;
  individual serialized artifact files are capped at 64 MiB. Stream data is
  private; stdout records and HTTP bodies are not a full provider-wire capture.
  Headers and stderr are omitted. SDK diagnostics are opaque during this task;
  bounded original data and safe exception classes/RPC codes remain available.
  SDK logging outside this task retains its normal behavior.
- Cancellation commits available evidence, closes owned resources and propagates.
  Stdio closes stdin, waits, then signals its private process group if necessary.
  Forced, failed or unreaped cleanup stays incomplete, including a failed pipe
  close. A parent exit does not hide ordinary surviving children. Detached
  processes and kernel-level kill survivors are not a process-isolation promise;
  unsuccessful cleanup is recorded, not called a clean shutdown.
- HTTP CLOSED state alone is not proof of a successful resource close. Close
  success is tracked separately; failed closing remains an explicit partial
  result. Resources owned by a remote server remain the server's responsibility.

Each invocation creates a unique private `mcp-<uuid>` directory with `plan.json`,
`transcript.json`, `receipt.json` and a committed SHA-256 manifest. Files are atomic
mode 0600 and the inspection directory is mode 0700. A running manifest cannot be
verified as committed. Reruns create new directories, preserving the original.
SDK/server/protocol versions, target configuration, RPC metadata, usable/raw inventory,
selected/attempted calls, partial failures and cleanup facts remain distinct.
Server identity/version is self-reported, not a signed build or principal claim.

`mcp-receipt` checks exact file inventory, hashes, schemas and complete-status
invariants, including plan order and omitted descriptors. It never loads target
code or the protocol SDK. These are capability receipts, not canonical security
assessment replay/rescore bundles. Hashes establish internal consistency, not
producer authenticity. Full raw artifacts remain private; sanitized MCP sharing
is not implemented. The dashboard rejects this kind and explicit non-assessment
provenance even when the document includes JSON/SARIF-shaped assessment fields.

MCP tools can internally call paid providers. Their token use and cost are
unavailable/null, not zero; this client does not meter those effects or promise a
spend ceiling. No cloud inference or external-target exercise was used to verify
this profile. Coverage is not security efficacy.

## Verification scope

`test_mcp_protocol.py`, `test_mcp_profile_cli.py`, `test_mcp_transport_cleanup.py`
and `test_mcp_receipt_integrity.py` exercise independent stdlib and official-SDK
servers over real stdio/HTTP, JSON/SSE, synthetic authentication success/failure,
version rejection, malformed/oversized data, pagination, schema/plan rejection,
no automatic continuation, cancellation, parent/child cleanup, failed closes,
unknown usage, opaque SDK logs, rehashed contradictory receipts and offline
verification with SDK imports/network prohibited. Dashboard tests cover the
non-assessment boundary. See PROGRESS.md for final gate results and artifact
locations. Verified host profile is POSIX/macOS, Python 3.12; hosted CI and every
other OS/Python matrix are not inferred from that local result.
