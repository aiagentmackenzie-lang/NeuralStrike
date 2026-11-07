# Capture and sharing profiles

The verified Phase 1 profile is an OpenAI-compatible JSON-body assessment using
controlled local fixtures, plus the bundled in-process graph fixture. This is
not a universal provider/protocol certification. Tests use synthetic credentials;
no cloud inference or external target exercises establish wider support.

| Workflow | Retained observation | Limits |
|---|---|---|
| OpenAI-compatible adapter | Actual JSON request for every round, injection-bearing messages/tool definitions, returned status/body/parsed JSON, sanitized endpoint, requested controls. Returned model/fingerprint/usage fields remain in response JSON when present. | Headers, URL userinfo/query/fragment are excluded. This is complete body capture, not a complete wire transcript or an authentication attestation. Providers can ignore controls or omit build metadata. |
| In-process graph | `langgraph-messages-v1` captures normalized input, returned and output-only text messages, newly emitted calls across all output turns and installed package versions. Custom extractors remain explicitly incomplete capture. | Append-mode checks the original input prefix; output-only/custom profiles must be explicit. No HTTP/provider-envelope or full internal-state claim. A sent marker does not prove target consumption. The separate account app provides controlled local consumption/state evidence; no customer efficacy claim. |
| Graph server | Planned inputs and normalized returned state. | Complete HTTP envelope/controls capture is not implemented; interoperability remains experimental pending Phase 2. |
| A2A | Planned inputs and normalized response. | Current adapter is text-only and ignores history/system-message channels. No indirect-channel or complete-envelope claim. Origin authorization does not authenticate an application build. |
| MCP | Read-only discovery and explicitly scoped fixture execution. | Discovery is not a behavioral security pass; this does not establish every HTTP revision or stdio interoperability. |
| Model-name evaluate / imported packs | Final payload, model/type/configuration identity and recorded observations. | No complete provider exchange history. Judge-only classification is advisory benchmark evidence, not proof of unauthorized application behavior. |

Unsupported/missing controls must not be inferred from seed metadata. Original
oracle verification requires a known data-only recipe and exact implementation
digest; custom/judged/unsupported records fail that mode explicitly. Ordinary
recorded-outcome replay remains a separate, labeled operation.

## Credential diagnostics

A new regression reproduced HTTPX status-error strings copying URL credentials
into exchanges, response errors, persisted JSON and logs. Another reproduced SDK
INFO records exposing the raw URL before adapter error handling. Neither proves
historical real-key exposure.

The OpenAI adapter now captures a structured class/status/credential-free endpoint
diagnostic. Authenticated or URL-bearing transport text is opaque, including
encoded echoes; ordinary credential-free details such as `boom` remain visible.
Redirect Location strings are not copied into status diagnostics. Captured
endpoints exclude fragments as well as userinfo/query. Default log filters and
formatters also remove those HTTP(S) URL components from SDK/traceback text.
Successful and failed request/response bodies within the accepted byte limit remain
exact private evidence. Phase 2 oversized streams record incomplete capture and
an explicit error; they do not retain a misleading truncated body.

One independent boundary investigation and one candidate bypass/regression
review were completed. The candidate review found the INFO route; new regressions
confirmed it before its fix. Verification includes 200/302/401/503 paths,
percent-encoded userinfo, query/fragment/redirect credentials, authenticated
connection/timeout/protocol errors, repeatedly encoded diagnostic URLs, both log
redaction mechanisms and ordinary connection-error controls. No authenticated
request behavior, header, tool action or response body was weakened for the fix.
The explicit log-redaction opt-out remains an opt-out; arbitrary target data in
raw bodies is not made safe by a diagnostic filter.

## Sharing boundary

`export-summary` validates a run or assessment first, then writes only allowlisted
counts, fixed outcome/fidelity/origin values and hash references. It excludes
freeform identifiers, targets, paths, models, prompts, histories, outputs,
arguments, oracle text, error text and raw policy/configuration data. A synthetic
sentinel placed across those fields is absent from the result. Summary files
remain mode 0600; exporting does not publish them.

The separate `neuralstrike-share-summary` profile is explicitly non-replayable.
It cannot establish remediation and is not accepted as a run/assessment. Export
exit 0 means file creation succeeded, not that the security assessment passed.
Hashes are linkable and are not an anonymity guarantee. A full scrubbed/replayable
sharing bundle is not implemented; retain the private original for audit/replay.

Phase 2 profile scope and compatibility: PHASE2_INTEROPERABILITY.md.
