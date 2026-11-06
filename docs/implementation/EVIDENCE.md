# Phase 0 evidence contract

`scan` and `corpus` preserve private per-scenario evidence under
`runs/<unique-run-id>/` (override with `--run-dir`). Corpus JSON also embeds the
original run under each scenario's `evidence` key. Run manifests enumerate hashed
files. A manifest's `complete` state means persistence finished; it does not mean
assessment coverage was complete or the target was secure. Execution health is
reported separately.

OpenAI-compatible evidence includes sent request JSON for every round, returned
JSON and HTTP status/errors, alongside adapter inputs and execution/delivery
traces. Each request is captured before the next round alters its messages.
Headers and URL userinfo/query are excluded; raw request/response bodies may
contain sensitive target data. Directories use mode 0700 and files 0600 on POSIX.
Corpus reports use atomic private writes. These files are **private raw evidence**.
There is no sanitized sharing/export command yet; do not treat report formats as
sanitizers. Embedding or publishing the JSON can disclose target content.

Runner seeds/temperatures are task-local and supplied to supported OpenAI and
LiteLLM requests. Recording a sent seed does not prove a provider honored it or
that a live rerun will match. Other adapters currently preserve planned inputs,
not complete provider envelopes. Offline integrity-checked replay is still a
separate outstanding workflow.

Modern adapter baselines bind scenario, target configuration, tool definitions,
oracle configuration and implementation digests. Credentials are excluded from
target configuration. Remote application builds are not authenticated by these
digests. Different configuration or missing modern identity is non-comparable;
regenerate old scan baselines with the current command before using them to gate.
Programmatic legacy baselines remain readable but lack those assurances.
