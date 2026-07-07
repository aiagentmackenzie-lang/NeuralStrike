# NeuralStrike Threat Model

This document models threats against NeuralStrike **itself** — the tool, the
runtime that hosts it, and the artifacts it produces. It is not a threat model
of the targets NeuralStrike is pointed at; that belongs in the operator's
engagement documentation.

## Scope and assumptions

**Assets**

1. Operator host — the workstation, CI runner, or container running NeuralStrike.
2. Operator credentials — API keys, Ollama endpoints, signing keys, GitHub/PyPI
tokens used by or adjacent to the tool.
3. Attacker / Judge models — local or remote LLMs that generate payloads and
score responses.
4. The MCP Interceptor proxy — FastAPI process that rewrites tool traffic.
5. The AgentC2 registry — local JSON state file simulating a compromised-agent
registry.
6. Generated reports — SARIF, JSON, JUnit, Markdown, PDF artifacts that may
contain canaries, tool-call traces, or excerpts from the target.
7. The NeuralStrike package and container image — supply-chain artifact.

**Trust boundaries**

- The operator host is trusted.
- The target system is untrusted and potentially hostile.
- The network between NeuralStrike and external targets is untrusted.
- Third-party models (remote APIs, Ollama if not locally controlled) are
semi-trusted: they see prompts but must not receive operator credentials.

## Threat inventory

### T1 — Supply-chain compromise of the NeuralStrike package or image

**Description:** An attacker modifies a released wheel, source repository, or
container image to inject malicious code into operator environments.

**Impact:** Arbitrary code execution on operator hosts; leaked engagement data;
degraded trust in red-team findings.

**Controls**

- Dependencies are pinned with SHA-256 hashes in `requirements.txt` and
`requirements-dev.txt`.
- CI runs `pip-audit` against the pinned requirements.
- A CycloneDX SBOM is generated per release.
- Container images are built reproducibly, signed with cosign, and attested to
Rekor.
- `neuralstrike smoke` verifies basic functionality on a fresh install without
reaching external services.

### T2 — Leakage of operator credentials through logs or prompts

**Description:** API keys, tokens, or the operator's own secrets are echoed in
logs, embedded in prompts, or exfiltrated via tool-call arguments.

**Impact:** Credential compromise; unauthorized access to target or operator
accounts.

**Controls**

- `NEURALSTRIKE_REDACT_LOGS=true` scrubs credential-shaped strings from logs
(default).
- `python-dotenv` loads secrets from `.env`, which is in `.gitignore` and never
packaged.
- The Adversarial Loop isolates Attacker/Judge prompts from operator secrets;
the victim prompt only contains the target URL/model and the canary.
- Report writers sanitize canaries as test artifacts, not operator secrets.

### T3 — Compromised Attacker or Judge model

**Description:** A local or remote LLM used by NeuralStrike is tampered with to
produce misleading verdicts, over-claim breaches, or refuse service.

**Impact:** False positives/negatives in reports; wasted operator time;
potentially fabricated evidence.

**Controls**

- Verdicts are deterministic-oracle first; the Judge is advisory.
- `LLMError` fail-closed on backend failure.
- Baseline comparison gates regression vs. pre-existing findings.
- Reports record model names, seeds, and per-trial metadata for audit.

### T4 — MCP Interceptor misused as an open proxy

**Description:** The MCP proxy is bound to a non-loopback interface or left
running, allowing unauthorized clients to relay tool traffic.

**Impact:** Lateral movement through the target's MCP tools; data exfiltration.

**Controls**

- Default bind host is `127.0.0.1`.
- Non-loopback binding requires explicit `--bind-host` and prints a warning.
- The proxy only forwards JSON-RPC tool calls; it does not expose arbitrary
HTTP.
- Container image runs as non-root user `neuralstrike` (uid 1000).

### T5 — AgentC2 registry tampering or disclosure

**Description:** The JSON registry file is world-readable, modified by another
process, or used to store real secrets.

**Impact:** Loss of chain of custody for simulated C2 state; possible secret
leakage if the operator misuses the registry.

**Controls**

- Registry is purely a local simulation; it is not a network daemon.
- File lives under `~/.neuralstrike/` with operator-owned permissions.
- Docs explicitly warn not to store real credentials in the registry.

### T6 — Report artifacts leak target data

**Description:** A SARIF/JSON/Markdown/PDF report contains sensitive target
output, canaries, or tool-call results and is shared outside scope.

**Impact:** Data breach of the target system; compliance violation.

**Controls**

- Reports are operator-controlled artifacts.
- Canaries are minted per trial and are not operator secrets.
- Operators are instructed in `SECURITY.md` to treat reports like raw evidence
and share them only within the engagement boundary.

### T7 — A2A identity / delegation spoofing

**Description:** An A2A Agent Card or delegation chain presented to NeuralStrike
is forged, causing the `a2a-scan` command to misclassify a malicious agent as
trusted.

**Impact:** False-negative on A2A identity verification; trust extended to a
spoofed agent.

**Controls**

- `a2a-scan` verifies Agent Card signatures and reports tamper detection.
- Reports align with A2A Identity Working Group error conventions:
  - `INVALID_CLAIM_SCOPE` — a claim expands or narrows authority beyond what the
    upstream principal delegated.
  - `INVALID_COMPOSITION` — a multi-layer identity/delegation envelope is
    structurally malformed or combines incompatible claim types.
- A tampered card is surfaced as a finding, never silently accepted.

### T8 — Accidental destructive action against a target

**Description:** An operator runs an irreversible probe (`exhaust`, `hijack` with
real tool execution, etc.) against a system outside scope.

**Impact:** Availability loss, data damage, legal liability.

**Controls**

- `scope.assert_allows()` validates target/intent against a rules-of-engagement
file.
- `classify_intent()` tags actions as reversible, compensable, or irreversible.
- `HITLGate` requires `--require-approval` for irreversible actions.
- `--force` is required for high-token DoS probes.

## Risk summary

| ID | Threat | Severity | Mitigation confidence |
|----|--------|----------|----------------------:|
| T1 | Supply-chain compromise | Critical | High (hashes + SBOM + signed image) |
| T2 | Credential leakage | Critical | High (redaction + env isolation) |
| T3 | Compromised model | High | Medium (deterministic oracles, audit trail) |
| T4 | Open MCP proxy | High | High (loopback default + explicit opt-in) |
| T5 | Registry tampering | Medium | Medium (local-only, filesystem perms) |
| T6 | Report data leakage | High | Medium (operator process control) |
| T7 | A2A identity spoofing | High | High (signature verification + error codes) |
| T8 | Accidental destructive action | Critical | High (scope + safety + HITL) |

## Out of scope

- Threats inside the target LLM/agent are the purpose of the tool, not threats to
it.
- Physical security of the operator host is assumed by the operator.
- Network segmentation between operator and target is the operator's
responsibility.
