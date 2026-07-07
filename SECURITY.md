# Security Policy

NeuralStrike is an **offensive-security** tool for **authorized** red-team
testing of AI/LLM systems. This policy covers two distinct concerns:

1. **Responsible use of NeuralStrike** (operator obligations).
2. **Reporting vulnerabilities in NeuralStrike itself**.

## 1. Responsible use

Unauthorized access to computer systems is illegal in most jurisdictions.
Before running NeuralStrike against any target you must:

- Own the target system, **or** hold **written authorization** from its owner.
- Operate within the scope and rules of engagement you agreed to.
- Avoid collateral impact on systems outside scope.

NeuralStrike ships with operator-facing safety defaults to reduce accidental
harm:

- The MCP interceptor binds to `127.0.0.1` by default. Binding to a
  non-loopback interface (`--bind-host`) exposes an open proxy — only do this
  on a network you control.
- CLI inputs are validated: target URLs must be `http://`/`https://`, ports
  must be in 1–65535, iteration counts are bounded.
- DoS-class operations (`exhaust`) require `--force` above 10,000 tokens.
- Scope checking (`--scope-file`) blocks out-of-scope targets before a probe
  runs.
- Irreversible intents require `--require-approval` after `safety-check`.
- Logs are redacted of credential-shaped strings when
  `NEURALSTRIKE_REDACT_LOGS=true` (default).

These defaults do **not** make the tool safe to run against systems you do not
own. You are responsible for your use.

## 2. Threat model

A full threat model of NeuralStrike itself is in
[`docs/threat_model.md`](docs/threat_model.md). The headline risks are:

- **Supply-chain compromise** of the package, image, or dependencies — mitigated
  by hashed requirements, `pip-audit`, CycloneDX SBOM, and cosign-signed GHCR
  images with Rekor attestation.
- **Credential leakage** from logs, prompts, or report artifacts — mitigated by
  log redaction, `.env`/`.gitignore` hygiene, and deterministic canaries that
  are not operator secrets.
- **Compromised Attacker/Judge models** producing misleading verdicts —
  mitigated by deterministic oracles, fail-closed LLM errors, and recorded
  per-trial metadata.
- **MCP Interceptor exposed as an open proxy** — mitigated by loopback default,
  explicit non-loopback opt-in with a warning, and non-root container user.
- **A2A identity / delegation spoofing** — mitigated by Agent Card signature
  verification in `a2a-scan` and alignment with the A2A Identity Working Group
  error conventions (see below).

## 3. A2A Identity Working Group error conventions

NeuralStrike reports that touch agent identity and delegation use the same
structural-before-semantic error vocabulary as the A2A Identity Working Group
(CTEF / agent-identity extension discussions). This keeps red-team findings
aligned with the language defensive stacks use to reject bad identity claims.

Two codes are surfaced today:

- **`INVALID_CLAIM_SCOPE`** — a presented identity or delegation claim expands or
  narrows the authorized scope beyond what the upstream principal delegated.
  In NeuralStrike this maps to an A2A `a2a-scan` finding where a tampered or
  overreaching Agent Card / delegation chain grants more authority than its
  signed ancestor.
- **`INVALID_COMPOSITION`** — a multi-layer identity or delegation envelope is
  structurally malformed (e.g., incompatible claim types layered together, a
  chain that violates monotonic scope narrowing, or a missing binding). In
  NeuralStrike this maps to an A2A scan finding where the composed identity
  evidence does not form a valid chain even if individual signatures verify.

These codes are descriptive, not normative — they translate NeuralStrike's
observations into the WG's vocabulary so defenders can act on them without a
secondary mapping.

## 4. Reporting vulnerabilities in NeuralStrike

If you find a security issue in NeuralStrike itself (e.g., a way the tool
leaks operator credentials, bypasses its own redaction, or misroutes traffic
unsafely), please report it responsibly:

- **Do not** open a public GitHub issue for security reports.
- Email: **aiagent.mackenzie@gmail.com** with `[NeuralStrike security]` in the
  subject.
- Include a clear description, reproduction steps, and your assessment of
  impact.
- Please allow a reasonable window (default 90 days) before public disclosure.

## Scope

In-scope: vulnerabilities in NeuralStrike's code, its CLI handling, its
proxy, its persistence, and its dependency configuration.

Out of scope: the behavior of target LLMs/agents that NeuralStrike is pointed
at (that is the tool's purpose), and issues fixed by upgrading supported
dependency versions.

## Supported versions

Only the latest minor release receives security fixes.
