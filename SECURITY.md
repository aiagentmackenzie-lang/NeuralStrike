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
- Logs are redacted of credential-shaped strings when
  `NEURALSTRIKE_REDACT_LOGS=true` (default).

These defaults do **not** make the tool safe to run against systems you do not
own. You are responsible for your use.

## 2. Reporting vulnerabilities in NeuralStrike

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