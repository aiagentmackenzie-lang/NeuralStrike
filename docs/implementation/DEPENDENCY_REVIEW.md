# Dependency refresh — 2026-11-06

Runtime and development locks were regenerated from pyproject.toml with hashes
using their existing uv commands, adding `--upgrade`. Validation used a new
Python 3.12.14 environment, not the operator's existing Python 3.14 environment.

The original runtime audit reported 26 entries across aiohttp, multidict,
certifi, filelock and litellm. These are scanner entries, not demonstrated
exploitable paths; certifi includes a duplicate advisory ID.

| Package | Source reachability assessment | Decision |
|---|---|---|
| aiohttp | No direct src import; transitive client stack. Server advisory prerequisites not demonstrated. | Updated to 3.14.5 |
| multidict | No direct src import; transitive HTTP stack. Reachability of vulnerable C-extension operations not demonstrated. | Updated to 7.2.1 |
| certifi | TLS trust bundle can affect outbound clients. No interception demonstrated. | Updated to 2026.10.23 |
| filelock | No direct src import; transitive model/cache operations. Platform/path prerequisites not individually exercised. | Require >=4.2.1; resolved 4.2.9 |
| litellm | `core/llm_manager.py` imports acompletion. Reported proxy-admin escalation requires proxy deployment; repository does not launch that proxy. | Updated to 1.103.10 |

An unconstrained first refresh resolved filelock 3.32.7 and retained 13 audit
entries. This candidate was rejected. A declared filelock security floor now
prevents that result in locks and ordinary wheel resolution.

Final `pip-audit --desc --require-hashes -r requirements.txt --format json`
returned exit 0: **no known vulnerabilities found**. Scanner cache warnings
were emitted. No advisory ignores were introduced. This is an audit-database
result, not a guarantee against undisclosed vulnerabilities or proof that the
old versions were exploitable in this application.

Verification: refreshed Python suite, Ruff and mypy; wheel/sdist build; runtime
lock install and wheel smoke outside the checkout. See PROGRESS.md for results.
The rejected unconstrained candidate included an OpenAI major upgrade. The final
security-constrained resolution retains OpenAI 2.54.0; fixture
checks cover local interfaces, not live provider compatibility. Independent
protocol/provider validation and container validation remain outstanding.

Follow-up report verification added `pypdf>=6` to development dependencies only,
resolved to 7.0.0 with hashes. Independent parsing exposed an actual blank-PDF
bug missed by prefix/xref string checks. Runtime dependencies are unchanged.
A complete refreshed dev-lock audit returned exit 0, no known vulnerabilities;
no advisory ignores were added. See the progress ledger for final test gates.

## MCP profile addition — 2026-11-07

Added the maintained official Python MCP SDK to the optional `mcp` extra, pinned
at **2.3.0** for the explicit 2026-07-28 profile. Reviewed the official migration/
protocol documentation and actual installed APIs before implementation. The
profile rejects automatic legacy negotiation; this does not claim complete SDK,
OAuth or extension conformance.

Regenerated both hashed locks with their existing compile commands, without
`--upgrade`. A programmatic before/after comparison confirmed **zero existing
version changes and zero removals**. Only these five distributions were added:

| Distribution | Version | Reachability in this increment |
|---|---|---|
| mcp | 2.3.0 | Optional modern typed client/protocol engine; explicit local example server |
| mcp-types | 2.3.0 | Revision-specific schemas and message validation; required exactly by SDK |
| PyJWT | 2.15.1 | SDK OAuth/auth dependency; NeuralStrike's static bearer-reference path does not enable an OAuth flow |
| python-multipart | 0.0.33 | SDK server-side dependency; no new public listener is launched by importing NeuralStrike |
| sse-starlette | 3.7.0 | SDK HTTP server dependency; finite JSON/SSE interoperability tested locally |

Actual HTTP transport remains httpx2 2.16.0 from the existing lock; no transport or
OpenAI major upgrade was introduced. Existing fastapi/uvicorn extras remain.
The server examples bind loopback and require explicit startup; telemetry/fleet
integrations remain optional and were not activated.

Both `pip-audit --desc --require-hashes ... --format json` gates returned exit 0:
runtime **80 audited distributions / 0 vulnerability entries**, development
**140 / 0**. No ignores were added. This is a current advisory-database result,
not proof of code security or absence of undisclosed vulnerabilities.

A CycloneDX environment SBOM was generated into a scratch directory (that file is **gone**;
regenerate one with `cyclonedx-py environment`); all five additions were verified using
normalized distribution names (the SBOM spells PyJWT with capitals). Reinstalled
the new dev lock with hashes into the isolated wheel environment, then installed
the rebuilt wheel with `--no-deps --reinstall`. Installed-wheel local stdio/HTTP,
credential failure, timeout/budget, immutable rerun, offline/corrupt receipt and
fresh smoke checks passed. See PROGRESS.md and MCP_PROFILES.md for scope/results.
