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
