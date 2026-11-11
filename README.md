# NeuralStrike

**Adversarial AI orchestration framework — a red-team toolkit for the autonomous-agent era.**

NeuralStrike red-teams AI systems the way offensive security tooling red-teams
networks: an automated **Attacker–Victim–Judge** loop discovers and exploits
prompt-injection, tool-use, and protocol-level weaknesses, scores every probe
with deterministic oracles, and maps each finding to **OWASP**, **MITRE ATLAS**,
and compliance controls so defenders can fix what actually breaks.

[![CI](https://img.shields.io/github/actions/workflow/status/aiagentmackenzie-lang/NeuralStrike/ci.yml?branch=main&label=CI)](https://github.com/aiagentmackenzie-lang/NeuralStrike/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11%20%E2%80%93%203.14-3776AB?logo=python&logoColor=white)](pyproject.toml)
[![TypeScript](https://img.shields.io/badge/TypeScript-dashboard-3178C6?logo=typescript&logoColor=white)](dashboard/)
[![Code style: ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Type checked: mypy](https://img.shields.io/badge/type%20checked-mypy-1E4C74)](https://mypy-lang.org)
[![Tested with pytest](https://img.shields.io/badge/tested%20with-pytest-0A9EDC)](https://docs.pytest.org)

[![Ollama](https://img.shields.io/badge/LLM%20runtime-Ollama-1A1A1A?logo=ollama&logoColor=white)](https://ollama.com)
[![LiteLLM](https://img.shields.io/badge/remote%20targets-LiteLLM-2F2F2F)](https://github.com/BerriAI/litellm)
[![FastAPI](https://img.shields.io/badge/MCP%20proxy-FastAPI-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Typer](https://img.shields.io/badge/CLI-Typer-00897B)](https://typer.tiangolo.com)
[![Rich](https://img.shields.io/badge/terminal-Rich-FB8C00)](https://rich.readthedocs.io)
[![pydantic](https://img.shields.io/badge/settings-pydantic-E92063)](https://docs.pydantic.dev)
[![React](https://img.shields.io/badge/dashboard-React%2018-61DAFB?logo=react&logoColor=black)](dashboard/)
[![SARIF](https://img.shields.io/badge/reports-SARIF%202.1.0-5C2D91)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
[![MCP](https://img.shields.io/badge/protocol-MCP-7C4DFF)](https://modelcontextprotocol.io)
[![MITRE ATLAS](https://img.shields.io/badge/mapping-MITRE%20ATLAS-B71C1C)](https://atlas.mitre.org)
[![OWASP](https://img.shields.io/badge/mapping-OWASP%20LLM%20%2B%20ASI-0277BD)](https://genai.owasp.org)

> [!WARNING]
> **NeuralStrike is an offensive-security tool.** It is designed for
> **authorized** security testing only: systems you own, or systems you have
> explicit written permission to test. Unauthorized access to computer systems
> is illegal. See [Ethical use](#ethical-use) and
> [SECURITY.md](SECURITY.md).

| Documentation | |
|---|---|
| **[Operator's Guide (USAGE.md)](USAGE.md)** | End-to-end walkthroughs, every command, kill chains, troubleshooting |
| **[Support matrix](docs/SUPPORT_MATRIX.md)** | What is supported, experimental or excluded, with measured limits |
| **[Live target guide](docs/LIVE_TARGET_GUIDE.md)** | Authenticated OpenAI-compatible target: credential by reference, scope, budgets |
| **[Offline example](docs/OFFLINE_EXAMPLE.md)** | Bundled fixture run with no model and no network |
| **[Phase 4 plan](docs/implementation/PHASE4_PLAN.md)** | Release/pilot gate definition and current state — **NOT RELEASED** |
| **[Threat model](docs/threat_model.md)** | What the tool assumes, what it does not |
| **[Security policy](SECURITY.md)** | Responsible disclosure |
| **[Changelog](CHANGELOG.md)** | Releases and notable changes |

---

## Evidence status

Phase 2 engineering acceptance covers only the controlled profiles in
[the acceptance record](docs/implementation/PHASE2_ACCEPTANCE.md).
Independent application efficacy, third-party review and customer pilots remain
uncompleted. Benchmark importers, oracle-honesty tests, local application cycles
and code coverage do not establish those results. The first Phase 3 offline
label/prediction comparison is documented in
[PHASE3_EFFICACY.md](docs/implementation/PHASE3_EFFICACY.md), and the binary gates
by which Phase 3 will be judged — with their current status, which is **not
accepted** — are in [PHASE3_ACCEPTANCE.md](docs/implementation/PHASE3_ACCEPTANCE.md).
The release phase's own gates — artifact binding, signing policy, scheduled dependency
health, pilot-facing documentation, platform claims and the pilot itself — are defined, with
their current state, in [PHASE4_PLAN.md](docs/implementation/PHASE4_PLAN.md); that phase is
**NOT RELEASED** and nothing in this repository is signed.

## Overview

Modern AI systems fail in ways traditional pentesting tools don't cover:
an agent can be talked into calling the wrong tool, a poisoned document can
hijack a retrieval pipeline, a malicious skill file can turn a helpful
assistant into an exfiltration engine. NeuralStrike ships a runnable, scored
probe library for exactly these failure modes.

It targets:

- **Autonomous agents** — multi-agent frameworks (CrewAI, AutoGen, LangChain/LangGraph)
- **Protocol layers** — MCP (Model Context Protocol) and A2A implementations
- **Execution engines** — function-calling / tool-use architectures
- **LLM APIs** — OpenAI, Anthropic, and local Ollama deployments

NeuralStrike pairs with [**NeuralGuard-AI-Firewall**](https://github.com/aiagentmackenzie-lang/NeuralGuard-AI-Firewall),
the defensive half of the same story: NeuralStrike generates the attacks,
NeuralGuard validates the controls, and the two repos talk directly via the
`neuralguard-bench` command. See
[Ecosystem](#ecosystem-attack-and-defend-in-one-loop).

### What makes it different

1. **Deterministic oracles, not vibes.** Every bundled corpus probe is scored by a
   deterministic oracle (canary extraction, forbidden-tool detection,
   predicate matching, schema validation). Imported benchmark-pack probes are the one exception: they ship no oracle, so they defer to the judge or stay `Inconclusive`. Verdicts are **three-outcome and
   conclusive-only**: `Resisted` | `Succeeded` | `Inconclusive`. Weak evidence
   is honestly `Inconclusive` — never a fabricated pass.
2. **The Judge is advisory — and audited.** A separate, stronger LLM judge
   annotates findings and decides only where no deterministic oracle was
   conclusive. It can never flip an oracle verdict, and the built-in
   `judge-audit` command measures the judge's own bias and manipulability.
3. **Behavior, not just words.** Adapter-driven scans drive real targets and
   classify evidence fidelity: *Verbal* (it said it), *IntentToAct* (it emitted
   a forbidden tool call), *Behavioral* (an instrumented canary tool actually
   executed).
4. **Statistics you can defend.** k-trial runs with Wilson confidence
   intervals, recorded seed/temperature controls, offline evidence replay, flaky detection, and a
   baseline gate that fails CI on regressions.

---

## How it works

NeuralStrike runs a tripartite adversarial loop hosted on
[Ollama](https://ollama.com) (local) and [LiteLLM](https://github.com/BerriAI/litellm) (remote):

1. **Attacker** (local model, e.g. `deepseek-r1`) — generates and iteratively
   refines adversarial payloads, seeded from a template library and mutated
   from judge feedback.
2. **Victim** — the system under test: a local Ollama model, a remote LLM API,
   or a real agent/protocol target driven through an adapter.
3. **Judge** (a deliberately stronger, *distinct* model, e.g.
   `deepseek-v3.1:671b-cloud`) — returns a typed, schema-validated verdict.
   An attack run never scores itself.

```
┌─────────────────────────────────────────────────────────────────┐
│                         NEURALSTRIKE                            │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐               │
│  │    RECON    │  │  WEAPONIZE  │  │   EXPLOIT   │               │
│  │ LLMRecon    │  │ Jailbreak-  │  │ FunctionHij │               │
│  │ ToolEnum    │  │   Forge     │  │ AgentPivot  │               │
│  │             │  │ ContextPoison│ │ MCPIntercept│               │
│  │             │  │             │  │ ModelExtract│               │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘               │
│         └────────────────┼────────────────┘                      │
│                          ▼                                       │
│               ┌─────────────────────┐                            │
│               │  POST-EXPLOITATION  │                            │
│               │ AgentC2 (persistent)│                            │
│               │ DataExfiltrator     │                            │
│               └─────────────────────┘                            │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                    EVASION LAYER                           │ │
│  │  Persona Wrap · Mimicry · Delimiter Wrap · Steganography   │ │
│  └────────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  CORE: LLMManager (async) · AdversarialLoop · Config       │ │
│  │  ORACLES: canary · forbidden_tool · predicate · schema     │ │
│  │  UTILS: URL validation · log redaction                     │ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

The stages mirror the MITRE ATLAS / OWASP kill chains. The output exists to
**validate detective and preventive controls** — every finding maps to an
OWASP Agentic (ASI01–10) or LLM (LLM01–10) category, a MITRE ATLAS technique,
and a control across NIST AI RMF / EU AI Act / ISO 42001 / SOC 2 / CSA MAESTRO.

The loop is **fail-closed**: backend errors abort the run loudly instead of
being fed back in as fake "responses". All LLM calls are genuinely async
(`ollama.AsyncClient`, `litellm.acompletion`).

---

## Breadth, measured

Everything in this section is counted from the tree by a command you can re-run, not estimated.
`tests/test_readme_claims.py` re-derives each number and fails if this table drifts.

| Dimension | Measured | Counted from | Evidence |
|---|---:|---|---|
| CLI surface | **42** command names, **41** distinct callbacks — `corpus` is the same callback as `assess` | the Typer command graph (`registered_names`) | ✅ CI-verified |
| Source | **121** implementation modules in **26** packages, **≈26.7k** lines under `src/` | `src/neuralstrike/**/*.py`, `__init__.py` excluded from the module count | ✅ CI-verified |
| Tests, local | **2,707** collected (**1,026** test functions; the rest parametrised) · **2,700** pass · **7** skip · **91.98 %** coverage | `scripts/ci_gate.sh` on macOS arm64 / CPython 3.12.14 | ⚠️ local observation |
| Tests, CI | the same suite, with **7 additional skips** and **91.88–91.92 %** coverage | CI run `43122299019` at `1664f73`: **2,693 pass, 14 skip, 91.88–91.90 %**, all seven jobs. The seven extra skips need the private evidence root or the pinned tau-bench checkout — neither is in the repository. An earlier run, `43115588777`, is kept as the red one: it failed on a test that demanded this machine's evidence root exist on a runner | ✅ CI-verified |
| Target adapters | **5** — `openai_endpoint`, `langgraph`, `langgraph_server`, `mcp_http`, `a2a` | `adapters/`, `--adapter` choices | ✅ CI-verified |
| Deterministic oracles | **5** families — canary, forbidden-tool, predicate, schema, system-prompt extraction | `oracles/`, plus the advisory judge and its ensemble | ✅ CI-verified |
| Scenario corpus | **60** scenarios · **20** OWASP categories (ASI01–10, LLM01–10) · **5** delivery vectors · **4** YAML files | `load_corpus_dir()` over the shipped package data | ✅ CI-verified |
| Adaptive strategies | **5** — PAIR, TAP, Crescendo, `trace`, `trace-pair`, plus an `auto` dispatcher | `--strategy` choices | ✅ CI-verified |
| Evasion codecs | **18** registered transforms with a winnability guard | `list_transforms()` | ✅ CI-verified |
| Defenses | **8** payload-transform defenses + **2** checkers (lethal trifecta, Rule of Two) | `defenses/defenses.py`, `defenses/checkers.py` | ✅ CI-verified |
| Benchmark packs | **4** — HarmBench, JailbreakBench, CyberSecEval, local | `list_packs()`; none vendored | ✅ CI-verified |
| Report formats | **5** — JSON, SARIF 2.1.0, JUnit, Markdown, PDF (pure standard library) | `reports/render.py` | ✅ CI-verified |
| Compliance crosswalk | **8** frameworks — OWASP ASI, OWASP LLM, MITRE ATLAS, NIST AI RMF, EU AI Act, ISO/IEC 42001, SOC 2, CSA MAESTRO | `reports/compliance.py` `FrameworkID` | ✅ CI-verified |
| Container | `linux/amd64` full offline smoke; `linux/arm64` built and started only | CI `container` job | ✅ CI-verified |

**What the numbers do not mean.** They are a count of surface, not of effectiveness — and a row
marked local is one machine speaking. A tool with 60 scenarios and a tool with 6,000 are equally
silent about whether the scenarios are the right ones; `docs/implementation/PHASE3_ACCEPTANCE.md`
is where that question is asked, and its answer today is **not accepted**.

### Evidence marks used in this README

| Mark | Means |
|---|---|
| ✅ | **CI-verified** — asserted by the automated suite on every push, on the runners |
| ⚠️ | **Local observation** — measured on one machine, one model, one seed; a reviewer cannot reproduce it without that machine |
| ❌ | **Not implemented** — named in a document but absent from the code |

---

## Attack coverage

The mapping below is **generated from the shipped scenario corpus, not
hand-written** — every row is a runnable, deterministic-oracle-scored probe.

<!-- BEGIN neuralstrike-mapping -->
> **Auto-generated from `corpus/*.yaml` by `neuralstrike readme-mapping`.**
> Do not hand-edit the table below the markers — regenerate it. The mapping is real because the corpus is real: every scenario row is a runnable, deterministic-oracle-scored probe.

The corpus ships **60 scenarios** across 20 OWASP categories (10 ASI + 10 LLM), exercising 5 delivery vectors: `memory`, `retrieved_document`, `system_prompt`, `tool_result`, `user_message`.

### OWASP Top 10 for Agentic Applications (2026)

| ID | Category | Scenarios | MITRE ATLAS | Delivery vectors |
|----|----------|----------:|-------------|------------------|
| **ASI01** | Agent Goal Hijack | 3 | `AML.T0051.001` | `retrieved_document`, `tool_result`, `user_message` |
| **ASI02** | Tool Misuse and Exploitation | 6 | `AML.T0051`, `AML.T0051.001`, `AML.T0080.001`, `AML.T0110` | `memory`, `retrieved_document`, `system_prompt`, `tool_result` |
| **ASI03** | Identity and Privilege Abuse | 5 | `AML.T0051.001`, `AML.T0054` | `retrieved_document`, `tool_result`, `user_message` |
| **ASI04** | Agentic Supply Chain Vulnerabilities | 7 | `AML.T0010.001`, `AML.T0057`, `AML.T0110` | `memory`, `retrieved_document`, `tool_result` |
| **ASI05** | Unexpected Code Execution | 3 | `AML.T0051.001` | `retrieved_document`, `tool_result`, `user_message` |
| **ASI06** | Memory and Context Poisoning | 9 | `AML.T0051.002`, `AML.T0057`, `AML.T0080.001`, `AML.T0110` | `memory`, `retrieved_document`, `system_prompt`, `tool_result` |
| **ASI07** | Insecure Inter-Agent Communication | 3 | `AML.T0051.001` | `memory`, `retrieved_document`, `tool_result` |
| **ASI08** | Cascading Failures | 4 | `AML.T0034.002`, `AML.T0051.001` | `memory`, `retrieved_document`, `tool_result`, `user_message` |
| **ASI09** | Human-Agent Trust Exploitation | 3 | `AML.T0051.001` | `memory`, `retrieved_document`, `tool_result` |
| **ASI10** | Rogue Agents | 4 | `AML.T0051.001`, `AML.T0061` | `memory`, `system_prompt`, `tool_result` |

### OWASP Top 10 for LLM Applications (2025)

| ID | Category | Scenarios | MITRE ATLAS | Delivery vectors |
|----|----------|----------:|-------------|------------------|
| **LLM01** | Prompt Injection | 2 | `AML.T0051.001`, `AML.T0054` | `retrieved_document`, `user_message` |
| **LLM02** | Sensitive Information Disclosure | 2 | `AML.T0024.000`, `AML.T0024.002` | `retrieved_document`, `tool_result` |
| **LLM03** | Supply Chain | 1 | `AML.T0010.001` | `tool_result` |
| **LLM04** | Data and Model Poisoning | 1 | `AML.T0018` | `retrieved_document` |
| **LLM05** | Improper Output Handling | 1 | `AML.T0051.001` | `retrieved_document` |
| **LLM06** | Excessive Agency | 1 | `AML.T0051.001` | `tool_result` |
| **LLM07** | System Prompt Leakage | 2 | `AML.T0051.000` | `retrieved_document`, `user_message` |
| **LLM08** | Vector and Embedding Weaknesses | 1 | `AML.T0051.001` | `retrieved_document` |
| **LLM09** | Misinformation | 1 | `AML.T0048.002` | `retrieved_document` |
| **LLM10** | Unbounded Consumption | 1 | `AML.T0029` | `user_message` |

_Each scenario's `success_criteria` reference deterministic oracles (canary / forbidden-tool / predicate / schema / system-prompt extraction); the Judge is advisory only and never flips a deterministic verdict._
<!-- END neuralstrike-mapping -->

---

## Installation

### Prerequisites

- **Python 3.11 – 3.14**
- **Ollama** running locally for the Attacker/Judge brains:
  ```bash
  ollama pull deepseek-r1        # attacker
  ollama pull mistral:7b         # a local victim to test against
  ```
- Optional API keys for remote targets (`--target-type remote`):
  `NEURALSTRIKE_OPENAI_API_KEY` / `NEURALSTRIKE_ANTHROPIC_API_KEY` in `.env`.

### From source (recommended)

```bash
git clone https://github.com/aiagentmackenzie-lang/NeuralStrike.git
cd NeuralStrike
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[mcp]"
neuralstrike --version
```

Optional extras:

| Extra | Adds |
|---|---|
| `.[mcp]` | FastAPI/Uvicorn — the MCP interception proxy |
| `.[langgraph]` | Drive real compiled LangGraph agents |
| `.[dev,mcp]` | Everything above + pytest/ruff/mypy for contributors |

Dependencies are single-sourced in `pyproject.toml`. Production installs can
use the hash-pinned `requirements.txt` / `requirements-dev.txt` lockfiles
(`pip install --require-hashes -r requirements-dev.txt`).

For development, do not install the unbounded `.[dev,mcp]` extra by hand:
`scripts/dev_env.sh` builds `.venv` from the hash-pinned lock and runs the same
gate CI runs. See [Development](#development).

### Verify the install

```bash
neuralstrike smoke
```

Runs a tiny corpus offline against a bundled fixture — no LLM required. A
fresh-clone smoke test also runs in CI.

### Docker

```bash
docker compose up -d ollama
docker compose run --rm neuralstrike neuralstrike --help
docker compose run --rm neuralstrike neuralstrike smoke
```

---

## Quickstart

The quickstart stays inside the acceptance claims: a capability preflight, one assessment, one
gate. The legacy offensive commands are in the [next section](#legacy-offensive-catalogue-no-acceptance-claim)
and carry no acceptance claim.

```bash
# 1. Copy and edit the config (points at local Ollama by default)
cp .env.example .env

# 2. Preflight the target before attacking it. This probes what the endpoint can
#    actually do (finite responses, tool round-trip) and exits 0 only when the
#    requested capability was OBSERVED — that is compatibility, not a security pass.
neuralstrike doctor --url http://localhost:11434/v1 --model mistral:7b \
    --out capability-receipt.json

# 3. Run one assessment against the bundled vulnerable agent fixture and commit a
#    hash-bound evidence bundle with an audit-grade SARIF report. No model, no network.
neuralstrike assess --adapter langgraph --format sarif --out neuralstrike-report

# 4. Once you have two committed assessments, diff them offline — no target, no
#    model, both bundles hash-verified (exit 3 = not comparable, 4 = regression):
neuralstrike compare <baseline-bundle> <current-bundle>

# 5. Gate your own target on a baseline (exit 4 = regression):
neuralstrike evaluate --target mistral:7b --target-type local \
    --trials 3 --seed 42 --save-baseline-dir .baselines
```

Every output lands in `runs/<run-id>/` as per-trial transcripts, and every
report maps findings to OWASP + ATLAS + compliance controls.

A completely offline check with no model at all:

```bash
neuralstrike smoke           # bundled fixture; 3 scenarios, no network
```

### Legacy offensive catalogue — no acceptance claim

The commands below are the original attack surface, kept because they are useful and because
deleting them would only hide them. **None of them carries an acceptance claim, none has an
efficacy record, and a result from any of them is a local observation — not evidence.**

Every one of them sends traffic to a model, a server or a network target. Every one of them
accepts `--scope-file`, `--intent` and `--require-approval`, and the scope check is **opt-in**:
nothing is refused unless you supply a scope file. That is a real limitation, stated here and in
[SUPPORT_MATRIX.md](docs/SUPPORT_MATRIX.md) rather than implied away.

| Command | What it does |
|---|---|
| `recon` | Scan LLM endpoints (`/models`, `/api/tags`), map capabilities, probe tool-schema leaks |
| `forge` | Iterative jailbreak loop (Attacker–Victim–Judge) |
| `poison` | Context manipulation, system-prompt extraction, `--extract` |
| `exhaust` | Context-window exhaustion (DoS-class; requires `--force` above 10k tokens) |
| `hijack` | Tool-use parameter injection |
| `confuse` | Tool-confusion attack (redirect to a decoy tool) |
| `schema-poison` | Redefine a tool's purpose via schema poisoning |
| `intercept` | MCP interception proxy — loopback-bound by default |
| `pivot` | Lateral movement across multi-agent trust boundaries |
| `map-network` | Discover agents and trust levels in a multi-agent system |
| `extract` | Fingerprinting prompts against a target (informational) |
| `timing` | Latency analysis (informational; not a model identifier) |
| `c2` | Persistent compromised-agent registry + dispatch (local JSON state, no daemon) |
| `evade` | Persona wrap, mimicry, delimiter wrap, real invisible-Unicode steganography |
| `neuralguard-bench` | Canonical recon→weaponize→exploit→post-ex chain against a NeuralGuard-defended victim |

[SUPPORT_MATRIX.md](docs/SUPPORT_MATRIX.md) gives the per-command effect class (local simulation /
informational / experimental) and the limits that stay true.

---

## CLI reference

`neuralstrike --help` lists everything; the highlights:

### Legacy offensive commands

`recon`, `forge`, `poison`, `exhaust`, `hijack`, `confuse`, `schema-poison`, `intercept`,
`pivot`, `map-network`, `extract`, `timing`, `c2`, `evade` and `neuralguard-bench` are the
legacy attack surface. They are listed once, above, under
[Legacy offensive catalogue — no acceptance claim](#legacy-offensive-catalogue-no-acceptance-claim),
because a second table here would be a second description of the same fifteen commands.

### Scenario-driven testing

| Command | What it does |
|---|---|
| `scan` | Drive a real target through an adapter and observe behavior. Adapters: `openai`, `langgraph`, `langgraph-server`, `mcp`, `a2a` |
| `assess` | **One assessment command.** Freeze the selection, run the OWASP ASI/LLM corpus, commit a hash-bound evidence bundle, emit SARIF / JSON / JUnit / Markdown / PDF, apply the gate. `corpus` is the legacy name for the same command and prints a deprecation notice |
| `compare` | **One compare command.** Diff two committed assessments offline (no target or model calls); exit 0 pass, 1 vuln, 3 not comparable, 4 regression |
| `replay` | **One replay command.** Verify a bundle's hashes and recompute recorded outcomes without calling the target |
| `evaluate` | k-trial canary-extraction probe; save/compare baselines |
| `adaptive` | Adaptive attacks: PAIR, TAP (beam=1), Crescendo, trajectory-conditioned `trace`/`trace-pair`, seed diversity |
| `exec-context` | Execution-context & skill attack pack: poisoned skills, rules-file backdoors, triggered injection, armed tool calls, worm-like propagation, resource exhaustion |
| `pack` | Benchmark packs: HarmBench / JailbreakBench / CyberSecEval (on-demand, license-gated) or your own local probes |
| `attack-memory` | Read-only view of the opt-in SQLite attack memory |

### Protocol & memory attacks

| Command | What it does |
|---|---|
| `mcp-scan` | MCP tool-poisoning detection: injected instructions, shadow tools, manifest hash pinning, sleeper rug-pull detection |
| `a2a-scan` | A2A Agent Card JWS/JCS signature verification + tamper detection |
| `minja` | MINJA memory-injection sequence against memory-augmented targets |
| `rag-poison` | PoisonedRAG-style retrieval-corpus poisoning with measurable ASR |

### Judge integrity

| Command | What it does |
|---|---|
| `judge-model-list` | List installed Ollama models — never guess the Judge |
| `judge-audit` | Audit your own judge: controlled-prompt bias battery, 6-technique manipulation family, ensemble disagreement — deterministically, with the judge as the *subject* |

### Attack/defend integration

| Command | What it does |
|---|---|
| `purple-report` | Join a local exercise receipt with what SecurityScarletAI actually detected |

`neuralguard-bench` — the canonical recon→weaponize→exploit→post-ex chain against a
NeuralGuard-defended victim — is a legacy command with no acceptance claim; it is described once,
in the [legacy catalogue](#legacy-offensive-catalogue-no-acceptance-claim).

### Safety & utilities

| Command | What it does |
|---|---|
| `scope-check` | Validate a target/intent against rules of engagement |
| `safety-check` | Classify an intent and enforce the human-in-the-loop gate |
| `smoke` | Offline fresh-clone smoke test against the bundled fixture |
| `readme-mapping` | Regenerate the OWASP/ATLAS table above from `corpus/*.yaml` |

**What the gate is, exactly.** Every command that sends traffic to a model, a server or a network
target accepts `--scope-file`, `--intent` and `--require-approval`, and calls the same two
functions (`_apply_scope`, `_apply_safety`). That is uniform by construction: the table lives in
`src/neuralstrike/safety/surface.py`, it is verified at import time, and an unclassified command
refuses to dispatch.

It is **not** a global gate, and this README does not claim one:

- `--scope-file` is **opt-in**. Omit it and no scope check runs — on `assess` and `scan` just as
  much as on `forge`.
- `--require-approval` gates an **irreversible intent you declare**. Omit `--intent` and nothing
  is classified as irreversible.
- Neither check sandboxes anything. They are operator controls, not containment.

Before this table existed, 11 of the 42 registered command names enforced both gates, 3 enforced
the scope gate only, 1 enforced the HITL gate only, and 27 enforced neither — 15 of which send
traffic. Which ones was not written down anywhere. It is now.

---

## Measurement and reporting

This is the part that makes results defensible:

- **Three-outcome verdicts.** `Resisted` / `Succeeded` / `Inconclusive`.
  Inconclusive is surfaced (SARIF `note`, JUnit `skipped`) — a coverage gap,
  never a fabricated pass. Attack success rate: `Succeeded / (Resisted + Succeeded)`; unavailable without conclusive trials.
- **Wilson confidence intervals** on every k-trial run, plus coverage and
  per-category attack-success rates and a severity-weighted 0–100 risk index.
- **Replayability.** Private per-trial transcripts land in unique `runs/<run-id>/`
  directories. `neuralstrike replay <directory> --verify-oracles` checks integrity
  and re-evaluates supported recorded deterministic policies without model calls.
  Corpus runs also create self-contained `assessment-<id>` bundles with frozen
  selection scope; replay can render all five report formats offline.
  `rescore` creates a derived bundle under an explicit new local policy. Live
  providers may ignore controls or vary. `export-summary` emits only an allowlisted,
  non-replayable sharing summary. Full reports remain private raw evidence.
  See [offline replay](docs/implementation/REPLAY.md).
- OpenAI target preflight: `neuralstrike doctor --url URL --model MODEL` checks
  a harmless tool round-trip. `--target-api-key-env NAME` resolves a bearer
  credential; `--max-response-bytes` bounds accepted response data. Both options
  are also available on `corpus`. Readiness is not a security verdict.
  OpenAI corpus runs also enforce shared request, rate, concurrency and token
  stopping controls (`--max-requests`, `--requests-per-minute`,
  `--max-concurrent-requests`, `--max-total-tokens`). Token estimates may overshoot;
  unavailable provider cost is not reported as zero.
  See [Phase 2 scope and limits](docs/implementation/PHASE2_INTEROPERABILITY.md).
- Modern MCP capability checks: `neuralstrike mcp-inspect --url URL` uses the
  explicit 2026-07-28 profile; stdio is available through `--stdio-command`.
  Discovery is read-only. `mcp-receipt DIRECTORY` verifies private evidence
  offline. Completion is not a security verdict. See
  [supported MCP profiles](docs/implementation/MCP_PROFILES.md).
- **Baseline gating.** Save a baseline, then fail CI on regression:
  exit `0` pass · `1` vulnerability · `3` runtime error · `4` regression
  (regression outranks absolute vulnerabilities). Probe-profile (intensity)
  mismatches are refused.
- **Adaptive attacks with separation enforced.** The attacker only generates;
  oracles + the advisory judge score. PAIR / TAP / Crescendo refine across
  turns; trajectory-conditioned strategies refine from the victim's observed
  *behavior*; an opt-in SQLite attack memory ranks strategies by the recorded
  Wilson lower bound — one lucky run cannot rewrite memory's truth.
- **Defenses are testable too.** Eight payload-transform defenses
  (spotlighting, StruQ, CaMeL, delimiter, sandwiching, …) plus lethal-trifecta
  and Rule-of-Two checkers; `measure_defense_delta` scores each scenario with
  and without a defense and reports both arms.
- **Benchmark packs import on demand** behind `--accept-license`; nothing is
  vendored. Pack probes ship no expected-token oracle, so verdicts come from
  `--judge` — or every probe is honestly `Inconclusive`.
- **Report formats:** JSON, SARIF 2.1.0 (inconclusive probes as low-noise
  notes), JUnit, Markdown, and PDF (pure Python, no extra dependency), each
  with a compliance crosswalk.

### A minimal React/Vite dashboard

`dashboard/` reads a JSON report or SARIF file and surfaces per-category ASR,
coverage, severity, and verdict filters:

```bash
cd dashboard && npm install
npm run build     # outputs to dashboard/dist/ — open index.html, or npm run dev
```

---

## Capability map

Every row is marked with the evidence behind it, using the marks defined above. "✅" means the
automated suite exercises the behaviour on every push — it does **not** mean the behaviour has
been validated by anyone outside this repository.

| Capability | What you get | Evidence |
|---|---|---|
| Recon & tool enumeration | Endpoint scanning, capability mapping, real MCP `tools/list` introspection | ✅ |
| Target adapters | openai_endpoint / langgraph / langgraph_server / mcp_http / a2a — drive real SUTs, observe tool calls | ✅ |
| Adversarial loop | Attacker–Victim–Judge, fail-closed, genuinely async (`ollama.AsyncClient`, `litellm.acompletion`) | ✅ |
| Adaptive attacks | PAIR, TAP (beam of one, 3 judge-ranked candidates per turn), Crescendo, trajectory-conditioned `trace` / `trace-pair`, attack memory, seed diversity | ✅ |
| Evasion & steganography | 18-codec pipeline with provenance, persona/mimicry/delimiter wrap, real invisible-Unicode hidden channels, ASCII-smuggling exfil probe | ✅ |
| Defense testing | **8** payload-transform defenses + **2** checkers (lethal trifecta, Rule of Two) + measured ASR delta | ✅ |
| Deterministic oracles | canary / forbidden_tool / predicate / schema / system-prompt extraction | ✅ |
| Advisory judge | Typed verdicts, never flips an oracle, fail-closed on malformed JSON, ensemble option | ✅ |
| Judge self-audit | Bias battery, manipulation family, blind-prompt judging, ensemble disagreement | ✅ |
| OWASP corpus & indirect injection | 60 scenarios, 5 delivery vectors, adapter-trace-verified channel injection | ✅ |
| Reports & compliance | SARIF 2.1.0 / JSON / JUnit / Markdown / PDF + 8-framework crosswalk | ✅ |
| MCP attack surface | Tool poisoning, implicit poisoning, shadow tools, TOFU pinning (`--pin-hash`), rug-pull detection (`--previous-url`) | ✅ |
| MINJA / RAG poisoning | Memory-injection sequences, retrieval-corpus poisoning | ✅ |
| Agent Card identity | A2A Agent Card JWS/JCS verification, tamper detection, RFC 9421 HTTP Message Signatures, `did:web` / `did:key` resolution — reachable from `a2a-scan` | ✅ |
| Delegation-chain analysis | `DelegationAnalyzer` in `attacks/a2a/delegation.py` — a **library**, tested directly; no CLI command drives it, and it does not contact a live endpoint | ⚠️ library only |
| Incident-modelled scenarios | 10 scenarios *modelled on* named 2025–2026 incidents (EchoLeak/CVE-2025-32711, MCP shadow tools, Supabase rug-pull, MCPoison/CVE-2025-54136, Amazon Q AWS-2025-015/-019, Copilot CVE-2025-53773, Cursor stdio poison, cross-session memory persistence). They are synthetic test cases in the declared taxonomy — not replays of the original evidence, and the CVE attributions are not verified by this repository | ⚠️ modelled, not replayed |
| Model fingerprinting | Raw-response probes + latency timing | ⚠️ informational, not a scoring signal |
| MCP bounded **stdio** discovery | `mcp-inspect --stdio-command` speaks the pinned 2026-07-28 profile over a bounded stdio transport (POSIX process groups; it executes trusted local code and is not a sandbox) | ✅ |
| MCP stdio **scanning** | `mcp-scan` requires `--url`: poisoning, shadow-tool and rug-pull detection is HTTP-only today. A stdio server can be inspected and receipted, not scanned for poisoning | ❌ not implemented |

### Honest limitations

- **TAP keeps a beam of one.** Each turn generates three candidates, has the judge rank them and
  continues with the best. There is no tree, no backtracking, no per-depth frontier — so this is
  branch-and-prune in miniature, not search.
- **Pack verdicts require `--judge`.** Pack probes ship no deterministic oracle, so without a
  judge every probe is `Inconclusive` — by contract, not by accident. That also means a pack run
  is the one place a verdict comes from a model rather than from state.
- **The incident scenarios are models, not post-mortems.** They encode the reported *class* of each
  incident as a deterministic test case. No original evidence, transcript or vendor advisory is
  reproduced here, and the CVE identifiers are cited as published names, not verified.
- **Calibration ships no built-in cohort.** Cohort-relative z-scores are informational only; bring
  your own reference cohort.
- **AgentC2 is a local JSON registry and dispatcher** for compromised-agent simulations. It opens
  no network listeners and runs no daemon.
- **`extract` / `timing` are informational.** Fingerprinting returns raw responses; latency is not
  a model-identification signal.
- **A2A identity is verification-only.** NeuralStrike consumes identity standards to test
  identity-defended targets; it does not issue credentials, and the identity code has not been
  exercised against an independent implementation.
- **Prompt-level defenses are prompt-level surfaces.** StruQ/CaMeL enforce policy in the runtime in
  production; NeuralStrike tests the surface a red-team can actually reach.
- **The acceptance claims are narrow.** They cover the four profiles in
  [the support matrix](docs/SUPPORT_MATRIX.md) and nothing else. The 15 legacy offensive commands
  carry no acceptance claim, and neither does any incident-modelled scenario.

### What NeuralStrike is not

Said plainly, because a capability table invites the opposite reading:

- **Not a certified or compliance-validated product.** The crosswalk maps findings to framework
  identifiers so a human can file them. No framework has assessed this tool, and nothing here
  constitutes a certification, an attestation or an audit opinion.
- **Not independently accepted.** Every claim in this README is the author's. Phase 3 is
  **NOT ACCEPTED** and unsigned ([definition](docs/implementation/PHASE3_ACCEPTANCE.md)); Phase 4
  is **NOT RELEASED** ([plan](docs/implementation/PHASE4_PLAN.md)).
- **Not a service, not multi-tenant, not distributed.** One CLI on one machine, local state, no
  hosted control plane.
- **Not a sandbox.** The scope file and the HITL gate are operator controls; they contain nothing.
- **Not a guarantee that a green run means safe.** A `Resisted` verdict is evidence about a
  declared probe on a declared configuration, and `Inconclusive` is a coverage gap — which is why
  the tool refuses to turn one into a pass.

---

## Configuration

Copy `.env.example` to `.env`. Every key is also settable via environment
variables with the `NEURALSTRIKE_` prefix (pydantic-settings).

```env
NEURALSTRIKE_OLLAMA_BASE_URL=http://localhost:11434
NEURALSTRIKE_ATTACKER_MODEL=deepseek-r1
NEURALSTRIKE_JUDGE_MODEL=deepseek-v3.1:671b-cloud
NEURALSTRIKE_JUDGE_MODEL_FALLBACKS=["kimi-k2.6:cloud","gpt-oss:120b-cloud","deepseek-r1:8b"]
NEURALSTRIKE_VICTIM_TEMPERATURE=0.0
NEURALSTRIKE_ATTACKER_TEMPERATURE=0.7
NEURALSTRIKE_SKIP_REACHABILITY_CHECK=false
NEURALSTRIKE_OPENAI_API_KEY=
NEURALSTRIKE_ANTHROPIC_API_KEY=
NEURALSTRIKE_REDACT_LOGS=true
```

| Key | Purpose |
|---|---|
| `OLLAMA_BASE_URL` | Local Ollama endpoint |
| `ATTACKER_MODEL` | Model that generates payloads |
| `JUDGE_MODEL` | The judge — deliberately a **stronger, distinct** model so an attack run never scores itself and the judge is harder to confuse |
| `JUDGE_MODEL_FALLBACKS` | Ordered fallback chain tried before refusing to run |
| `VICTIM_TEMPERATURE` | Requested at `0.0`; providers may vary or ignore controls. Offline evidence replay is separate |
| `ATTACKER_TEMPERATURE` | Attacker creativity (per-trial seed keeps runs deterministic) |
| `SKIP_REACHABILITY_CHECK` | Tests/offline only — a startup check normally fails closed if the Attacker or Judge is unreachable |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` | Optional, for `--target-type remote` |
| `REDACT_LOGS` | Scrub credential-shaped strings from log output |

SecurityScarletAI exercise telemetry (`SCARLETAI_URL` / `SCARLETAI_TOKEN`) is
**opt-in** and off by default — see `.env.example`.

Operator safety defaults: the MCP proxy binds loopback only, URLs are
validated to `http`/`https`, DoS-class commands gate behind `--force`, and
`scope-check` / `safety-check` enforce a human-in-the-loop gate.

---

## Ecosystem: attack and defend in one loop

NeuralStrike is the offensive half of a three-part story, and the wiring is
real, not aspirational:

- **NeuralGuard-AI-Firewall** screens each payload before it reaches the
  victim. `neuralstrike neuralguard-bench` runs the canonical attack chain
  and reports the attack success rate **with and without** the firewall,
  plus the per-phase delta:

  ```bash
  # Bundled deterministic fixture — fresh-clone runnable, no external deps:
  neuralstrike neuralguard-bench

  # Real in-process NeuralGuard (install the sibling repo):
  uv pip install -e ../NeuralGuard-AI-Firewall
  neuralstrike neuralguard-bench --in-process

  # Live deployment:
  neuralstrike neuralguard-bench --neuralguard-url http://localhost:8000
  ```

  The bundled fixture is a deterministic, contract-compatible stand-in
  (clearly labeled everywhere) so the plumbing is provable on a fresh clone.
  One honest caveat: attacker and defender share an author, so this measures
  **defense-in-depth and regression detection**, not neutral third-party
  validation.

- **SecurityScarletAI** closes the purple loop: with telemetry enabled, every
  exercise reports `exercise_start` / `probe_*` / `exercise_end` events to the
  SIEM, and `purple-report` joins your local receipt with what the SIEM
  actually caught — per-payload caught/gap/resisted table, the
  **UNDETECTED-SUCCEEDED defense-gap list**, and trend vs. the previous
  exercise. Queries fail loud; a report is never silently partial. Canary
  values never leave the process, and a dead SIEM never fails an exercise
  (telemetry is observability, never a control).

---

## Development

### Quality gate (what CI enforces)

The gate has **one description**, and it is a file you can run before pushing:

```bash
scripts/dev_env.sh        # build .venv from the hash-pinned lock, then run the gate
```

`scripts/dev_env.sh` installs `requirements-dev.txt` with `--require-hashes` (the same locked dev
extra the CI `supply-chain` job installs) and then hands off to `scripts/ci_gate.sh`, which is
literally the file both CI jobs execute. An existing environment can be gated with:

```bash
PYTHON=.venv/bin/python bash scripts/ci_gate.sh
```

which runs, in order:

```bash
python -m ruff check src tests
python -m mypy src                                   # strict on src/
python -m pytest --cov=neuralstrike --cov-report=term-missing --cov-fail-under=85
```

**Why the lock is not optional.** On 2026-11-11 the suite passed locally and failed twice in
CI on a test that was correct in substance, because `.venv` and CI resolved different versions
from the same unbounded range (`typer>=0.12` gave 0.29.0 locally, 0.28.0 in CI). `typer` is now
pinned exactly, `requirements-dev.txt` is the lock for the dev extra, and a contract fails if
the two disagree or if a workflow inlines a gate command instead of calling the shared script.
The lock is compiled for CPython 3.12 and `scripts/dev_env.sh` refuses any other interpreter
rather than resolving a different wheel set and calling it the same gate.

CI (`.github/workflows/ci.yml`) runs three jobs on every push and PR:

| Job | What it does |
|---|---|
| **quality** | Unbounded install (**compatibility probe**, by design) + `scripts/ci_gate.sh` on Python 3.11, 3.12, 3.14 — it exists to discover a break in the latest resolution, so it is deliberately not locked |
| **supply-chain** | Installs the hash-pinned lock, runs `scripts/ci_gate.sh` (the gating install), `pip-audit`, a CycloneDX SBOM, and the fresh-clone smoke test |
| **dashboard** | `npm ci`, report-parsing tests, production build |

Current state, measured on this machine: **2,707** collected (**2,700** pass, **7** skip), **91.98 %**
coverage (85 % enforced), mypy strict over 147 files. CI runs the same suite and skips seven more
tests that need the private evidence root or the pinned tau-bench checkout. The breadth table above
is derived from the same tree, and `tests/test_readme_claims.py` re-derives every number in it. Local measurement on macOS arm64 / CPython 3.12.14; CI is the authority.

### Project structure

```
NeuralStrike/
├── src/neuralstrike/
│   ├── main.py                 # Typer CLI — all subcommands
│   ├── core/                   # config, async LLM manager, adversarial loop, trajectory, attack memory
│   ├── modules/                # recon / weaponize / exploit / post-ex kill-chain modules
│   ├── adapters/               # openai_endpoint, langgraph, langgraph_server, mcp_http, a2a
│   ├── oracles/                # deterministic oracles + judge + evidence tiers
│   ├── evaluation/             # verdicts, statistics, baselines, calibration, judge auditing
│   ├── attacks/                # indirect injection, adaptive (pair/tap/crescendo/trace), MCP, MINJA, RAG, A2A, ASCII smuggling
│   ├── transforms/             # 18-codec evasion pipeline with winnability guard
│   ├── defenses/               # payload-transform defenses + checkers + delta harness
│   ├── identity/               # JWS, JCS, HTTP Message Signatures, DID resolution
│   ├── packs/                  # HarmBench / JailbreakBench / CyberSecEval / local
│   ├── integrations/           # NeuralGuard screen contract + canonical attack chain
│   ├── corpus/                 # typed scenario loader
│   └── reports/                # json, sarif, junit, markdown, pdf, compliance, readme_mapping
├── corpus/                     # OWASP-tagged scenario YAML (60 scenarios)
├── dashboard/                  # Vite + React report viewer (TypeScript)
├── tests/                      # 120 files, 1,026 test functions (2,707 collected cases)
├── docs/threat_model.md
├── .github/workflows/ci.yml
├── Dockerfile / docker-compose.yml
├── pyproject.toml              # single source of deps + tool config
├── .env.example
├── USAGE.md · CHANGELOG.md · SECURITY.md · LICENSE
```

### Contributing

1. Fork, create a feature branch.
2. Make your change; run the quality gate above (ruff, mypy, targeted tests).
3. Keep commit messages conventional (`feat:`, `fix:`, `docs:`, `test:`).
4. Open a PR against `main`. CI must be green.

Attack content in this repo exists only to score against the harness's own
oracles and bundled fixtures — please don't submit payloads whose only purpose
is real-world abuse. New probes need a deterministic oracle or an explicit
`--judge` contract.

### Roadmap

- **MCP stdio poisoning scans.** Bounded stdio discovery shipped (`mcp-inspect`); `mcp-scan` is
  still HTTP-only, so a stdio server can be inspected and receipted but not scanned.
- **A2A delegation-chain attacks** against live, identity-defended endpoints. The analyzer exists
  as a tested library; no command drives it.
- Judge-audit gate thresholds once baseline numbers exist across common models.
- Wider benchmark-pack coverage.
- A second-person review of anything in this repository. That is the only item on this list that
  no amount of code can close.

---

## Responsible disclosure

Found a way to break the harness itself, or a vulnerability in a target you
tested with it? See [SECURITY.md](SECURITY.md) before opening a public issue.

## Ethical use

NeuralStrike is for **authorized security testing only**.

1. Only test systems you own or have **written authorization** to test.
2. Report vulnerabilities responsibly (see [SECURITY.md](SECURITY.md)).
3. Unauthorized access to computer systems is illegal.

## Acknowledgments

NeuralStrike builds on the published state of the art:

- **PAIR** (Chao et al., 2023) and **TAP** (Mehrotra et al., 2023) — adaptive
  jailbreak strategies
- **Crescendo** — multi-turn ladder attacks
- **HarmBench**, **JailbreakBench**, **CyberSecEval** — benchmark packs
  (imported on demand, license-gated, never vendored)
- **MINJA** and **PoisonedRAG** — memory- and retrieval-poisoning techniques
- **OWASP Top 10 for LLM Applications (2025)** and **OWASP Top 10 for Agentic
  Applications (2026)** — the coverage map
- **MITRE ATLAS** — attack-technique mapping
- The MCP and A2A communities for protocol specifications and real-world
  incident case studies

## License

[MIT](LICENSE) — see the LICENSE file.