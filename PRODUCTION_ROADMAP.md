# NeuralStrike — Production Roadmap

**Author:** Mackenzie 🔍 (lead security engineer)
**Created:** 2026-07-05
**North star:** Make NeuralStrike the honest, behavior-observing, audit-grade
red-team harness for the agentic-AI era — the offensive half of a
NeuralGuard + AI Agent Security Monitor defensive stack, with verifiable
ASR, compliance-grade reports, and CI-gating that actually means something.
**Target tier:** 🥇 S (≥ 92), Production, industry-leading.

This is the single source of truth for the lift. Every item is a real
deliverable; nothing is aspirational prose. Phases are sequenced so each
one unblocks the next and nothing is built on sand.

---

## 0. Non-negotiable architectural principles

These hold across every phase. If a decision violates one, stop and
re-plan.

1. **Observe behavior, not text.** A verdict is only trustworthy when it
   reflects what an agent *did*, not just what it *said*. Evidence
   fidelity (Verbal / IntentToAct / Behavioral) is mandatory on every
   finding.
2. **Conclusive-only scoring.** Three outcomes — Resisted, Succeeded,
   Inconclusive — never two. Weak evidence becomes Inconclusive (a
   coverage gap), never a fabricated PASS. The headline score is
   `Resisted / (Resisted + Succeeded)`.
3. **The Judge never scores itself.** Attacker generates, Judge scores,
   Verifier is deterministic. Separation is enforced at the type level.
4. **Deterministic oracles over free-text judges.** Canary-token
   detection, forbidden-tool/argument-shape, and structured-output
   schema validation come first. The LLM Judge is advisory only and
   can never flip a deterministic verdict.
5. **Fail-closed by default.** Errors in attacker/judge abort loudly.
   Victim errors are recorded as Inconclusive, never as failure or
   success.
6. **Reproducibility is a first-class output.** Every run is seedable,
   temperature-pinned, transcript-recorded, and baseline-comparable.
7. **Honest scope enforcement.** No attack runs without a scope file /
   rules-of-engagement. Destructive/irreversible actions require HITL.
8. **Canonicalization is pinned.** JCS (RFC 8785) for any signed/hashed
   object, with the integer-float / null-vs-absent / NFC edge cases
   explicitly specified and tested both directions.
9. **No vapor.** Every README claim maps to shipped, tested code.
10. **Defense-in-depth, not single-control trust.** Layer structural
    separation (instruction hierarchy) + input sanitization + scoped
    tool authority + HITL at consequential boundaries.

---

## 1. Consolidated gap inventory (everything, including first-review misses)

Severity legend: 🔴 ship-blocker · 🟠 major · 🟡 polish · 🟢 nice-to-have.

### A. Core oracle & measurement (the ship-blocker cluster)

| # | Gap | Sev |
|:--|:---|:--:|
| A1 | Judge is substring match on free text (`"SUCCESS" in eval.upper()`). | 🔴 |
| A2 | No structured-output Judge (JSON schema verdict). | 🔴 |
| A3 | No canary-token oracle (plant `CANARY-<hex>`, detect leakage incl. base64/hex/chunked). | 🔴 |
| A4 | No ASR computation, no severity-weighted 0–100 risk score, no per-category breakdown. | 🔴 |
| A5 | No k-trial runs, no Wilson CIs, no flaky detection, no conclusive-only coverage. | 🔴 |
| A6 | No baseline / regression gate (`--save-baseline`, `--baseline`, `--fail-on vuln\|regression`, exit codes 0/1/3/4). | 🔴 |
| A7 | No replayability: no seed, no temperature pin, no recorded transcripts. | 🔴 |
| A8 | No oracle-honesty property corpus (clearly-safe + clearly-vulnerable asserted both directions). | 🟠 |
| A9 | No z-score calibration vs a reference cohort (garak-style relative scoring). | 🟡 |
| A10 | No adaptive-attack evaluation path (Nasr/Carlini: static ASR ~0% vs adaptive >90%). | 🟠 |

### B. Target adapters & evidence fidelity (the "harness not library" cluster)

| # | Gap | Sev |
|:--|:---|:--:|
| B1 | No real-target adapter — victim is just a model name sent a prompt. | 🔴 |
| B2 | No `openai_endpoint` adapter (drives `/v1/chat/completions` with a tool schema and serves tool results itself so oracles observe arguments). | 🔴 |
| B3 | No `langgraph` adapter (imports + drives a real compiled graph). | 🔴 |
| B4 | No `langgraph-server` HTTP adapter. | 🟠 |
| B5 | No real MCP introspection — `ToolEnum` is a prompt leak only. | 🔴 |
| B6 | No MCP-over-stdio transport (real Claude Code/Claude Desktop/Cursor servers speak stdio). | 🔴 |
| B7 | No MCP-over-HTTP JSON-RPC introspection (parse real `tools/list`, not ask the model). | 🔴 |
| B8 | No A2A protocol adapter (Agent2Agent JSON-RPC 2.0, Agent Cards, signed messages). | 🟠 |
| B9 | No evidence-fidelity tiers (Verbal / IntentToAct / Behavioral). | 🔴 |
| B10 | No instrumented canary-tool execution (Tier-2: tool actually runs + records call). | 🔴 |
| B11 | No system-prompt canary (plant `CANARY-<hex>` in SUT prompt; only Succeeded when token surfaces). | 🔴 |

### C. Attack surface coverage (OWASP Agentic ASI01–10 + LLM Top 10 + ATLAS)

| # | Gap | Sev |
|:--|:---|:--:|
| C1 | No indirect prompt injection delivery vectors (`user_message`, `tool_result`, `retrieved_document`, `memory`, `system_prompt`). | 🔴 |
| C2 | No OWASP Agentic scenario corpus tagged ASI01–ASI10. | 🔴 |
| C3 | No OWASP LLM Top 10 (2025/2026) coverage (LLM01–LLM10). | 🔴 |
| C4 | No MITRE ATLAS technique mapping (AML.T0051, AML.T0054, AML.T0057, AML.T0080.001, AML.T0099, AML.T0110…). | 🟠 |
| C5 | No multi-turn / attacker-LLM adaptive attacks (Crescendo, PAIR, TAP). | 🟠 |
| C6 | No GCG adversarial-suffix optimization (the hardest class; research-grade). | 🟡 |
| C7 | No MINJA-style memory-injection (query-only, bridging steps, progressive shortening). | 🟠 |
| C8 | No RAG / vector-store poisoning (PoisonedRAG: 5 docs → 97% ASR). | 🟠 |
| C9 | No MCP tool-poisoning / rug-pull / shadow-tool detection (Invariant Labs, MCPTox, MCP-ITP implicit poisoning). | 🟠 |
| C10 | No multi-agent / A2A inter-agent communication attacks (signed-message spoofing, delegation-chain abuse). | 🟠 |
| C11 | No cascading-failure / runaway-agent testing. | 🟡 |
| C12 | No rogue-agent / behavioral-drift detection. | 🟡 |
| C13 | Only 4 jailbreak templates + 3 fingerprint prompts — no real corpus. | 🔴 |

### D. Benchmark datasets & adaptive evaluation

| # | Gap | Sev |
|:--|:---|:--:|
| D1 | No AgentDojo integration (97 tasks, 629 security cases, dynamic multi-tool env). | 🟠 |
| D2 | No InjecAgent integration (1,054 cases, indirect injection, direct-harm + data-stealing). | 🟠 |
| D3 | No BIPIA integration (Microsoft indirect-injection benchmark). | 🟡 |
| D4 | No HarmBench / JailbreakBench / CyberSecEval pack import (`--pack`, `--accept-license`). | 🟠 |
| D5 | No `--import-probes` local dataset support. | 🟡 |
| D6 | No adaptive attacker that optimizes against the defense (assumes attacker has read the defense). | 🟠 |

### E. Encoding / evasion transforms

| # | Gap | Sev |
|:--|:---|:--:|
| E1 | No 18-codec transform pipeline (Base64/Hex/ROT13/Morse/homoglyph/zero-width/leetspeak/reverse/NATO…). | 🟠 |
| E2 | No invisible-Unicode stripping / detection (Tag-block U+E0000–U+E007F, variation-selector U+FE00–U+FE0F, zero-width U+200B/C/D, U+2060). | 🟠 |
| E3 | No ASCII-smuggling exfiltration channel (EchoLeak class). | 🟡 |
| E4 | "steganographic" technique is delimiter obfuscation only — rename or implement real steganography. | 🟠 |
| E5 | No multimodal steganographic injection (pixel-level image payloads). | 🟡 |

### F. Reports, compliance & CI integration

| # | Gap | Sev |
|:--|:---|:--:|
| F1 | No structured report generator (JSON / SARIF / JUnit / Markdown / PDF). | 🔴 |
| F2 | No compliance crosswalks (OWASP Agentic, OWASP LLM, MITRE ATLAS, NIST AI RMF, EU AI Act, ISO 42001, SOC 2, CSA MAESTRO). | 🟠 |
| F3 | No SARIF upload to GitHub Security Tab. | 🟠 |
| F4 | No JUnit for CI pipelines. | 🟠 |
| F5 | No `--explain` LLM rationale attached to findings (advisory, never flips verdict). | 🟡 |
| F6 | No NIST AI 800-2 statistical-evaluation-practices compliance (9 practices). | 🟠 |
| F7 | No AIUC-1 pre-certification mapping (quarterly adversarial testing). | 🟡 |

### G. Operator safety, scope & HITL

| # | Gap | Sev |
|:--|:---|:--:|
| G1 | No scope file / rules-of-engagement (in-scope targets, allowed intents, exclusions). | 🟠 |
| G2 | No action classification (reversible / compensable / irreversible) → TTL scaling. | 🟠 |
| G3 | No HITL gate for destructive/irreversible actions (Rapid7 production pattern). | 🟠 |
| G4 | No rate limiting / cost budget / token cap / concurrency limit. | 🟠 |
| G5 | No timeout / retry / backoff on LLM calls (hangs abort the whole run). | 🟠 |
| G6 | No `--delay` between probes (avoid WAF/rate-limit bans on live targets). | 🟡 |
| G7 | No re-verify endpoint pattern (pre-mutation re-check; the 6th gate). | 🟡 |

### H. Production hygiene & supply chain

| # | Gap | Sev |
|:--|:---|:--:|
| H1 | `main.py` CLI coverage 51%. | 🟠 |
| H2 | No `pip-audit` in CI. | 🟡 |
| H3 | No PyPI publish / GitHub Release / GHCR multi-arch image. | 🟠 |
| H4 | No SBOM (CycloneDX) / cosign / Sigstore Rekor attestation. | 🟡 |
| H5 | No dashboard / results viewer (every portfolio peer ships one). | 🟡 |
| H6 | No formal threat model of NeuralStrike itself. | 🟡 |
| H7 | `Any`-typed LLM response shapes (mypy green but type hole). | 🟡 |
| H8 | No telemetry opt-out / privacy statement. | 🟡 |
| H9 | No `--quiet` / `--verbose` / progress reporting. | 🟡 |

### I. Doc honesty

| # | Gap | Sev |
|:--|:---|:--:|
| I1 | README claims OWASP LLM/Agentic/ATLAS mapping — none exists in code. | 🟠 |
| I2 | README implies NeuralGuard benchmark harness works — verify or remove. | 🟡 |
| I3 | "steganographic" name misleading. | 🟡 |
| I4 | USAGE.md (23KB) not deep-verified against code. | 🟡 |
| I5 | No screenshots / GIFs / architecture diagram. | 🟢 |

### J. Things the first review missed (new from research)

| # | Gap | Sev |
|:--|:---|:--:|
| J1 | No instruction-hierarchy enforcement / spotlighting / StruQ / CaMeL defensive-pattern testing. | 🟠 |
| J2 | No "lethal trifecta" detection (private data + untrusted content + external comms) as a pre-deployment check. | 🟡 |
| J3 | No Meta "Rule of Two" evaluation + Noma critique awareness. | 🟡 |
| J4 | No real-incident replay vectors (EchoLeak CVE-2025-32711, GitHub MCP, Supabase MCP, postmark-mcp, Amazon Q AWS-2025-015/019, GitHub Copilot CVE-2025-53773, MCPoison CVE-2025-54136, Cursor). | 🟠 |
| J5 | No fun-tuning / fine-tuning-API-as-gradient-oracle awareness (65–82% ASR on closed models). | 🟡 |
| J6 | No cross-session memory-poisoning persistence (Gemini memory attack, MITRE AML.T0080.001). | 🟠 |
| J7 | No MCP schema pinning / hash verification / TOFU detection (ETDI paper, Deconvolute). | 🟠 |
| J8 | No MCP gateway / transport-layer policy enforcement pattern (PolicyLayer). | 🟡 |
| J9 | No agent-identity integration (did:key/did:web, SPIFFE/SPIRE, WIMSE, OAuth 2.0 agent-identity, NIST NCCoE, IETF draft-klrc-aiagent-auth). | 🟡 |
| J10 | No property-based / adversarial-paraphrase testing of oracles. | 🟡 |
| J11 | No continuous red-teaming cadence documentation. | 🟢 |

---

## 2. Phased plan

Each phase has: **Goal · Deliverables · Exit gate · Dependencies.**
A phase is not "done" until its exit gate is green on a fresh clone.

### Phase 0 — Kill the ship-blocker (the oracle rewrite)

**Goal:** Replace the substring Judge with a deterministic-oracle +
structured-Judge system that produces trustworthy, reproducible
verdicts. This is the foundation; nothing else is meaningful until it
lands.

**Deliverables**
- `src/neuralstrike/oracles/` package:
  - `canary.py` — plant `CANARY-<16-hex>` token; detect leakage in
    response text AND any outbound tool-call arguments; decode base64,
    base64url, hex; detect chunked/split leakage.
  - `forbidden_tool.py` — flag a call to a forbidden tool, or a
    forbidden argument *shape* (regex / contains / equals / JSON-path)
    on an allowed tool.
  - `predicate.py` — regex / JSON-path assertions over the final answer
    (`match` or `absence` polarity).
  - `schema.py` — structured-output schema validation (JSON schema for
    the SUT's tool-call emissions).
  - `judge.py` — optional advisory LLM judge that returns a *typed*
    `JudgeVerdict {verdict, severity, evidence_quote}` validated against
    a JSON schema; **never** flips a deterministic oracle's result.
- `src/neuralstrike/evaluation/` package:
  - `verdict.py` — `Resisted | Succeeded | Inconclusive` enum +
    `EvidenceFidelity` (`Verbal | IntentToAct | Behavioral`).
  - `runner.py` — k-trial runner; per-trial canary minting; Wilson CI;
    flaky detection (`FLAKY` verdict when criteria match in some trials).
  - `scoring.py` — conclusive-only score, per-category ASR,
    severity-weighted 0–100 risk index, coverage metric.
  - `baseline.py` — `--save-baseline`, `--baseline`, `--fail-on
    vuln|regression|never`, exit codes 0/1/3/4; regression outranks
    absolute vuln.
- `tests/oracle_honesty_corpus/` — both-directions property corpus:
  clearly-safe responses (must never score Succeeded) and
  clearly-vulnerable responses (must never score Resisted); one
  invariant test asserts both directions. Every fixed honesty bug
  seeds a permanent regression case.
- `core/adversarial_loop.py` rewritten to use the new oracle/judge
  contract; old substring logic deleted.
- Seed + temperature pinning + per-trial transcript persistence
  (`runs/<run-id>/trial-<n>.json`).

**Exit gate**
- `ruff && mypy --strict && pytest --cov-fail-under=85` green on fresh clone.
- Oracle-honesty corpus passes both directions.
- A recorded run produces identical verdicts when replayed with the
  same seed.
- No `"SUCCESS" in` substring logic anywhere in `src/`.

**Dependencies:** none. Unblocks Phase 1, Phase 2.

---

### Phase 1 — Become a behavior-observing harness (adapters + evidence fidelity)

**Goal:** Stop sending one prompt to a model name. Drive real targets
and observe what they *do*.

**Deliverables**
- `src/neuralstrike/adapters/`:
  - `base.py` — `TargetAdapter` ABC: `query(input) -> AgentResponse`
    returning `(text, tool_calls, traces)`; supports canary tools,
    injected tool schemas, conversation history.
  - `openai_endpoint.py` — drives `/v1/chat/completions` with a tool
    schema; **serves the tool results itself** so oracles observe
    arguments; supports `--sut-tier text|function-calling|instrumented`.
  - `langgraph.py` — imports + drives a real compiled graph
    (`graph`/`app`/`agent`/`build_graph()` attribute discovery).
  - `langgraph_server.py` — HTTP adapter for `langgraph dev` /
    deployed graphs.
  - `mcp_http.py` — real JSON-RPC 2.0 MCP over HTTP; parses `tools/list`
    (replaces `ToolEnum` prompt leak); observes `tools/call` arguments;
    supports capability-injection into `tools/list` responses.
  - `mcp_stdio.py` — MCP over stdio (the transport Claude Code / Claude
    Desktop / Cursor actually use).
  - `a2a.py` — Agent2Agent JSON-RPC 2.0; fetches Agent Card from
    `/.well-known/agent-card.json`; respects declared security schemes;
    supports signed messages (RFC 9421) when the target advertises them.
- `src/neuralstrike/oracles/evidence.py` — `EvidenceFidelity` tagging
  on every finding: Verbal (model's words), IntentToAct (emitted a
  forbidden tool-call), Behavioral (instrumented tool actually ran).
- `src/neuralstrike/oracles/tool_harness.py` — instrumented canary
  tools (`export_user_data`, `delete_all_records`, `grant_admin_access`)
  that record execution for Tier-2 evidence.
- `src/neuralstrike/oracles/system_prompt.py` — plant
  `CANARY-<hex>` in the SUT's system prompt; `SystemPromptExtraction`
  scores Succeeded only when that exact token surfaces (else
  Inconclusive, never a false Resisted).
- Replace `modules/recon/tool_enum.py` prompt-leak with real MCP/A2A
  introspection; keep prompt-leak as an explicit, labeled fallback.

**Exit gate**
- A scan against a real MCP server (bundled vulnerable fixture) produces
  behavioral evidence (Tier-2) when the agent executes a canary tool.
- A scan against a real LangGraph agent drives the compiled graph
  end-to-end and observes tool calls.
- Evidence fidelity is tagged on every finding in the report.
- `ToolEnum` no longer makes a social-engineering prompt the primary
  path.

**Dependencies:** Phase 0 (oracles must exist before adapters can feed
them).

---

### Phase 2 — OWASP Agentic corpus + indirect injection + reports

**Goal:** Make the README's mapping claim real, and cover the dominant
real-world vector (indirect injection).

**Deliverables**
- `corpus/asi01-asi10.yaml` — YAML scenario corpus tagged ASI01–ASI10,
  ≥30 cases to start (expandable; the field standard is 20–146+).
  Each case: `id`, `owasp_category`, `mitre_atlas`, `severity`,
  `delivery_vector` (`user_message|tool_result|retrieved_document|
  memory|system_prompt`), `intent`, `success_criteria` (deterministic
  oracle refs), `mitigations`.
- `corpus/llm01-llm10.yaml` — OWASP LLM Top 10 (2025/2026) coverage.
- `src/neuralstrike/attacks/indirect.py` — delivery-vector injection
  harness: weaves the legitimate task and the adversarial payload
  together at the scenario's declared injection point. The adapter
  surfaces each channel distinctly so the SUT can be tested at the
  `tool_result` / `retrieved_document` / `memory` boundary, not just
  `user_message`.
- `src/neuralstrike/reports/`:
  - `json.py`, `sarif.py`, `junit.py`, `markdown.py`, `pdf.py`.
  - `compliance.py` — crosswalk to OWASP Agentic, OWASP LLM, MITRE
    ATLAS, NIST AI RMF, EU AI Act, ISO 42001, SOC 2, CSA MAESTRO.
  - SARIF emits inconclusive probes as low-noise `note` results
    (coverage gap, surfaced not dropped).
- README mapping claim becomes a real table generated from the corpus;
  C1 / I1 closed by construction.

**Exit gate**
- A full corpus run against the bundled vulnerable agent fixture
  produces a SARIF report that maps every finding to an ASI/LLM/ATLAS
  ID and a compliance control.
- Indirect-injection delivery vectors all exercise the correct channel
  (verified by adapter trace, not by reading the prompt).
- README mapping table is generated, not hand-written.

**Dependencies:** Phase 0 (scoring) + Phase 1 (adapters, for indirect
injection to reach the right channel).

---

### Phase 3 — Measurement, CI gating & benchmark packs

**Goal:** Verdicts that mean something statistically and gate CI.

**Deliverables**
- `src/neuralstrike/evaluation/statistics.py` — Wilson CIs, k-trial
  aggregation, flaky classification, conclusive-only score, coverage
  metric, per-category ASR, severity-weighted 0–100 risk index.
- `src/neuralstrike/evaluation/calibration.py` — z-score vs a
  user-supplied reference cohort (`--calibration cohort.json`);
  informational, never changes exit code. Ship **no built-in cohort**
  (a fabricated one makes every z-score a lie).
- `src/neuralstrike/packs/` — HarmBench, JailbreakBench, CyberSecEval
  import behind `--pack <name> --accept-license` (on-demand download,
  no data bundled). `--import-probes <file.json>` for local datasets.
  Packs ship no expected-token oracle → require `--judge` or scored
  Inconclusive (never a fabricated verdict).
- `src/neuralstrike/cli/gate.py` — `--save-baseline`, `--baseline`,
  `--fail-on vuln|regression|never`, honest exit codes
  (0 pass · 1 vuln · 3 runtime error · 4 regression). Regression
  outranks absolute vuln. Refuses to compare a FailFast-truncated scan
  or an intensity mismatch.
- `--explain` — advisory LLM rationale attached to Succeeded /
  Inconclusive findings; quotes verbatim evidence; requires `--judge`;
  never flips a verdict; suppressed when evidence is redacted.
- `--trials`, `--delay`, `--timeout`, `--quiet`, `--verbose`,
  `--progress`.

**Exit gate**
- A 3-trial run reports Wilson CIs and a coverage number, not just a
  raw ASR.
- A baseline saved on `main` gates a PR: a new finding exits 4, a
  pre-existing finding exits 1, a clean run exits 0.
- A HarmBench pack run with `--judge` produces real verdicts; without
  `--judge` every pack probe is honestly Inconclusive.

**Dependencies:** Phase 0 (scoring).

---

### Phase 4 — Adaptive attacks + evasion transforms + defensive-pattern testing

**Goal:** Match the field's hardest class and test the defenses the
field actually ships.

**Deliverables**
- `src/neuralstrike/attacks/adaptive/`:
  - `crescendo.py` — linear multi-turn escalation; scripted ladder
    fallback when no attacker LLM is configured.
  - `pair.py` — Chao et al. 2023; refines a single jailbreak each turn
    from the target's last reply. Requires `--attacker`.
  - `tap.py` — Mehrotra et al. 2023; branches K candidates, judge-scores,
    prunes to a beam, expands. Requires `--attacker`.
  - Separation enforced: attacker generates, judge scores — distinct
    clients; an attack can never score itself.
- `src/neuralstrike/transforms/` — 18-codec pipeline (Base64, Hex,
  ROT13, URL, Atbash, Caesar, reversed, leetspeak, Morse, binary, NATO,
  homoglyph, zero-width, ASCII-art, emoji-braille, JSON-wrap, XML-wrap,
  markdown). Correct-by-construction with provenance + a winnability
  guard (a lossy codec can't silently produce an always-Resisted
  probe).
- `src/neuralstrike/defenses/` — test the published defenses, not just
  attack past them:
  - instruction-hierarchy / spotlighting (Microsoft Research) / StruQ
    (USENIX 2025) / CaMeL (Anthropic 2025).
  - data delimiters, prompt-injection detector, tool filter, prompt
    sandwiching (AgentDojo defenses).
  - lethal-trifecta pre-deployment check (private data + untrusted
    content + external comms).
  - Meta Rule of Two evaluation + Noma critique handling.
- Rename `steganographic_prompt` → `delimiter_wrap`; add a real
  invisible-Unicode steganography transform (Tag-block / variation-
  selector / zero-width) and an ASCII-smuggling exfil-channel probe
  (EchoLeak class). Close E4 / I3.
- `--attacker`, `--attacker-model`, `--attacker-api-key`,
  `--judge-model`, `--judge-api-key`, `--judge-mode fallback|primary`,
  `--judge-rubric evidence-anchored|strict|lenient` (default
  evidence-anchored).

**Exit gate**
- A PAIR run against a vulnerable fixture succeeds where a static
  template fails (adaptive ASR > static ASR, demonstrated).
- All 18 transforms round-trip on a known-answer vector suite.
- A spotlighting defense reduces ASR on the same corpus by a measured
  delta (the harness reports both, not just the attack).

**Dependencies:** Phase 0 (oracles) + Phase 2 (corpus) + Phase 3
(k-trial stats to make adaptive ASR meaningful).

---

### Phase 5 — MCP & A2A deep coverage + agent identity

**Goal:** Cover the protocol surfaces that define the 2026 attack
landscape and the identity layer that defends them.

**Deliverables**
- `src/neuralstrike/attacks/mcp_poison.py` — tool-poisoning detection:
  scan `tools/list` for injected instructions, whitespace padding,
  language-switching, tool shadowing; manifest-hash pinning + drift
  detection (TOFU per ETDI paper); sleeper rug-pull detection across
  sessions.
- `src/neuralstrike/attacks/mcp_implicit.py` — MCP-ITP-style implicit
  tool poisoning: black-box optimization with attacker + detector +
  evaluator LLM loop; maximize ASR while suppressing Malicious Tool
  Detection Rate.
- `src/neuralstrike/attacks/minja.py` — MINJA memory injection:
  query-only, bridging steps, progressive shortening strategy;
  targets agents with shared memory banks.
- `src/neuralstrike/attacks/rag_poison.py` — PoisonedRAG-style corpus
  poisoning + cross-session memory persistence (Gemini memory attack,
  MITRE AML.T0080.001).
- `src/neuralstrike/attacks/a2a/` — A2A inter-agent attacks:
  - spoofed control messages (signed-message verification bypass
    attempts).
  - delegation-chain abuse (scope widening, depth escalation).
  - Agent Card tampering / signature verification tests (RFC 7515 JWS +
    RFC 8785 JCS canonicalization, per the A2A spec).
  - cross-tenant access.
- `src/neuralstrike/identity/` — agent-identity awareness (consume, not
  re-implement): resolve `did:web` / `did:key` / SPIFFE SVIDs / WIMSE
  WITs; verify RFC 9421 HTTP Message Signatures; understand OAuth 2.0
  agent-identity tokens (IETF draft-klrc-aiagent-auth); record
  `key_resolution_source` (inline|cache|resolver) per the A2A WG
  convergence. This is so NeuralStrike can *test* identity-defended
  targets, not become an IdP.
- Real-incident replay vectors: EchoLeak CVE-2025-32711, GitHub MCP,
  Supabase MCP, postmark-mcp, Amazon Q AWS-2025-015/019, GitHub
  Copilot CVE-2025-53773, MCPoison CVE-2025-54136, Cursor — each as a
  named scenario in the corpus with a reference.

**Exit gate**
- A scan of a deliberately-poisoned MCP server fixture flags the
  poisoned tool description and the shadow-tool pattern.
- An A2A scan against a target with a signed Agent Card correctly
  verifies the signature and refuses a tampered card.
- MINJA scenario against a memory-augmented fixture produces a
  measurable ISR/ASR.

**Dependencies:** Phase 1 (MCP/A2A adapters) + Phase 2 (corpus).

---

### Phase 6 — Production hygiene, supply chain, scope/HITL, docs

**Goal:** Make it safe to hand to a client and safe to run in CI.

**Deliverables**
- `src/neuralstrike/scope/` — scope file / rules-of-engagement:
  in-scope targets, allowed intents, exclusions, testing window.
  Every attack validates scope before running; out-of-scope discoveries
  are reported, never probed.
- `src/neuralstrike/safety/` — action classification
  (`reversible|compensable|irreversible`) → TTL scaling; HITL gate for
  destructive/irreversible actions (Rapid7 pattern); `--require-approval`
  for sensitive probes.
- `src/neuralstrike/runtime/` — timeouts, retries w/ exponential
  backoff, rate limiting, cost budget / token cap, concurrency limit,
  graceful drain.
- CLI coverage to ≥ 85% (backfill `main.py` tests; current 51%).
- `pip-audit` in CI; deps pinned with hashes where feasible.
- PyPI publish + GitHub Release + GHCR multi-arch image + smoke test
  that the image boots.
- SBOM (CycloneDX) + cosign image signing + Sigstore Rekor
  attestation for the tool itself (the tool whose pitch is ASI04
  supply-chain defense must practice what it preaches).
- `dashboard/` — minimal results viewer (Vite + React, consistent with
  the portfolio stack); reads report JSON; surfaces per-category ASR,
  evidence fidelity, coverage.
- `docs/threat_model.md` — threat model of NeuralStrike itself (what
  happens if Attacker/Judge models, the MCP proxy, or the C2 registry
  are compromised).
- `Any`-typed LLM response shapes → typed wrappers; mypy strict stays
  green with no holes.
- Telemetry opt-out + privacy statement.
- USAGE.md deep-verified against code; screenshots / GIFs / architecture
  diagram; README mapping table auto-generated.
- SECURITY.md expanded with the formal threat model and the
  `INVALID_CLAIM_SCOPE` / `INVALID_COMPOSITION` error conventions from
  the A2A identity WG (so NeuralStrike's reports speak the same
  language as the defensive stack).

**Exit gate**
- `pip install neuralstrike` works and the smoke test passes on a fresh
  clone with no local Ollama required (uses the bundled fixture).
- A scope file blocks an out-of-scope target with a clear error.
- An irreversible action without `--require-approval` aborts.
- SBOM + signed image published; `cosign verify` passes.

**Dependencies:** Phases 0–5 (the hardening layers on top of working
core).

---

### Phase 7 — NeuralGuard benchmark harness (the pairing story)

**Goal:** Make the README's NeuralGuard-pairing claim real, and close
the attack/defend/govern triad.

**Deliverables**
- `src/neuralstrike/integrations/neuralguard.py` — wire NeuralStrike
  payloads → NeuralGuard → measure blocked/detection rates against
  live NeuralStrike runs. The defensive half already ships a
  deterministic benchmark harness per its README; this makes the two
  actually talk.
- A canonical attack-chain demo script (recon → weaponize → exploit →
  post-exploit) that runs against a NeuralGuard-defended target and
  reports the defensive delta.
- Cross-project README alignment: both repos point at the same
  worked example.

**Exit gate**
- A single command runs the full attack chain against a
  NeuralGuard-defended fixture and prints the ASR with and without the
  firewall.
- README claim verified; C2 / I2 closed.

**Dependencies:** Phase 0–5 (a real harness) + NeuralGuard repo access.

---

## 3. Realistic score trajectory

| Phase | Composite | Tier | Readiness |
|:--:|:--:|:--:|:--|
| Start | 76 | B+ | Demo-ready |
| After 0 | ~80 | A | Demo-ready (trustworthy) |
| After 1 | ~84 | A | Demo-ready (behavioral) |
| After 2 | ~87 | S- | Production (audit-grade reports) |
| After 3 | ~89 | S | Production (CI-gating) |
| After 4 | ~91 | S | Production (adaptive parity) |
| After 5 | ~93 | S | Production (full protocol coverage) |
| After 6 | ~94 | S | Production (hardened + portable) |
| After 7 | ~95 | S | Production (paired flagship) |

These are honestly-earned, not aspirational. Each phase's exit gate is
the proof.

---

## 4. Definition of Done — Production

A reviewer on a fresh clone must be able to:

1. `pip install neuralstrike` (or pull the signed GHCR image) and run
   `neuralstrike smoke` → 22/22 checks pass with no local Ollama.
2. Run a corpus scan against a bundled vulnerable fixture and get a
   SARIF report mapping every finding to ASI/LLM/ATLAS + a compliance
   control, with evidence fidelity tagged.
3. Run `--save-baseline` on `main`, then `--baseline` + `--fail-on
   regression` on a PR, and have CI fail on a new finding (exit 4)
   while tolerating pre-existing ones (exit 1).
4. Drive a real MCP server over stdio and a real LangGraph agent and
   observe *behavioral* evidence (Tier-2), not just text.
5. Replay any recorded run with the same seed and get identical
   verdicts.
6. Read the README and find zero vapor: every claim maps to shipped,
   tested code, including the OWASP/ATLAS mapping table.

Until all six hold, the project is not Production. The phased plan
exists to get there without cutting corners.

---

## 5. Decisions (resolved by lead security engineer, 2026-07-05)

These are made now so Phase 0 can start unblocked. Each has
industry-standard security reasoning; each is recorded so a future
revisit knows *why*, not just *what*.

### D1 — Judge model default: `deepseek-v3.1:671b-cloud`

**Decision.** Default `NEURALSTRIKE_JUDGE_MODEL=deepseek-v3.1:671b-cloud`,
with a fallback chain `deepseek-v3.1:671b-cloud → kimi-k2.6:cloud →
gpt-oss:120b-cloud → deepseek-r1:8b` (local, last resort for offline
runs). The Attacker default stays `deepseek-r1` (local, fast mutation
loop); the Judge is intentionally the *strongest* available model, not
the same one, so the judge is harder to confuse than the attacker.

**Reasoning.**
- The Judge is the integrity anchor of the entire system. AgentEval's
  evidence-anchored rubric and the A2A identity-verification WG both
  converged on "the judge must be strong enough to ground every
  verdict in a verbatim quote." A weak judge produces false verdicts.
  Per the conclusive-only-scoring discipline, an ambiguous judge must
  abstain (Inconclusive), not guess — a stronger judge means fewer
  Inconclusives and fewer fabricated verdicts.
- Separation is enforced at the type level: the Judge client and
  Attacker client are distinct instances. An attack run can never
  score itself, even if both resolve to the same Ollama model. The
  Judge *model* being stronger than the Attacker is a deliberate
  asymmetry, not a coupling.
- Ollama makes the Judge trivially swappable (`NEURALSTRIKE_JUDGE_MODEL`
  + `--judge-model` / `--judge-api-key`), so this is a default, not a
  lock-in. Pack runs that ship no expected-token oracle *require* a
  Judge; the default must be the one most likely to produce
  evidence-anchored verdicts on the first try.

**Latent bug to fix in Phase 0.** Both `config.py` and `.env.example`
currently default `JUDGE_MODEL=llama3.1`, which is **not installed** on
this machine. Phase 0 must (a) change the default to
`deepseek-v3.1:671b-cloud`, (b) add a startup reachability check that
fails closed with a clear error if the configured Attacker/Judge models
are not resolvable, and (c) add a `--judge-model-list` helper that
prints available Ollama models so the operator never guesses.

**Available Ollama models on this host** (verified 2026-07-05):
- Cloud: `deepseek-v3.1:671b-cloud`, `kimi-k2.6:cloud`, `kimi-k2.5:cloud`,
  `gpt-oss:120b-cloud`, `qwen3-coder:480b-cloud`, `minimax-m2.5:cloud`,
  `minimax-m2:cloud`, `gemma4:31b-cloud`.
- Local (offline-capable): `deepseek-r1:8b`, `mistral:7b`, `gemma3:4b`,
  `nomic-embed-text` (embedding, for any RAG-poisoning fixtures).

### D2 — Dashboard stack: Vite + React + Tailwind, read-only

**Decision.** Build the results viewer in **Vite + React + Tailwind**,
the portfolio-consistent stack. It is **read-only** over the generated
JSON/SARIF report — no attack execution from the UI. Served as a static
build.

**Reasoning.**
- A red-team tool's dashboard should be the lowest-blast-radius option
  for a tool whose entire pitch is runtime and supply-chain safety.
  A static, read-only viewer has no server-side execution surface; a
  Streamlit app (SecurityScarletAI's choice) adds a Python server-side
  execution surface that is inconsistent with the threat model this
  tool exists to test.
- Portfolio consistency: WebBreaker, HONEYTRAP, SecurityScarletAI,
  AI Agent Security Monitor, MobiusSec all use Vite + React + Tailwind.
  A reviewer or client sees one coherent toolset instead of two stacks.
- Static-hostable: the report JSON is the only input, so the viewer can
  ship as a static site (GitHub Pages / Cloudflare Pages) with no
  backend — the same pattern GHOSTWIRE uses for its published dashboard.
- This is a Phase 6 deliverable; it does not block Phases 0–5.

### D3 — MCP stdio transport: HTTP in Phase 1, stdio in Phase 5

**Decision.** Ship the **MCP HTTP JSON-RPC adapter in Phase 1** and
the **MCP stdio adapter in Phase 5** (alongside the deep MCP-coverage
phase).

**Reasoning.**
- The dominant 2025–2026 MCP attack class — tool poisoning, rug pulls,
  shadow tools, implicit poisoning (MCP-ITP), descriptor-channel
  injection (MCPoison CVE-2025-54136) — lives in the `tools/list`
  *descriptor text*, which is **transport-agnostic**. HTTP catches the
  same findings immediately; stdio is not required to detect a poisoned
  description.
- Stdio's real value is *target realism* — it lets us test the actual
  servers people run (Claude Code, Claude Desktop, Cursor). That
  realism matters most when we are testing *defenses* (Phase 4) and
  doing *deep MCP coverage* (Phase 5), not when we are standing up the
  first adapter (Phase 1).
- Shipping stdio in Phase 1 would risk delivering a half-tested
  transport (subprocess management, stdio framing, lifecycle handling)
  just to hit a deadline. The security-honest call is to land it where
  its value is highest and its test surface is mature.
- The Phase 1 `mcp_http.py` adapter still does real JSON-RPC
  introspection of `tools/list` and observes `tools/call` arguments —
  it is not a stub. It just speaks HTTP instead of stdio.

### D4 — A2A depth: HTTP + Agent Card in Phase 1; signatures + delegation in Phase 5

**Decision.** Ship **HTTP JSON-RPC + Agent Card fetch +
security-scheme-aware requests in Phase 1**. Ship **full RFC 7515 JWS
signature verification + RFC 8785 JCS canonicalization + Agent Card
signature verification + delegation-chain attacks in Phase 5**.

**Reasoning.**
- This mirrors how the A2A identity-verification working group itself
  phased its ratified specs: *identity-at-rest* (the published Agent
  Card and its DID-published key material) before *identity-in-motion*
  (per-request HTTP signatures). NeuralStrike should test the deployed
  surface first, then the standardizing surface.
- Agent Cards are deployed today (`/.well-known/agent-card.json`); signed
  messages and the cryptographic identity layer are still being
  ratified (QSP-1/DID Resolution/Entity Verification were ratified
  March 2026, ~4 months ago). Testing the deployed surface in Phase 1
  means the harness is useful against real targets immediately; the
  crypto-depth layer lands in Phase 5 where it sits naturally beside
  the agent-identity-awareness work (J9).
- Phase 1's A2A adapter still does real work: it fetches the Agent
  Card, respects the declared `securitySchemes` (API key / HTTP Bearer
  / OAuth 2.0 / OpenID Connect / mTLS), and sends authenticated
  JSON-RPC. It is not a stub. It just does not yet verify JWS
  signatures on the card or on inter-agent messages — that is Phase 5.

### D5 — PyPI / GHCR publish: NOT until Phase 6

**Decision.** Do **not** publish to PyPI or GHCR until Phase 6 lands
(SBOM + cosign + Rekor attestation + smoke-tested image). Develop via
`pip install -e ".[dev]"` throughout. The first public release is a
**signed, SBOM-attested, cosign-signed, Rekor-anchored `v1.0.0`**.

**Reasoning.**
- Publishing the current `0.2.0` would bake the substring-Judge bug
  into a public release — the exact supply-chain risk this tool exists
  to find in its targets. A security tool must practice what it
  preaches; the IETF agent-auth draft explicitly calls static API keys
  an antipattern and the OWASP ASI04 supply-chain coverage that
  NeuralStrike will itself test demands SLSA-aligned practice.
- The Phase 0 oracle rewrite changes verdict semantics. A 0.2.0
  published now would have verdicts that a reviewer cannot trust —
  the worst possible state for a public red-team tool.
- The standard pattern for security tooling is: develop against a
  local editable install, publish a signed release once the hardening
  is done. PyRIT, garak, AgentEval all follow this; the signed release
  is the artifact.
- `v1.0.0` (not `0.3.0`) signals the production bar and matches the
  Definition of Done. Anything earlier is a dev tag, not a release.

### Cross-cutting: the latent `llama3.1` default bug

D1 surfaces a real defect: `config.py` and `.env.example` default the
Judge to `llama3.1`, which is not installed on this host. This is a
fail-open bug — a fresh-clone run silently uses a missing model and
the Judge call hangs/errors instead of failing closed with a clear
message. **Phase 0 must fix this** as part of D1: change the default,
add a startup reachability check, and add `--judge-model-list`. This
is recorded as gap A7-adjacent (replayability/liveness) and is a
Phase 0 exit-gate requirement, not a deferrable item.

---

*Living document. Update the gap inventory, score trajectory, and
decisions as phases land. The exit gates, not the prose, are the
contract.*