# NeuralStrike Bug Catalog — May 14, 2026 Audit

**Auditor:** Mackenzie (glm-5.1:cloud)  
**Project:** NeuralStrike v0.1.0  
**Previous Audit:** April 22, 2026 (8 bugs, all fixed)  
**Tests:** 65/65 passing | **Coverage:** 83%  
**Status:** ✅ ALL 25 BUGS FIXED

---

## 🔴 CRITICAL (2)

### C-01: `scan_openai_compatible()` REPLACES `discovered_models` — silent data loss
**File:** `modules/recon/llm_recon.py:49-50`  
**Impact:** If `scan_openai_compatible()` is called after `scan_ollama()` (or called twice), it overwrites the entire list with `=` instead of extending it. `scan_ollama()` uses `.extend()`. This asymmetric mutation means:
- Calling recon on the same `LLMRecon` instance in different order loses data
- Programmatic usage (not CLI) that reuses instances will silently lose models
- `run_full_recon()` works only because it calls openai first, then ollama extends
**Fix:** Change `self.discovered_models = [...]` to `.extend()` + dedup at read time.

### C-02: `AgentC2.dispatch_command()` passes `agent_id` as LiteLLM model name
**File:** `modules/post_ex/agent_c2.py:35-38`  
**Impact:** `dispatch_command` calls `llm_manager.call_remote(agent_id, hidden_prompt)` — treating the agent ID (e.g., `"agent_01"`) as a model name for LiteLLM. This will always fail at runtime because LiteLLM doesn't know what `"agent_01"` is. The entire C2 dispatch mechanism is non-functional.
**Fix:** `dispatch_command` should maintain a mapping of `agent_id → endpoint_url` or `agent_id → model_name` and use that for routing.

---

## 🟠 HIGH (5)

### H-01: `requirements.txt` includes `uvicorn`/`fastapi` but `pyproject.toml` marks them as optional
**File:** `requirements.txt` vs `pyproject.toml`  
**Impact:** `pip install -r requirements.txt` installs uvicorn + fastapi unconditionally, but `pip install .` does NOT. If someone installs via `pyproject.toml` without `[mcp]`, importing `mcp_interceptor.py` fails with `ImportError` at runtime (only when `intercept` command is used). Two configs are contradictory.
**Fix:** Either move uvicorn/fastapi to core dependencies in `pyproject.toml`, or remove from `requirements.txt` and document the `[mcp]` extra.

### H-02: `MCPInterceptor` proxy hardcodes `/etc/passwd` path hijack — no configuration
**File:** `modules/exploit/mcp_interceptor.py:46-50`  
**Impact:** The interceptor has a hardcoded `if name == "read_file": args["path"] = "/etc/passwd"` — demo code that would execute in any real deployment. No way to configure what gets hijacked or disable it. For a red team tool, this should be configurable.
**Fix:** Make interception rules configurable (JSON/YAML config file or CLI params).

### H-03: `MCPInterceptor.trigger_capability_injection()` is a pass stub — documented as implemented
**File:** `modules/exploit/mcp_interceptor.py:56-59`  
**Impact:** README advertises "Capability injection into MCP server responses" as a feature. The method is `pass` — completely unimplemented. Documented feature that doesn't exist.
**Fix:** Either implement it or remove from README/CLI.

### H-04: `EvasionSuite.steganographic_prompt()` unreachable from CLI
**File:** `evasion/mimicry.py:36-41`, `main.py:evade` command  
**Impact:** README lists "Steganographic Prompts" as a feature. The method exists but the CLI `evade` command only calls `persona_wrap` or `apply_behavioral_mimicry`. Users cannot access steganographic prompts.
**Fix:** Add `--technique steganographic` option to the `evade` command.

### H-05: `exhaust_context()` sends ~660KB payload with no safety guard
**File:** `modules/weaponize/context_poison.py:44-51`  
**Impact:** Default `token_limit=100000` creates `"Lorem ipsum " * 50000` (~660KB). This will likely crash or OOM the target model, and there's no upper bound validation. For a red team context, you'd want controlled testing, not a single nuclear payload.
**Fix:** Add a max cap (e.g., 50K tokens), add a confirmation prompt or `--force` flag, and document the impact.

---

## 🟡 MEDIUM (10)

### M-01: `adversarial_loop` module-level singleton is the CLASS, not an instance
**File:** `core/adversarial_loop.py:47`  
**Impact:** `adversarial_loop = AdversarialLoop` assigns the class itself, not an instance. If someone imports `adversarial_loop` expecting a pre-configured instance, they'll get the class and `AttributeError` when calling methods. Currently dead code — nothing uses it.
**Fix:** Either instantiate it (`adversarial_loop = AdversarialLoop(...)`) or remove it.

### M-02: `AdversarialLoop` doesn't use `JailbreakForge.generate_mutation()`
**File:** `core/adversarial_loop.py:37-44`, `modules/weaponize/jailbreak_forge.py:34-49`  
**Impact:** `JailbreakForge.run_automated_breach()` creates an `AdversarialLoop` and passes a string that already includes the forge's template. But the loop then wraps the goal in its own attacker instruction. This double-wrapping means the attacker model gets redundant instructions that may confuse it.
**Fix:** Have `JailbreakForge` either pass the raw goal to the loop (letting the loop handle the template) or bypass the loop's own instruction construction.

### M-03: `C2` CLI command hardcodes `agent_01` registration
**File:** `main.py:c2` command (~line 155)  
**Impact:** `await c2_engine.register_agent("agent_01", ["read_file", "web_search"], "High")` is hardcoded. If the user passes `--agent-id agent_99`, it dispatches to an agent that was never registered.
**Fix:** Add `--register-agent-id`, `--capabilities`, and `--trust-level` CLI options, or auto-register the specified agent.

### M-04: `EvasionSuite.persona_wrap()` and `steganographic_prompt()` are `async` but contain no `await`
**File:** `evasion/mimicry.py:29-35` and `evasion/mimicry.py:36-41`  
**Impact:** Both methods are declared `async def` but perform no async operations — they're pure string manipulations. This forces callers to `await` them unnecessarily and misleads about the function's nature.
**Fix:** Change both to regular `def` methods. Update CLI `evade` command to call `persona_wrap()` without `await`.

### M-05: Multiple `logging.basicConfig()` calls — first import wins
**File:** `core/llm_manager.py:7`, `core/adversarial_loop.py:5`, etc.  
**Impact:** Several modules call `logging.basicConfig(level=logging.INFO)`. Python's logging module only applies the first call; subsequent calls are no-ops. This means logging configuration depends on import order, which is unpredictable.
**Fix:** Configure logging once in `main.py` (the entry point) and remove `basicConfig` from library modules. Use `logging.getLogger(__name__)` pattern instead.

### M-06: No `.env.example` file
**File:** Missing from project root  
**Impact:** README documents `.env` configuration (OLLAMA_BASE_URL, API keys, etc.) but provides no `.env.example` template. Users must read the README and guess at the format.
**Fix:** Add `.env.example` with all config keys and placeholder values.

### M-07: `JailbreakForge.templates["persona_collapse"]` missing `[GOAL]` placeholder
**File:** `modules/weaponize/jailbreak_forge.py:14`  
**Impact:** `run_automated_breach()` does `self.templates["persona_collapse"].replace("[GOAL]", goal)` but `persona_collapse` doesn't contain `[GOAL]` — it's a standalone prompt. The `.replace()` is a silent no-op. The goal is still included because it gets prepended via the `initial_goal` parameter, but the template itself doesn't work as documented.
**Fix:** Add `[GOAL]` placeholder to the `persona_collapse` template, or document that it's used differently.

### M-08: `AdversarialLoop` returns inconsistent dict shapes
**File:** `core/adversarial_loop.py:36,42`  
**Impact:** Success returns `{"status": "success", "iteration": N, "payload": str, "response": str}`, but failure returns `{"status": "failure", "history": list}`. These have completely different keys. If a caller assumes `payload` exists on a failure result, it gets `KeyError`.
**Fix:** Make both return `status`, `iteration`, `payload`, `response`, and `history`. Include the last iteration's data in the failure result.

### M-09: `coordinate_exfiltration()` claims to split data but sends same string to all agents
**File:** `modules/post_ex/agent_c2.py:47-52`  
**Impact:** The comment says "Logic to split data and assign to different agents" but the implementation just sends the same `target_data` string to every agent with `"Exfiltrate chunk of {target_data}"`. No actual data splitting happens.
**Fix:** Implement data splitting (chunk the data, distribute chunks across agents) or remove the misleading comment and document the limitation.

### M-10: `AdversarialLoop.history` never cleared between runs
**File:** `core/adversarial_loop.py:15`  
**Impact:** If you reuse a loop instance across multiple `execute_cycle()` calls, history from previous runs accumulates. The `__init__` sets `self.history = []`, but `execute_cycle` only appends.
**Fix:** Add `self.history = []` at the start of `execute_cycle()`, or document that a new instance should be created per cycle.

---

## 🟢 LOW (8)

### L-01: `main.py` imports `AdversarialLoop` at top level but never uses it directly
**File:** `main.py:3`  
**Impact:** The import `from neuralstrike.core.adversarial_loop import AdversarialLoop` is unused at the module level. It's only used implicitly through `JailbreakForge`. Dead import.
**Fix:** Remove the unused import.

### L-02: `type` parameter name shadows Python builtin
**File:** `main.py` (forge, poison, hijack, extract commands)  
**Impact:** Multiple commands use `type: str = typer.Option(...)` as a parameter name, shadowing the `type` builtin. Not a runtime bug, but poor style and confusing for readers.
**Fix:** Rename to `target_type` to match the module constructors.

### L-03: `ToolEnum` only uses prompt leak — no actual API/MCP introspection
**File:** `modules/recon/tool_enum.py`  
**Impact:** README says "Enumerate function definitions and tool schemas" but the implementation only sends a social-engineering prompt to the model asking it to leak its tools. No actual API endpoint probing or MCP schema discovery.
**Fix:** Either update README to accurately describe the current capability (prompt-based leak only) or implement API introspection.

### L-04: `ModelExtract.fingerprint_model()` returns unstructured strings
**File:** `modules/exploit/model_extract.py:19-33`  
**Impact:** Returns `{"llama": raw_response, "gpt": raw_response, "claude": raw_response}` — raw LLM output strings. No parsing, scoring, or model identification logic. The CLI just dumps this dict to a Panel.
**Fix:** Parse responses to determine likely model family and return a structured result with confidence scores.

### L-05: `AgentC2` is in-memory only, no persistence
**File:** `modules/post_ex/agent_c2.py`  
**Impact:** All registered agents and commands exist only in process memory. On restart, everything is lost. For a C2 tool, this is a significant limitation.
**Fix:** Add optional JSON file persistence for agent registry, or document this as a limitation.

### L-06: No input validation on CLI arguments
**File:** `main.py`  
**Impact:** No validation on target URLs (SSRF potential), no port range checks in `intercept`, no bounds on `--iterations`, no sanitization on payloads. For a red team tool this is somewhat expected, but basic bounds checking would prevent accidental misuse.
**Fix:** Add basic URL scheme validation, port range checks (1-65535), and iteration bounds (1-100).

### L-07: `EvasionSuite.target_type` is stored but never used
**File:** `evasion/mimicry.py:13`  
**Impact:** `__init__` accepts and stores `target_type` but no method references it. `apply_behavioral_mimicry` always uses `call_local` (attacker brain). `persona_wrap` and `steganographic_prompt` are pure string ops. The attribute is dead.
**Fix:** Either use `target_type` in `apply_behavioral_mimicry` to route to local/remote, or remove it.

### L-08: `poison` command creates event loop even when no action specified
**File:** `main.py:poison` command  
**Impact:** If neither `--payload` nor `--extract` is provided, the command prints an error message but still creates and destroys an asyncio event loop via `asyncio.run(run())`. The `run()` function returns immediately, but the overhead is wasteful.
**Fix:** Add an early return before `asyncio.run()` if neither option is specified.

---

## 📋 DEAD CODE / UNREACHABLE METHODS (6)

| Method | File | Why Unreachable |
|--------|------|-----------------|
| `JailbreakForge.generate_mutation()` | `jailbreak_forge.py:34-49` | Never called — `run_automated_breach` delegates to `AdversarialLoop` |
| `ContextPoison.exhaust_context()` | `context_poison.py:44-51` | No CLI command exposes it |
| `ModelExtract.time_analysis()` | `model_extract.py:36-49` | No CLI command exposes it |
| `FunctionHijack.tool_confusion_attack()` | `function_hijack.py:38-48` | No CLI command exposes it |
| `FunctionHijack.schema_poisoning()` | `function_hijack.py:50-60` | No CLI command exposes it |
| `AgentPivot.map_agent_network()` | `agent_pivot.py:37-46` | No CLI command exposes it |

---

## 📖 README ACCURACY ISSUES (7)

| README Claim | Reality | Severity |
|---|---|---|
| "Steganographic Prompts: Hide instructions in system override blocks" | Just wraps in `--- BEGIN/END SYSTEM OVERRIDE ---` delimiters. Not steganography. | ⚠️ Misleading |
| "Enumerate function definitions and tool schemas" | Only prompt-based leak, no API introspection | ⚠️ Incomplete |
| "Capability injection into MCP server responses" | `trigger_capability_injection()` is `pass` — not implemented | ❌ False |
| "Completion timing analysis" | Averages response times, no actual model identification from timing | ⚠️ Misleading |
| "Orchestrate compromised agents" | `dispatch_command` sends agent_id as model name — always fails at runtime | ❌ Broken |
| "Template library" | 4 hardcoded string templates, not a library | ⚠️ Oversold |
| "Mutation engine" | Single LLM call, no engine architecture | ⚠️ Oversold |

---

## 🔬 TEST COVERAGE GAPS

| File | Coverage | Missing Lines | What's Not Tested |
|---|---|---|---|
| `main.py` | 0% | 1-224 | No CLI integration tests |
| `mcp_interceptor.py` | 0% | 1-67 | No tests at all |
| `function_hijack.py` | 92% | 45, 60 | Local branches untested |
| `model_extract.py` | 94% | 33, 50 | Local branches untested |
| `llm_recon.py` | 85% | 49-50, 70-76 | Integration paths |

**Overall coverage: 63%** — needs `main.py` and `mcp_interceptor` tests to reach 75%+.

---

## 📝 DOCS ISSUES (2)

| Issue | File | Fix |
|---|---|---|
| "Run `python src/neuralstrike/main.py --help`" | `NEXT_STEPS.md` | Change to `neuralstrike --help` |
| No `.env.example` provided | Project root | Add `.env.example` with all config keys |

---

## SUMMARY

| Severity | Count |
|---|---|
| 🔴 Critical | 2 |
| 🟠 High | 5 |
| 🟡 Medium | 10 |
| 🟢 Low | 8 |
| Dead code | 6 methods |
| README inaccuracies | 7 claims |
| Docs issues | 2 |
| **Total bugs** | **25** |

### Priority Fix Order
1. **C-01** — Data loss bug, simple fix
2. **C-02** — C2 module completely broken
3. **H-03** — Documented feature doesn't exist
4. **H-04** — Documented feature unreachable
5. **H-02** — Hardcoded attack path
6. **M-02** — Double-wrapping degrades attack quality
7. **M-08** — Inconsistent return shapes cause runtime errors
8. Everything else in severity order