# NeuralStrike: Post-Launch Execution Roadmap

This document outlines the strategic next steps for evolving NeuralStrike from a functional framework into a battle-hardened adversarial AI toolkit.

## 🚩 Phase 1: The "Live Fire" Test Bed (Immediate Priority)
Before scaling, we must validate the a-to-z attack chain in a controlled environment.
- [ ] **Deploy Target:** Create a "Vulnerable Agent" using Ollama/CrewAI with a specific tool (e.g., `read_file` or `web_search`).
- [ ] **Full-Chain Validation:** Execute a complete sequence: `recon` $\rightarrow$ `forge` $\rightarrow$ `hijack` $\rightarrow$ `pivot`.
- [ ] **Metric Baseline:** Document the "Time-to-Breach" and "Success Rate" for the current Attacker/Judge models.

## 🧠 Phase 2: Adversarial Brain Optimization
Enhancing the local "brains" to increase breach probability.
- [ ] **Attacker Specialization:** Develop a custom `.Modelfile` for Ollama to create a "NeuralStrike-Attacker" model optimized for mutation and bypass.
- [ ] **Judge Refinement:** Implement a multi-criteria scoring system for the Judge (e.g., grading a response on *Intent*, *Completeness*, and *Bypass Quality*).
- [ ] **Multi-Turn Planning:** Implement "Priming" logic where the framework sends a series of preparatory prompts before the final payload.

## 🛠️ Phase 3: Protocol & Tool Expansion
Moving from prompt-injection to protocol-level exploitation.
- [ ] **Advanced MCP Interception:** Integrate `mitmproxy` for transparent, low-level interception of Model Context Protocol traffic.
- [ ] **Automated Payload Injection:** Create a library of "Automatic Rewrites" that the interceptor applies whenever specific tool calls (e.g., `exec_shell`) are detected.
- [ ] **Expanded Template Library:** Integrate a wider array of adversarial patterns including latest findings from the research community.

## 🛡️ Phase 4: Evasion & Stealth
Bypassing the next generation of AI safety monitors.
- [ ] **Behavioral Mirroring:** Improve the `EvasionSuite` to analyze deeper target patterns (frequency of terminology, response length) for better mimicry.
- [ ] **Steganographic Prompts:** Implement "Invisible" character injections and token-level obfuscation to bypass string-based safety filters.

---

**Quick Start for Return:**
Run `python src/neuralstrike/main.py --help` to see all implemented commands.
Start with `recon` to map your target, then `forge` to break it.
