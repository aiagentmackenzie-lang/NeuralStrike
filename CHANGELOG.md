# Changelog

All notable changes to NeuralStrike are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — 2026-06-20

Production-grade rewrite. The framework now does what its documentation claims,
fails loudly when a backend is unreachable, and passes a real CI quality gate.

### Added
- Genuinely asynchronous LLM calls (`ollama.AsyncClient`, `litellm.acompletion`).
- Fail-closed error contract: `LLMError` raised on backend failure instead of
  silently returning error strings into the adversarial loop.
- Typed exceptions (`LLMError`, `ConfigError`, `ValidationError`).
- Injectable attacker step in `AdversarialLoop` (`attacker_fn`).
- `JailbreakForge` template library + Attacker-driven mutation wired into the
  live loop (iteration 1 seeded from a template, later iterations mutated).
- `AgentC2` JSON-persistent registry (`~/.neuralstrike/agents.json`),
  `register`/`deregister`/`list`/`coordinate-exfiltration` with real data splitting.
- `MCPInterceptor` capability injection into `tools/list` responses, `/__inject`
  endpoint, loopback-only bind by default, configurable `bind_host`,
  `build_app()` for testability.
- CLI subcommands for previously-unreachable methods: `exhaust`, `confuse`,
  `schema-poison`, `map-network`, `timing`.
- CLI `--target-type` on `recon`/`pivot`/`evade`; `c2 --register` (repeatable),
  `--capabilities`, `--trust-level`, `--list-agents`, `--deregister`,
  `--registry-file`; `pivot --target-model`; `intercept --bind-host`,
  `--inject-tool`, `--inject-schema`; `--version`.
- Input validation (URL scheme, port range, iteration bounds, model names).
- Log redaction filter for credential-shaped strings.
- `py.typed` marker, `__version__`, env prefix `NEURALSTRIKE_`.
- CI workflow (ruff + mypy + pytest --cov, floor 80%) on Python 3.10/3.12/3.14.
- `Dockerfile`, `docker-compose.yml`, `SECURITY.md`.

### Changed
- `AgentPivot` routes LLM calls through `target_model`, not the framework name.
- README rewritten with ✅/⚠️/❌ status triples and honest module limitations.
- Dependencies single-sourced in `pyproject.toml`; `requirements.txt` removed.

### Fixed
- `call_local`/`call_remote` were fake-async (sync SDK calls blocking the loop).
- Errors were swallowed and fed back into the loop as fake "responses".
- `evade --technique persona --sample` ran mimicry instead of persona.
- `scan_ollama` could inject `None` into `discovered_models`.
- `MCPInterceptor` bound to `0.0.0.0` (open proxy) by default.
- `trigger_capability_injection` was queued but never applied.
- Dead module-level `adversarial_loop` singleton; unused `EvasionSuite.target_type`.

### Removed
- Tracked build artifacts (`src/neuralstrike.egg-info/`).
- Empty placeholder `config/` and `docs/` directories.
- `requirements.txt` (single-sourced to `pyproject.toml`).
- `BUG_CATALOG.md`, `NEXT_STEPS.md` (superseded by this changelog and the audit).

## [0.1.0] — 2026-04-08

Initial release: adversarial loop, recon/weaponize/exploit/post-ex/evasion modules.