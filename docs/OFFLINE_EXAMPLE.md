# Offline example — no model, no network

The fastest honest look at the tool: a bundled fixture corpus, a deterministic run, and a report
you can read. No Ollama, no API key, no external request. Verified on `41670a7` on macOS arm64,
Python 3.12.14.

## Run it

```sh
neuralstrike smoke --out smoke
```

Observed output (⚠️ local observation, not a CI artifact):

```
NeuralStrike smoke: bundled fixture corpus scan...
run run-98d32bec071843859a39e0e784884387 complete: ASR=0.0% (CI 0.0%-79.3%) coverage=100.0% ...
run run-9de3cc5af45e404889c61a9a8f06c706 complete: ASR=100.0% (CI 20.7%-100.0%) coverage=100.0% ...
run run-d3ac9f7311bb4764baa4410157222000 complete: ASR=0.0% (CI 0.0%-79.3%) coverage=100.0% ...
Smoke passed — 3 scenarios, 3 trials, ASR 33.3%, coverage 100.0% → smoke.json
```

The artifact is written mode 0600 and carries `schema_version`, `adapter: langgraph`,
`target: bundled-vulnerable-fixture`, per-scenario trials and the report body. `--format sarif`
produces the same run as SARIF instead.

Exit is non-zero if the fixture report cannot be produced or is structurally malformed, so this
doubles as a wiring check — which is why CI runs it on every push from a fresh clone.

## What it demonstrates, and what it does not

It demonstrates: corpus loading, a real LangGraph trial against a bundled **vulnerable** fixture,
oracle scoring, uncertainty intervals, and report generation.

It does **not** demonstrate anything about your system. ASR 33.3 % here is three fixture
scenarios, one trial each, on a graph shipped in this repository for exactly this purpose. It is
not an efficacy result, not a comparator score, and not a pilot.

## Next, still offline

```sh
neuralstrike replay runs/<bundle> --verify-oracles    # byte-verify and re-score recorded evidence
neuralstrike rescore <assessment>                     # new oracle version, source bytes preserved
```

Replay proves the recorded evidence is intact and deterministic; it never re-runs the target. If
you want to see the whole cycle with an actual model, that requires a local target and is a
different, declared run — see the profile documents under `docs/implementation/`.
