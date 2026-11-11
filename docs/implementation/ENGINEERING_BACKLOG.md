# Engineering backlog — what is left after the 2026-11-11 master-plan audit

Status: **not a release plan.** Nothing in this file moves Phase 3 gates P3-1…P3-5 or Phase 4
gate P4-6. Those need people and customers, and no amount of engineering substitutes for them.
This is the engineering that *is* left — written down after an independent audit of the repo
against `NEURALSTRIKE_MASTER_PLAN.md`, because most of it was invisible from the gate tables.

Ordered by what it protects, not by size. Every item names the test or artefact that would
close it, so "done" cannot be a feeling.

## State after the 2026-11-12 sprint

| State | Item |
|---|---|
| **CLOSED** | E-1, E-2, E-3, E-4, E-5, E-7, E-8, E-9, E-11, E-12 |
| **BLOCKED** | E-6 (needs approval to install `garak` and PyRIT into an isolated env), E-10 (needs approval to dispatch `.github/workflows/release.yml`, and a push first — the workflow on `origin/main` is still `a2e3b6a`) |

Two items are *not* closed and cannot be closed by engineering. They stay exactly where the
audit put them, and the gate documents still say so: Phase 3 is **NOT ACCEPTED**, Phase 4 is
**NOT RELEASED** with P4-2 `PARTIAL` on purpose (no dispatched release exists).

## A. Integrity — fix before this is shown to anyone

| ID | Item | Why it matters | Done when | State |
|---|---|---|---|---|
| E-1 | `pyproject.toml` classifier is `Development Status :: 5 - Production/Stable` while every gate document says **NOT RELEASED** / **NOT ACCEPTED** | The classifier ships on the package page and inside the wheel. A buyer reads it first and the honesty lives three clicks deeper | Classifier is `4 - Beta` (or narrower), and a contract fails if the classifier claims a stability the Phase 4 status line contradicts | **CLOSED** — `df7701c`, `tests/test_release_stability.py`. Classifier `4 - Beta`; the contract was run red against the unfixed classifier first |
| E-2 | `docs/SUPPORT_MATRIX.md` classifies the four accepted profiles and says nothing about the 15 legacy offensive commands | The one document that exists to prevent "it must work, it isn't excluded" is silent on the largest part of the CLI | A section that names every legacy command and states, per command, that it carries no acceptance claim and what it is (local simulation / informational / experimental) | **CLOSED** — `df7701c`, `tests/test_support_matrix.py`. The contract also found 8 further traffic-sending commands the matrix never named; they are now classified under Experimental |
| E-3 | 15 of 40 commands enforce neither a scope file nor the HITL gate: `forge`, `poison`, `exhaust`, `recon`, `hijack`, `confuse`, `schema-poison`, `intercept`, `pivot`, `map-network`, `extract`, `timing`, `c2`, `evade`, `neuralguard-bench` | `scan`, `assess`, `doctor`, `pack`, `adaptive`, `mcp-*-scan`, `a2a-scan`, `minja`, `rag-poison`, `exec-context` all do. A binary whose offensiveness depends on which subcommand you picked is not a control | One declared table (command → sends-traffic? gate?) in the package; every registered command appears exactly once; every traffic-sending command calls `_apply_scope`/`_apply_safety`; a contract fails on an unclassified new command. `README.md` §"Safety & utilities" stops implying the gate is global | **CLOSED** — `df7701c`, `tests/test_command_surface.py` + `src/neuralstrike/safety/surface.py`. **Counts corrected:** the audit's "13 of 40" does not match the code — measured on the 42 registered names, 11 enforced both gates, 3 scope only, 1 HITL only, and 27 neither (15 of which send traffic) |
| E-4 | README Quickstart step 3 is `neuralstrike forge` — an ungated legacy command — while the accepted path (`assess`) is step 4 | The first thing a new reader is told to run is outside every acceptance claim | Quickstart opens with `doctor` → `assess`; the legacy catalogue is one headed section with an explicit "no acceptance claim, no scope gate unless you pass one" warning | **CLOSED** — `df7701c`, `tests/test_quickstart.py` |
| E-5 | `--out report.json` writes `report.json.json` (extension appended unconditionally) | Small, but it is the first command in the offline example and it looks broken | Extension appended only when absent; contract over `smoke`, `assess`, `replay` | **CLOSED** — `df7701c`, `tests/test_report_destination.py`. Reproduced before the fix (`e5-red-extension.txt` in the sprint record) |

## B. Measurement — engineering that strengthens Phase 3 without closing it

| ID | Item | Why it matters | Done when | State |
|---|---|---|---|---|
| E-6 | A real **tool-vs-tool** comparator was never built. The one comparator run varies the *attacker* (PyRIT as generator) and keeps our measurement; garak was named by the master plan and never run | The plan asks to "compare common workflows with PyRIT/garak on the same targets, budgets and ground truth; publish both weaknesses and advantages". Today there is no score, only an attacker cross-check | A declared comparator plan for the tool axis (not the attacker axis), executed once, with unsupported rows reported as unsupported — and the result published even if it flatters PyRIT or garak | **BLOCKED** — plan closed at `d247df3` (`docs/implementation/TOOL_AXIS_COMPARATOR_PLAN.md`, `tests/test_tool_axis_plan.py`). Execution needs: (1) approval to install `garak` and PyRIT 1.1.0 into an isolated scratch virtualenv, (2) `examples/tool_axis_compare/` adapters + scorer, (3) one local-inference session. Until then the plan declares its own rows `unsupported` where a tool cannot express the question |
| E-7 | The declared write-first matrix has one seed. A second seed is permitted **only** under its own pre-registered plan | One seed cannot distinguish model behaviour from a seed artifact | A second declared plan, run, and recorded as a replication or a null | **CLOSED** — `d247df3`, `tests/test_tau_bench.py`. Pre-declared seed 11, own plan kind, 12/12 observations, exit 3; **all four verdicts identical to seed 7** — a null, recorded as one. Packet under the durable root |
| E-8 | Phase 3 residue that is genuinely measurement: the destructive class is measured-not-reproduced, and persistent-memory influence stands at one 2/3 in one stage | Named as `PARTIAL` since 8 Nov; the gap is evidence, not code | Either a reproduced destructive effect on an app this project did not author, or the residue is restated as a permanent limit of the declared profiles | **CLOSED as a stated limit** — `d247df3`, `tests/test_phase3_residue_limits.py`, `PHASE3_EFFICACY.md` §Two permanent limits. No profile has a destructive tool with external ground truth; the memory persistent effect is falsified and the surviving contamination is a k=3 count. P3-6 stays `PARTIAL` |
| E-9 | Evidence durability: one replication packet and one capability probe live only in `/tmp`, and the record already lost `/tmp` evidence once | `/tmp` evaporates; a reviewer cannot open what is gone | Packets under the declared durable root (`~/Documents/Codex/2026-11-08/neuralstrike-phase3`), plus a contract that no evidence path recorded in a document points at `/tmp` | **CLOSED** — `dd24967`, `tests/test_evidence_paths.py`. The root is declared in `EVIDENCE.md`, 13 stale `/tmp` citations became tombstones, and the contract also asserts every durable path a document cites exists. **Both lost artefacts are recorded, not recovered** — they cannot be |

## C. Release path — configuration, one code check, one decision

| ID | Item | Why it matters | Done when | State |
|---|---|---|---|---|
| E-10 | The release workflow has never been dispatched, not even with `publish: false`; `PYPI_API_TOKEN` does not exist on the repository (zero secrets configured) | P4-2 is `PARTIAL` for exactly this. A decision was assumed to be one click; it is not, and nobody knows what else is missing | One non-publishing dispatch recorded, and its output reviewed — then the release decision is taken on evidence rather than on hope | **BLOCKED** — needs the owner's approval to dispatch `.github/workflows/release.yml`, and a push first: a dispatch runs the workflow definition on the default branch, which is still `a2e3b6a`. Reading the workflow without running it surfaced two candidate defects, recorded in `PHASE4_PLAN.md` §P4-2 variants as **unconfirmed** — a multi-platform `push: false` buildx combination, and `python -m build` running from the repo root |
| E-11 | The decision itself: release to GitHub + GHCR only, or also PyPI (which needs an account and token) | The gate criterion names version/tag/commit/wheel/image/SBOM/provenance — not PyPI. Choosing the narrower release closes P4-2 without inventing a distribution channel | The chosen scope is written into `PHASE4_PLAN.md` §P4-2 before the dispatch, and the dispatch is recorded after | **CLOSED as written-not-decided** — `d247df3`, `tests/test_phase4_plan.py`. Both variants and their prerequisites are in §P4-2 variants; no decision is taken, nothing is published, and P4-2 stays `PARTIAL` |

## D. Environment — the cost of two red CI runs on 2026-11-11

| ID | Item | Why it matters | Done when | State |
|---|---|---|---|---|
| E-12 | Local `.venv` and CI resolve different versions from the same unbounded range (`typer>=0.12` gave 0.29.0 locally, 0.28.0 in CI) | A suite that passes locally failed CI twice, on a test that was correct in substance. `requirements.txt` is hash-pinned but the `.[dev,mcp]` install path is not | Either a lock for the dev extra, or a `make dev-env` / script that installs exactly what CI installs, referenced from the contributor section | **CLOSED** — `df7701c`, `tests/test_dev_environment.py`. `typer==0.28.0` pinned; `scripts/dev_env.sh` installs the hash-pinned dev lock and refuses a non-3.12 interpreter; both gating CI jobs now execute one `scripts/ci_gate.sh`, and the contract fails if a workflow inlines a gate tool again. The 3.11/3.14 matrix job stays unbounded **on purpose** and its step name says so — it is the compatibility probe, not the gate |

## Explicitly not in this backlog

No new attack payloads, no scenario rows for taxonomy coverage, no C2/exploit expansion, no TAP
tree search, no autonomous campaigns, no fingerprinting growth, no compliance certification
claims, no hosted multi-tenancy, no billing, no distributed workers, no mobile UI, no mandatory
Scarlet/NeuralGuard dependency. The master plan lists each as a non-goal until pilots succeed,
and adding any of them now would be the failure mode the plan was written to prevent.

## What is not engineering at all

Phase 3 gates P3-1…P3-5 (independent labels, a named reviewer, a consenting pilot, a
willingness-to-pay signal, corroborated ground truth) and Phase 4 gate P4-6 (three pilot teams).
They are open because no second person has ever looked at this work. They stay open until one
does.
