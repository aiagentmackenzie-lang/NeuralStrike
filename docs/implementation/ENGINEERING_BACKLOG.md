# Engineering backlog — what is left after the 2026-11-11 master-plan audit

Status: **not a release plan.** Nothing in this file moves Phase 3 gates P3-1…P3-5 or Phase 4
gate P4-6. Those need people and customers, and no amount of engineering substitutes for them.
This is the engineering that *is* left — written down after an independent audit of the repo
against `NEURALSTRIKE_MASTER_PLAN.md`, because most of it was invisible from the gate tables.

Ordered by what it protects, not by size. Every item names the test or artefact that would
close it, so "done" cannot be a feeling.

## A. Integrity — fix before this is shown to anyone

| ID | Item | Why it matters | Done when |
|---|---|---|---|
| E-1 | `pyproject.toml` classifier is `Development Status :: 5 - Production/Stable` while every gate document says **NOT RELEASED** / **NOT ACCEPTED** | The classifier ships on the package page and inside the wheel. A buyer reads it first and the honesty lives three clicks deeper | Classifier is `4 - Beta` (or narrower), and a contract fails if the classifier claims a stability the Phase 4 status line contradicts |
| E-2 | `docs/SUPPORT_MATRIX.md` classifies the four accepted profiles and says nothing about the 15 legacy offensive commands | The one document that exists to prevent "it must work, it isn't excluded" is silent on the largest part of the CLI | A section that names every legacy command and states, per command, that it carries no acceptance claim and what it is (local simulation / informational / experimental) |
| E-3 | 15 of 40 commands enforce neither a scope file nor the HITL gate: `forge`, `poison`, `exhaust`, `recon`, `hijack`, `confuse`, `schema-poison`, `intercept`, `pivot`, `map-network`, `extract`, `timing`, `c2`, `evade`, `neuralguard-bench` | `scan`, `assess`, `doctor`, `pack`, `adaptive`, `mcp-*-scan`, `a2a-scan`, `minja`, `rag-poison`, `exec-context` all do. A binary whose offensiveness depends on which subcommand you picked is not a control | One declared table (command → sends-traffic? gate?) in the package; every registered command appears exactly once; every traffic-sending command calls `_apply_scope`/`_apply_safety`; a contract fails on an unclassified new command. `README.md` §"Safety & utilities" stops implying the gate is global |
| E-4 | README Quickstart step 3 is `neuralstrike forge` — an ungated legacy command — while the accepted path (`assess`) is step 4 | The first thing a new reader is told to run is outside every acceptance claim | Quickstart opens with `doctor` → `assess`; the legacy catalogue is one headed section with an explicit "no acceptance claim, no scope gate unless you pass one" warning |
| E-5 | `--out report.json` writes `report.json.json` (extension appended unconditionally) | Small, but it is the first command in the offline example and it looks broken | Extension appended only when absent; contract over `smoke`, `assess`, `replay` |

## B. Measurement — engineering that strengthens Phase 3 without closing it

| ID | Item | Why it matters | Done when |
|---|---|---|---|
| E-6 | A real **tool-vs-tool** comparator was never built. The one comparator run varies the *attacker* (PyRIT as generator) and keeps our measurement; garak was named by the master plan and never run | The plan asks to "compare common workflows with PyRIT/garak on the same targets, budgets and ground truth; publish both weaknesses and advantages". Today there is no score, only an attacker cross-check | A declared comparator plan for the tool axis (not the attacker axis), executed once, with unsupported rows reported as unsupported — and the result published even if it flatters PyRIT or garak |
| E-7 | The declared write-first matrix has one seed. A second seed is permitted **only** under its own pre-registered plan | One seed cannot distinguish model behaviour from a seed artifact | A second declared plan, run, and recorded as a replication or a null |
| E-8 | Phase 3 residue that is genuinely measurement: the destructive class is measured-not-reproduced, and persistent-memory influence stands at one 2/3 in one stage | Named as `PARTIAL` since 8 Nov; the gap is evidence, not code | Either a reproduced destructive effect on an app this project did not author, or the residue is restated as a permanent limit of the declared profiles |
| E-9 | Evidence durability: one replication packet and one capability probe live only in `/tmp`, and the record already lost `/tmp` evidence once | `/tmp` evaporates; a reviewer cannot open what is gone | Packets under the declared durable root (`~/Documents/Codex/2026-11-08/neuralstrike-phase3`), plus a contract that no evidence path recorded in a document points at `/tmp` |

## C. Release path — configuration, one code check, one decision

| ID | Item | Why it matters | Done when |
|---|---|---|---|
| E-10 | The release workflow has never been dispatched, not even with `publish: false`; `PYPI_API_TOKEN` does not exist on the repository (zero secrets configured) | P4-2 is `PARTIAL` for exactly this. A decision was assumed to be one click; it is not, and nobody knows what else is missing | One non-publishing dispatch recorded, and its output reviewed — then the release decision is taken on evidence rather than on hope |
| E-11 | The decision itself: release to GitHub + GHCR only, or also PyPI (which needs an account and token) | The gate criterion names version/tag/commit/wheel/image/SBOM/provenance — not PyPI. Choosing the narrower release closes P4-2 without inventing a distribution channel | The chosen scope is written into `PHASE4_PLAN.md` §P4-2 before the dispatch, and the dispatch is recorded after |

## D. Environment — the cost of two red CI runs on 2026-11-11

| ID | Item | Why it matters | Done when |
|---|---|---|---|
| E-12 | Local `.venv` and CI resolve different versions from the same unbounded range (`typer>=0.12` gave 0.29.0 locally, 0.28.0 in CI) | A suite that passes locally failed CI twice, on a test that was correct in substance. `requirements.txt` is hash-pinned but the `.[dev,mcp]` install path is not | Either a lock for the dev extra, or a `make dev-env` / script that installs exactly what CI installs, referenced from the contributor section |

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
