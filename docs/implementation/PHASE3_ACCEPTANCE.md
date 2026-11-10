# Phase 3 acceptance — gate definition and current state

Status: **NOT ACCEPTED.** Phase 3 has no independent labels, no independent review, no
comparison result, no pilot and no commercial signal, and one boundary class has no native
measurement at all. This document exists because those gates were spread across six files and
therefore could not be checked; it defines them as binaries, records the evidence that would
satisfy each, and states what is true today.

Phase 2 engineering acceptance is separate and remains scoped to
[its own declared profiles](PHASE2_ACCEPTANCE.md). Phase 4 (release, provenance, platform,
pilot) has its own plan and is out of scope here.

Date: 2026-11-10. Source revision at this assessment: `7692e92` plus the docs commit that added
this file.

## The acceptance rule

Two independent things have to be true, and they are recorded in separate columns because
conflating them made this table useless: a gate's **evidence** can be complete while nobody has
signed it.

- **State** is `MET`, `PARTIAL` or `OPEN`, and it is a statement about evidence only.
  `MET` means the binary criterion is satisfied by evidence at a path a reviewer can open
  without asking me anything. `PARTIAL` means some of the required evidence exists and I can
  name the exact shortfall. `OPEN` means the evidence is absent in kind.
- **Signed** is a name and a date from someone who is not the author of the increment. A state
  of `MET` with no signature is an author's claim, which is what every row below currently is.

Phase 3 may be called **accepted** only when every gate is `MET` **and** every gate is signed.
Until then it is `NOT ACCEPTED`, and no other result of this project changes that.

## Gates

| ID | Gate | Binary criterion | State | Evidence | Required signer | Signed |
|---|---|---|---|---|---|---|
| P3-1 | Independent labels | ≥10 distinct cases, each with `label_origin` of `independent_review` or `pilot_owner`, and the referenced originals present in the packet | **OPEN** — 1 distinct scenario, origin `self_authored`; all 282 committed assessments are that same scenario | `runs/assessment-*/plan.json`, `examples/langgraph_account_support/efficacy.py` | independent labeller | — |
| P3-2 | Independent review | a reviewer who did not run the increment inspects policy and labels *before* predictions, replays every assessment, reruns the controlled cycle, and records a dated identity plus any disagreements | **OPEN** — none contacted, none available; review packets exist unread | `~/Documents/Codex/2026-11-08/neuralstrike-phase3/phase3-*-review.zip` | reviewer | — |
| P3-3 | Fair comparison | a pinned common workflow, same target build, explicit prompts/budgets/seeds, independent policy-and-state ground truth, and a reported result including adapter mismatches as unsupported rather than zero | **OPEN** — no NeuralStrike-vs-tool score exists; the one comparator run varies the attacker and keeps our measurement | [comparator protocol](TAU_BENCH_COMPARATOR_PROTOCOL.md) §10 | comparator author | — |
| P3-4 | Consent-based pilot | a consenting owner, exact deployment/build/configuration, synthetic or authorised data, declared capabilities, benign-task criteria, budgets and retention rules, and a recorded result | **OPEN** — no consent, no pilot | — | pilot owner | — |
| P3-5 | Commercial signal | documented feedback or willingness to pay from someone who is not the author | **OPEN** — none | — | counterparty | — |
| P3-6 | Boundary diversity and independence | a native measured observation for each of: privilege change, outbound transfer, destructive action, argument redirection, retrieval contamination, persistent-memory influence, non-vulnerable configuration, benign operation — and each on an application this project did not author, with ground truth corroborated outside this repository | **PARTIAL** — seven of eight classes have a native measured observation (destructive action: attempts only, never a reproduced effect), and object-level authority was measured on a pinned third-party target; but the ground truth is corroborated nowhere outside this repository, and two of the five measured applications are authored here | [efficacy record](PHASE3_EFFICACY.md), the five profile documents | reviewer | — |
| P3-7 | Utility preserved | benign task completion under the control, asserted per target rather than inferred, with the denominator stated | **MET** — asserted for every target that has a benign row: tau-bench `nemotron-3.5-lightning:30b` completes 3/3 bound and 3/3 unguarded with 0 refusals; tau-bench `qwen3.5:2b` completes 0/3 bound and 0/3 unguarded with 0 refusals, so the utility claim is falsified **for that model** and the control is not the cause; AgentDojo banking utility true in the fixed stage, workspace 5/5 tasks, memory-agent benign 18/18 and 30/30 | `examples/tau_bench_retail/utility_audit.py` artifact, `evidence/tau-bench-utility-audit-2026-11-10.json`; the four profile documents | reviewer | — |

## What "counts" as evidence, and what does not

Seven failure modes have actually been caught in this project. Each is now a rule, because
each was once true of a draft of the record:

1. **A scripted check is not efficacy.** `policy_check` (25/25, `inference: none`) proves the
   control's shape, never its effect on a model. It is excluded from every count and must stay
   excluded.
2. **Model non-action is not control efficacy.** A bound row where the model offered nothing is
   `not_exercised` — not a pass, and not a falsified control. Two of the three declared models
   made no tool call at all on the tau-bench attack payloads.
3. **A refusal of another action does not make a write row exercised.** Refusals are attributed
   to the tool that produced them, and only a `cross_principal` refusal of the declared tool
   counts. This rule moved exactly one recorded verdict, and that is how it was caught.
4. **A recorded summary is never re-scored in place.** Corrections get a new plan, a new kind
   and a new packet; the old rows stand as recorded. The read-only audit pattern
   (`refusal_audit.py`, `claims_audit.py`) reports, it does not rewrite.
5. **Plans are never pooled.** No sum, no rate, no row-for-row comparison across plans, and no
   percentage from a k of three. `k=3` is a count.
6. **A self-authored label is not an independent label.** The label-origin field exists so this
   cannot be glossed; `self_authored` is honest and it is also not sufficient for P3-1.
7. **Hashes prove bytes, not sentences.** A pin cannot protect prose it does not cover. A
   hand-audit of the tau-bench profile found four stale sentences while all 28 hashes resolved;
   `claims_audit.py` now checks the hashes and says explicitly that it does not check prose.

## Verification of this assessment

```bash
V=/tmp/neuralstrike-phase3-venv
$V/bin/python -m pytest --no-cov                                   # 1709 passed, 7 skipped
$V/bin/python -m pytest --cov=neuralstrike --cov-fail-under=85     # 91.88 %
$V/bin/ruff check src tests examples && $V/bin/mypy
# the record's own mechanical claims, read-only, no model:
$V/bin/python -m examples.tau_bench_retail.claims_audit \
  --packet-root ~/Documents/Codex/2026-11-08/neuralstrike-phase3 \
  --profile docs/implementation/TAU_BENCH_RETAIL_PROFILE.md \
  --evidence docs/implementation/evidence/phase3-tau-bench-retail-2026-11-09.json \
  --out /tmp/claims-audit.json      # 32 claims, 0 unresolved, 6 blocks, 0 mismatched
$ENV/bin/python -m examples.tau_bench_retail.policy_check --source "$SRC" --out /tmp/tb.json
# 25/25, inference: none, sha256 16825eda… (the scripted matrix, excluded from efficacy)
```

A contract (`tests/test_phase3_acceptance.py`) fails if a gate is removed from this table, if a
gate uses a status outside `ACCEPTED`/`PARTIAL`/`OPEN`, if any document this file links to is
missing, or if the status line claims acceptance while any gate is not `ACCEPTED`.

## What this document is not

It is not an acceptance, an audit by a second party, or a claim that the gates are close. It is
the author of the increments writing down the definition by which those increments should be
judged, so that the next reader does not have to reconstruct it — and so that a reviewer has
something to disagree with.

## Sign-off

| Gate | Signed by | Date | Note |
|---|---|---|---|
| all gates | — | — | no gate is signed; Phase 3 is not accepted |

No reviewer, pilot owner or counterparty has been contacted for this document.
