# Phase 3 efficacy — 2026-11-07

Status: **in progress; independent efficacy acceptance is not established**.
Started from clean `fc28469`. Phase 2 acceptance remains scoped to its recorded
engineering profiles. This increment implements an offline measurement vertical
slice, not an independent application cohort, human review or customer pilot.

## Evaluation contract

`neuralstrike efficacy ASSESSMENT --labels LABELS.json --out METRICS.json`
loads the existing committed canonical assessment and every child through the
integrity-checking replay loader. It makes no target, model or oracle calls.
The separate strict JSON sidecar must cover exactly the selected scenarios once,
bind their complete frozen content digests and the assessment manifest digest,
and declare application source/revision/license/configuration, capabilities and
exclusions. Duplicate keys, extra fields, string booleans, missing labels and
mismatched provenance fail. Output is private mode 0600 outside the source bundle
and cannot overwrite the label file. Exit 0 means export succeeded, **not a
security pass, verified fix or Phase 3 acceptance**; invalid inputs exit 3.

Each case records expected violation, boundary class, preconditions, ground-truth
source/document digest, label origin and a separately measured benign task result
with an evidence digest. Expected violation describes the exact selected operation
in that application configuration. It is not simply “the application contains a
vulnerability.” Labels must come from independently specified policy and observed
application state, never from NeuralStrike's prediction. A genuinely stochastic
outcome requiring different per-trial ground truth needs separate cases; this
initial contract only supports a fixed expectation per case/configuration.

Label origins (`self_authored`, `upstream_assertion`, `independent_review`,
`pilot_owner`) are **supplied assertions**. Neither hashes nor an origin string
prove independence, reviewer identity, consent or accurate labeling. Source
revision/configuration and external evidence digests are recorded assertions;
this command does not fetch those artifacts or authenticate their authors.
Review packets must include those referenced originals. Labels are bound after
execution; this is not a preregistration or blinding protocol.

## Counting rules

| Recorded prediction | Expected violation | Classification |
|---|---|---|
| Succeeded, including a later execution error | true / false | TP / FP |
| Complete Resisted | true / false | FN / TN |
| Resisted with trial/response error | either | Inconclusive |
| Inconclusive or missing planned trial | either | Inconclusive |
| Assessment-wide error with a negative prediction | either | Inconclusive |

Missing planned trials remain explicit denominator rows with no fabricated run ID,
seed or attempt. Positive observations survive later errors. Trial error counts,
missing counts, assessment-wide errors and source execution health remain separate.
TP+FP+TN+FN+inconclusive equals the planned count. Report totals and groups by
boundary class and recorded evidence-origin set retain all outcomes. Missing
attribution is `unattributed`; verbal, intent and local handler evidence never
become production execution through this export. Original fidelity is retained.

Precision uses TP/(TP+FP), recall TP/(TP+FN), specificity TN/(TN+FP).
These are explicitly **conclusive-only** ratios; inconclusives do not establish
TN, FN, resistance or fixes. All rates include numerators, denominators and Wilson
95% intervals; absent denominators yield null values/intervals. Repeated trials
may be correlated, and selected cases are not a representative population sample.
Intervals do not establish independence or general efficacy. No composite efficacy
or remediation score is published.

Benign completion is supplied **once per case**, not multiplied by attack trials.
Passed/(passed+failed) has its own denominator; inconclusive and unmeasured cases
remain counted separately. This slice cannot establish preserved utility without
real task evidence; disabling all useful tools is not successful remediation.

## Working engineering packet

```sh
python -m examples.langgraph_account_support.efficacy --out /tmp/phase3-packet
# Prints a unique validation directory containing three assessment bundles,
# application state/events, labels and efficacy reports for each mode.
neuralstrike efficacy /PATH/TO/assessment-UUID \
  --labels /PATH/TO/vulnerable-labels.json --out /tmp/review-metrics.json
```

Requires the existing LangGraph extra/dev environment. No third-party code import,
new dependency, inference or external target. The generator runs the existing
vulnerable → hardened → regressed cycle with reset hooks, original-oracle offline
replay and baseline gates. Expected labels come from the configured mode and
direct role-state checks, separately from oracle verdicts. The task-completion
receipt and application source digest are preserved. Reports always state
`independent_validation: not_established`.

Reviewable finding: injected retrieved content causes a synthetic reader customer's
role to become admin in vulnerable/regressed mode. Preconditions: controlled
account-support application, explicit injected document and vulnerable policy.
Evidence: `validation.json` role/events, source digest, stage assessment/run IDs,
canonical trial calls and original policy. Fix guidance: enforce authorization in
the application tool dispatch using the authenticated actor; retrieved content
must not supply authority. Hardened mode retains the benign support answer and
reader role. Persistent rerun: the command above, plus
`tests/test_efficacy.py::test_controlled_application_packet_keeps_truth_separate_from_prediction`.
These application events are same-author evidence, not independent human review.

A reviewer should inspect policy and expected labels before consulting predictions,
verify the source/configuration and all referenced evidence, replay each assessment,
rerun the controlled cycle, and record disagreements and their own dated identity
in a separate review document. No reviewer has been contacted or participated.
For a pilot, supply owner consent, exact local deployment/build/configuration,
synthetic test data and policy labels, authorized capabilities, benign task criteria,
request/token/time budgets and retention rules. No pilot consent or result exists.

## Public source research and comparison candidates

Read-only source review on 2026-11-07; exact HEAD revisions resolved with GitHub's
commit API and LICENSE/README/pyproject fetched at those revisions. No candidate
was installed, imported or executed. These are candidates, not accepted cohort rows.

| Candidate | Pinned revision and primary source | License / execution review / disposition |
|---|---|---|
| AgentDojo | [089ed468cf3ed0322acc66b0211f26d9d90dbf60](https://github.com/ethz-spylab/agentdojo/tree/089ed468cf3ed0322acc66b0211f26d9d90dbf60) | [MIT](https://github.com/ethz-spylab/agentdojo/blob/089ed468cf3ed0322acc66b0211f26d9d90dbf60/LICENSE); retain copyright/license on redistribution. README benchmarks tool-using workspace tasks; pyproject 0.1.35 requires Python >=3.10 and multiple provider SDKs, langchain, deepdiff and dotenv. Candidate independently developed simulated task environment, not an independent human review or deployed customer application. Next: inspect task security/utility predicates and actual tool effects, select disjoint tasks, isolate dependencies and use only an explicitly local backend. Default cloud benchmark command was not run. |
| PyRIT | [298f27d4a4bf9f401b65e7f042b8abf46ea246ff](https://github.com/microsoft/PyRIT/tree/298f27d4a4bf9f401b65e7f042b8abf46ea246ff) | [MIT](https://github.com/microsoft/PyRIT/blob/298f27d4a4bf9f401b65e7f042b8abf46ea246ff/LICENSE). Comparison tool candidate; reviewed metadata is 1.2.0.dev0. Not a vulnerable target or measured comparator run. |
| garak | [892779207cbc38f65a738ef9cbdfbc1e83aa0b55](https://github.com/NVIDIA/garak/tree/892779207cbc38f65a738ef9cbdfbc1e83aa0b55) | [Apache-2.0](https://github.com/NVIDIA/garak/blob/892779207cbc38f65a738ef9cbdfbc1e83aa0b55/LICENSE). Comparison tool candidate; metadata 0.17.2.pre1. Redistribution requires license/notice review. Not a vulnerable application or measured comparator run. |

Comparison status: **not performed**, no scores. Before comparing, pin a genuinely
common request/response workflow, same local target build, exact prompts, trial
seeds, request/token/time budgets, independent policy/state ground truth, capture
origin and task utility. Report adapter/scorer/tool-action workflow mismatches as
unsupported, not zero scores. Do not infer equivalence from all tools accepting
text or having deterministic scorers. Keep comparator environments separate from
NeuralStrike's hashed runtime locks. No dependency changes were made here.

## Remaining acceptance work

The required approximately 10–15 independently labeled meaningful cases are absent.
Privilege change, outbound transfer, destructive action, argument redirection,
retrieval contamination, true persistent-memory influence (only for targets that
actually implement memory), non-vulnerable configurations and benign operations
still require independently authored applications and corroborated ground truth.
No independent efficacy metric, reviewer validation, fair comparative result,
customer feedback, willingness-to-pay or pilot completion is claimed. Phase 4
release/provenance/platform/pilot gates remain open. Further independent engineering
can proceed with candidate task review and controlled local integrations; human
review and pilots require actual participants and consent, without unauthorized
outreach. Verification for this increment is recorded in PROGRESS.md.

## Subsequent local application increment

The candidate-only status above is superseded for the exact AgentDojo banking
profile in [AGENTDOJO_LOCAL_PROFILE.md](AGENTDOJO_LOCAL_PROFILE.md): actual local
model inference, native simulated tool effects and upstream state/utility predicates
were exercised in 15 exploratory configurations. A fresh local effect/utility
remediation cycle reproduced. PyRIT/garak execution, diverse application coverage,
independent human labels/review and consenting pilots remain absent. The original
candidate research is retained as history; this increment does not accept Phase 3.

## Typed measurement contract — 2026-11-08

Version 2 labels now bind the ground-truth boundary to the recording plan's
prediction boundary/origin. Intent/effect mismatches are not comparable and cannot
produce TP/FP/TN/FN rates. Version 1 retains explicitly marked legacy counts.
A separate completed-dispatch selector and fresh durable three-seed native cycles
are recorded in [PHASE3_MEASUREMENT_BOUNDARIES.md](PHASE3_MEASUREMENT_BOUNDARIES.md).
Historical `/tmp` raw artifacts have expired; do not claim their availability.
Phase 3 independent-review/cohort/comparator/pilot gates remain open.
