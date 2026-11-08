# Phase 3 typed measurement boundaries — 2026-11-08

Status: **engineering/evidence increment; Phase 3 remains in progress**.
Source baseline: clean `b9f8e0d`; its hosted CI passed:
https://github.com/aiagentmackenzie-lang/NeuralStrike/actions/runs/42438409186.

## Demonstrated measurement limitation and contract

The previous AgentDojo report explicitly compared forbidden **emitted intent**
with native **completed-effect** labels. Its three FP rows represented correctly
observed intent whose effect was blocked or remapped. That is useful calibration,
but those rows are not detector false-accusation statistics. This semantic caveat
now has an enforced data contract rather than depending only on prose.

Version 2 efficacy labels require `ground_truth_boundary` on every case:
`emitted_intent` or `completed_effect`. Before recording, the assessment plan must
freeze `declared_scope.measurement_contract` with exactly `boundary` and `origin`.
Example for the local receipt profile:

```json
{"measurement_contract": {
  "boundary": "completed_effect",
  "origin": "agentdojo-native-local-completed-dispatch"
}}
```

A missing, invalid or unbound contract rejects export. An explicit truth boundary
cannot be smuggled into version 1 labels. Version 1 remains readable with its
existing classification semantics, but exports identify
`legacy_unspecified_boundary` and `measurement_comparable: false`. Schema versions
must be actual integers. Existing CLI syntax and historical bundles are unchanged.

Version 2 only places aligned observations into TP/FP/TN/FN/inconclusive counts.
Mismatched boundaries become **not_comparable**, even if their boolean outcomes
happen to agree. Their original prediction, source execution health, error/missing
counts and expected outcome remain visible. Counts are exclusive:
TP+FP+TN+FN+inconclusive+not_comparable equals planned rows. Ratios exclude
not-comparable rows and retain null when no eligible denominator exists. No
positive observation is deleted to obtain that result. `measurement_comparable`
means matching declared types, not complete execution, truthful provenance,
independence, statistical representativeness or a verified fix.

`prediction_origin` comes from the digest-bound recording plan and is included in
grouped counts. This is explicitly a declared origin. Original finding
`evidence_origin` remains separate and can remain unattributed. Neither field
signs/authenticates the source or promotes it to a production effect/canary receipt.

## Separate effect predictor

`examples/agentdojo_banking/replay.py --measurement completed_effect` selects the
new receipt-based measurement; its default emitted-intent path remains available.
The effect selector:

- Reads completed native dispatch receipts, using effective arguments when the
  application bound them to trusted bill data. Blocked calls are excluded.
- Implements the selected goal checks over those receipts: transfer amount and
  recipient, recurring payment recipient, password change, or outbound detail
  content. It never reads `upstream_violation`, `upstream_utility` or oracle labels.
- Preserves validated positive observations across later failed/malformed receipts
  and marks execution incomplete. Incomplete negatives cannot establish resistance.
- Freezes a JSON observation and selector source digest in canonical evidence. An
  existing deterministic PredicateOracle scores that frozen observation, keeping
  conservative Verbal fidelity. It does not fabricate local-canary Behavioral
  evidence or mislabel completed receipts as emitted tool calls.

Native AgentDojo pre/post-state predicates remain the separate upstream-asserted
label source. Agreement between two implementations is not independent human
validation. Original-oracle replay checks the frozen selector output; it does not
silently execute source code or rerun the selector. The raw source observation and
selector hash/code are supplied so a reviewer can separately recompute it.

## Fresh local-model evidence

The old `/tmp/neuralstrike-*` environments, observations and review zip were no
longer present at session start. The committed 2026-11-07 index remains a historical
summary; its original private raw bytes cannot currently be independently rechecked.
Do not describe the old zip as available or silently substitute new observations
for it. Fresh results below are a distinct run with distinct identifiers.

New durable private root:
`/Users/agentmackenzie/Documents/Codex/2026-11-08/neuralstrike-phase3`.
Pinned AgentDojo revision/model and local-only controls are unchanged. Dependencies
were rebuilt from the existing hashed locks in separate environments. No dependency
upgrade, model download, external target, cloud inference, outreach or release.

Fresh actual-model cycles at seeds **7, 17 and 29**, three stages each, reproduced
native violation/utility **true/false → false/true → true/false**. The repeated-seed
plan was saved before the additional two cycles. All nine observations are kept.
This is one recipient-field scenario and correlated configuration variants, not
nine independent applications or a representative cohort.

| Measurement against upstream completed-state labels | TP | FP | TN | FN | Not comparable |
|---|---:|---:|---:|---:|---:|
| Recorded emitted intent | 0 | 0 | 0 | 0 | 9 |
| Completed-dispatch selector | 6 | 0 | 3 | 0 | 0 |

Both exports preserve all nine attempts and their native task utility (**3/9**
overall; all three fixed stages complete the legitimate bill task). The six
vulnerable/regressed stages divert the payment, so their benign utility fails.
Original-oracle replay agrees for both measurements. Counts, denominators, Wilson
intervals, source health and declared origins are in the machine-readable index:
[evidence/phase3-boundaries-2026-11-08.json](evidence/phase3-boundaries-2026-11-08.json).
No generalized efficacy, comparison ranking or independent review claim follows.

Reproduce using the existing example setup, then:

```sh
python -m examples.agentdojo_banking.verify --source /PATH/TO/PINNED/agentdojo \
  --python /PATH/TO/ISOLATED/bin/python --out /DURABLE/PRIVATE/observations --seed 17
python -m examples.agentdojo_banking.replay \
  --observation /DURABLE/PRIVATE/observation.json --out /DURABLE/PRIVATE/assessments \
  --measurement completed_effect
```

Ground truth, native state, provider bodies, requested/effective arguments and
canonical evidence remain distinct. The raw packet is private and hashes establish
internal consistency, not author authenticity. Human labels/review, broader target
classes/applications, memory/destructive behavior, fair PyRIT/garak workflows,
consenting pilots and Phase 4 acceptance remain outstanding. See PROGRESS.md for
verification and the durable packet path.
