# Offline run replay and rescoring

A run directory is private raw evidence. Do not publish it or treat any report
format as a sanitizer. Request bodies can contain sensitive target content even
when authentication headers and URL credentials were excluded during capture.

## Commands

```sh
# Verify hashes and consistency; recompute scores from recorded trial outcomes.
neuralstrike replay runs/<run-id> --out /private/replayed.json

# Also re-evaluate the original supported deterministic policy, offline.
neuralstrike replay runs/<run-id> --verify-oracles

# Evaluate a new explicit policy and create a separate derived bundle.
neuralstrike rescore runs/<run-id> --forbid-tool grant_admin_access \
  --oracle-version tool-policy-v2 --out-dir derived-runs
```

These commands construct no target/provider and make no model calls. The CLI
rescoring policy uses the built-in forbidden-tool oracle: full names, with its
existing case-insensitive policy matching; receipt binding remains exact.
Default `--fail-on vuln` exits 1 for an observed violation, 3 for incomplete
assessment, and 0 only for a conclusive non-violation under that selected policy.
`--fail-on never` overrides the assessment exit, not bundle-load failures, and
still displays incomplete health. Changing the policy does not establish that a
live target was remediated. Evidence replay is distinct from a fresh target run.

The Python API exposes `load_bundle`, `replay_bundle` and `rescore_bundle` in
`neuralstrike.evaluation.bundle`. The rescore API accepts explicitly supplied
trusted Oracle objects; arbitrary caller code is not sandboxed. The CLI does
not import oracle classes or code from evidence. Built-in policy recipes cover
canary, system-prompt extraction, forbidden-tool/argument constraints, predicate
and Draft-7 schema oracles. External schema references are refused offline.
Custom oracles/validators are explicitly non-replayable via a stored recipe;
callers can supply their implementation explicitly for a new derived rescore.

`--verify-oracles` requires an exact implementation digest covering the built-in
oracle modules, recipe code, verdict foundation, combination and receipt binding.
A changed implementation requires an explicit rescore, rather than silently
calling a new implementation an identical replay. Advisory model judgments are
not rerun offline; original-oracle verification rejects mismatched/unsupported
judged records. Recorded-outcome replay remains available for structurally valid
bundles with those limitations. Regex and schema recipes are local computation;
use trusted assessment bundles. This is not a sandbox for hostile policy inputs.

## Persistence and compatibility

New run manifests declare schema 2 (separate from corpus report schema 2 and
baseline snapshot schema 1). Each trial has explicit response presence, a stable
observation `evidence_id`, and a separate oracle policy. The observation ID hashes
normalized recorded inputs/responses and trial context, excluding outcomes,
findings and evaluation policy. It remains unchanged when the same observation
is rescored. Run ID + trial index identify the execution location; identical
observation content can legitimately have the same content ID in another run.

New metadata retains category/severity and actual completion time. Old reports
show missing completion as unrecorded, never the export time. No seed or clock
field guarantees that a provider would produce the same live response.

The loader verifies a complete known-schema manifest, exact file inventory,
bounded regular files, SHA-256 hashes, component/report equality, scenario/trial
identity, comparison context, observation IDs, receipt structure and recomputed
scores. Duplicate JSON keys, nonfinite numbers, symlink entries, unknown declared
schemas and incomplete persistence fail explicitly. Current limits are 16 MiB
per file, 256 MiB per bundle and 10,000 trials. Oversized evidence is rejected,
not truncated into a pass. POSIX no-follow behavior and private modes are tested
on macOS; no new cross-platform certification is claimed.

Phase 0 schema-1 bundles with the canonical trial/score shape remain readable.
They lack response-presence and explicit category/policy assurances. An absent
category can be recovered only from a unique recorded conclusive category;
zero-conclusive legacy bundles retain unknown/uncategorized context. Older or
inconsistent shapes fail explicitly and require a trusted reference rerun; no
in-place migration or mutation is performed.

Rescoring records the source execution ID, source manifest hash, user policy
version and actual implementation/configuration digest. It creates a new unique
private directory with atomic writes. Output inside the source bundle is
rejected. Original inputs, observations and raw receipts remain intact; derived
outcomes replace annotations only in the new bundle. A failed derivation cannot
be labeled a complete committed bundle.

Hashes establish byte consistency, not author authenticity. Someone able to
rewrite all files and the manifest can author a different self-consistent bundle.
A local-canary receipt proves harmless fixture execution, not production account
takeover. Remote build identity, permission attestations, sanitized sharing,
complete capture across every adapter and a signed multi-scenario assessment
bundle remain outside this increment.

## Portable multi-scenario assessments

`corpus` now freezes its entire selected plan before adapter setup and records
`<run-dir>/assessment-<id>/`. Existing `<run-dir>/run-<id>/` files remain available
for CLI compatibility. The assessment is self-contained: `plan.json`, aggregate
`report.json`, a versioned manifest, and private child bundles under `runs/`.
Moving/copying the directory does not require the original checkout or run root.

```sh
neuralstrike replay runs/assessment-<id> --verify-oracles \
  --format sarif --out /private/replayed.sarif
neuralstrike rescore runs/assessment-<id> --forbid-tool grant_admin_access \
  --oracle-version tool-policy-v2 --out-dir derived-assessments
neuralstrike export-summary runs/assessment-<id> --out /private/share-summary.json
```

Assessment manifest schema 1 has kind `neuralstrike-assessment`; it is distinct
from per-run manifest schemas 1/2, report schema 2 and baseline schema 1. It binds
the frozen ordered scenario definitions, base seed/trial budget, declared scope,
configured target label, recorded failure policy, child manifest hashes and
compiled report. The plan digest identifies this execution's exact plan,
including execution identity/time; it is not a remote build or author signature.
Scope-file digests and intent record supplied configuration, not permission
attestation. URL credentials/query/fragment are excluded from target labels.

Missing scenarios remain selected, appear with `recording_status: missing`, and
have zero committed trials. No dummy attempt is invented. A source may have
attempted work without committing evidence; missing status does not assert that
nothing executed. JSON/SARIF rules/JUnit properties/human views and the dashboard
retain this distinction. Coverage is labeled as conclusive / recorded trials;
health's selected/attempted counts and completeness are authoritative for scope.
An assessment-wide failure remains incomplete even if every child is conclusive.
A complete persistence manifest does not mean successful/security-complete
execution. Running/partial persistence is rejected rather than treated as a pass.

`recorded_gate` retains the original standalone policy decision and explicitly
records that no baseline comparison occurred. A replay invocation can select a
different `--fail-on`; its process exit is separately displayed without modifying
the source's recorded policy. `never` remains an explicit report-only override.
Do not gate on JUnit pass/skip rows alone: assessment-wide health/scope/error
properties and the CLI exit are required, including for zero-trial suites.

Rescoring preserves selected/missing scenarios, original inputs, observations and
source-wide execution errors. It records source assessment ID/manifest hash,
explicit oracle version and implementation digest in a new unique assessment.
The original scenario describes the workload that was run; the new per-trial
oracle policy/provenance describes the evaluation override. No live remediation
is inferred by changing that policy.

Known report-schema-2 recording-status labels are additive and can be derived
for older snapshots. Recorded producer versions are preserved during replay,
rather than replaced with the installed viewer's version. Other incompatible
schemas or contradictory records still fail explicitly. Parent profiles allow
at most 1,000 scenarios, 10,000 planned trials, 16 MiB per file and 256 MiB across
the entire assessment. Existing profiles are not silently truncated to fit.

Sharing summaries use a separate schema/profile and are not full reports for the
dashboard or replay. See CAPTURE_PROFILES.md for the exact omission/sanitization
boundary and the adapters outside complete-body capture support.
