# Phase 1 acceptance — 2026-11-07

Status: the master plan's Phase 1 acceptance gates pass for the declared local
capture/replay profiles. This closes the Phase 1 evidence/report engineering
gate, not production readiness, universal adapter support or security efficacy.
Earlier progress entries recording open Phase 1 work are historical checkpoints.

| Master-plan requirement | Demonstrated evidence |
|---|---|
| Record an indirect trial; replay offline with identical scoring and no model calls | `test_bundle_replay.py`, `test_oracle_recipes.py`: exact observation/score round trips, original deterministic-policy verification across all 60 corpus cases, network-forbidden controls. `test_assessment_bundle.py`: moved self-contained assessments verify offline. |
| Rescore with a new oracle version without mutating the source | Per-run and assessment rescore tests preserve source bytes and observation IDs, record source manifest hash/version/implementation, retain missing selections and source-wide errors, and reject output inside the source. |
| Every format agrees for mixed oracles/outcomes, partial errors and unsupported channels | Shared four-trial synthetic fixture: S1/R1/I2, ASR 50%, recorded coverage 50%, incomplete health. JSON, SARIF, JUnit, Markdown, independently parsed/rendered PDF and dashboard agree. Parent ID/plan digest and missing-record labels propagate without invented trial rows. |
| Independent ES256 raw vectors verify; malformed/nonstandard signatures fail | RFC 7515 Appendix A.3 fixture and independent backend-signed JOSE-form control pass; DER wire encoding, invalid lengths and malformed raw signatures fail. Full JOSE/A2A authentication conformance is not inferred. |
| `grant_admin_access` trace cannot promote `grant_admin_access_extra` | `test_evidence_binding.py`: prose/prefix/suffix controls, exact call/name/argument identity, duplicate/absent/mismatched bindings. Bound local receipts survive replay/rescore and keep their fixture origin. |
| Corruption and incompatible schemas fail explicitly | Per-run/assessment tests reject missing/changed/unlisted/unsafe children, rewritten plan/summary inconsistencies, wrong schemas/states, duplicate JSON keys and invalid values. Corruption exits 3 even under `--fail-on never`. |

## Additional closure in this increment

- Corpus selection is frozen before adapter setup. Self-contained parent bundles
  bind the ordered full scenario definitions/scope, child manifests and aggregate
  report; existing per-run output paths remain. Missing selections have zero
  committed trials and incomplete health, not fabricated attempts. Setup/cleanup
  failures remain assessment-wide failures even with conclusive children.
- All five presentation formats can be regenerated from the parent offline. The
  dashboard also lists selected SARIF scenarios that have no result rows, while
  counting only actual recorded trials. `recorded_gate` identifies the source's
  standalone policy; it is not a replay override or a baseline comparison.
- Known older recording-status metadata can be derived read-only, and original
  producer versions survive replay. Unknown/contradictory shapes are not silently
  upgraded or made comparable. Root profile 1 and report profile 2 are distinct.
- Sharing is an allowlisted, content-redacted summary with separate kind/schema,
  not a supposedly sanitized full evidence bundle. Source validation precedes
  output; targets, identifiers, prompts, responses, arguments, policy/error text
  and other freeform fields are omitted. Hash references remain linkable. Export
  success is not a security-gate result; the summary cannot be replayed.
- The capture audit reproduced URL credentials in recorded HTTP error strings.
  An independent reviewer additionally reproduced default SDK INFO leakage.
  Both triggers and alternate encoded/redirect/transport forms now pass their
  regressions; ordinary `boom` diagnostics and exact private bodies remain.
  This fix covers adapter diagnostic copies plus default log filter/formatter
  URL rendering. No authentication behavior was weakened. See CAPTURE_PROFILES.md.

## Frozen-source verification

- Refreshed Python 3.12.14: `python -m pytest --cov=neuralstrike
  --cov-fail-under=85` → **1295 passed, 2 skipped, 91.62% coverage**.
  Local log: written to `/tmp`, **gone** — the counts are a record of that run, not a file a
  reviewer can open.
- `ruff check src tests`: pass. `mypy src`: pass, **136 source files**.
- Dashboard: **19 tests pass**; TypeScript/production build pass.
- Wheel and sdist rebuilt; installed rebuilt wheel with `--no-deps --reinstall`
  into the isolated runtime-lock environment. From `/tmp`, bundled graph corpus
  produced an assessment; moved-copy original-oracle replay rendered all five
  formats, derived assessment rescoring verified, sharing export succeeded and
  source bytes remained unchanged. Missing selection replay exited 3; corrupted
  replay and summary export exited 3 even under `never` / export-only handling.
- Final installed-wheel scratch root:
  `/var/folders/zv/n4210phd6_d5lqqfx462c9gw0000gn/T/neuralstrike-phase1-accepted-wheel-fjjzknaa`.
  Source manifest SHA-256:
  `0a595d45ea15a122f80ad21f94e8d7b87b4165b700e16e7b2545e11fedf8a32e`.
  Scratch evidence is local/disposable, not committed or published.
- Final two-page PDF preview was rendered with Poppler and visually inspected:
  legible IDs/digests, no clipping/overlap, trial errors grouped with their
  identities, correct pagination. Local fontconfig warning remains nonfatal.
- `git diff --check`: pass. No dependency changes since the recorded Phase 0
  hashed-lock audits. Existing setuptools/pytest deprecation warnings remain.

The two skipped tests require optional base58 and real NeuralGuard; neither is
counted as a verified integration. No cloud inference, external-target exercise,
release publication or optional service activation was performed. Local checks
are not a claim that hosted CI has completed for the final pushed commit.

## Boundaries retained for subsequent phases

CAPTURE_PROFILES.md defines what was actually captured. Other adapter/provider
wire capture and independent interoperability remain experimental. Authentication
references/preflight, remote build identity, target consumption/production-effect
attestation, resource/retry/idempotency controls, independent efficacy validation
and pilot readiness remain later-phase work. Raw artifacts remain private; full
replayable sanitized sharing and signed-author bundles are not implemented.
Stored-policy replay is limited to known deterministic recipes; advisory model
judges are not rerun. Coverage measures executed code, not security efficacy.
