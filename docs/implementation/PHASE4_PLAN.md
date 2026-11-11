# Phase 4 plan — narrow pilot release: gate definition and current state

Status: **NOT RELEASED.** Phase 4 is the master plan's release phase, and its acceptance gates
are the ones that turn a working tool into an artifact another team can install, verify and
judge. Three of its seven gates are engineering, three need people, and one is both. Nothing
here is signed, and no gate is satisfied by this document.

This document exists for the same reason [PHASE3_ACCEPTANCE.md](PHASE3_ACCEPTANCE.md) does: the
master plan's Phase 4 requirements were prose in a planning document, so they could not be
checked. Here they are as binaries, with the evidence that would satisfy each and the state
measured against this repository.

Phase 3 remains **NOT ACCEPTED** and is unaffected by anything in this file.

Date: 2026-11-11. Source revision at this assessment: `2b104d8`.

## The acceptance rule

Same two-column discipline as Phase 3, because the failure mode is the same: a state can be
complete while nobody outside this repository has signed it.

- **State** is `MET`, `PARTIAL` or `OPEN`, and it is a statement about evidence only.
  `MET` means the binary criterion is satisfied by evidence at a path a reviewer can open
  without asking me anything. `PARTIAL` means some of the required evidence exists and the
  exact shortfall is named. `OPEN` means the evidence is absent in kind.
- **Signed** is a name and a date from someone who is not the author. Every row below is
  unsigned, so every state below is an author's claim.

Phase 4 may be called **released** only when every gate is `MET` **and** every gate is signed.
A tag, a wheel or a green workflow is not a release.

## Gates

| ID | Gate | Binary criterion | State | Evidence | Required signer | Signed |
|---|---|---|---|---|---|---|
| P4-1 | Command spine | one assessment command, one compare command and one replay command exist, and every command a document names resolves to a registered command | **MET** — `assess` is the single assessment command: the legacy `corpus` name is the **same callback** registered under a second name, so the alias cannot drift, and it prints a deprecation notice at runtime. `compare BASELINE CURRENT` is the single comparison command: offline, both bundles hash-verified, and it calls the live gate's own decision function (`decide_comparison`) so the two surfaces cannot disagree about a regression. `replay` already existed. `scan --adapter openai` now accepts `--target-api-key-env` and attaches the resolved bearer, closing the asymmetry the live-target guide exposed. The documentation contract now reads the registered commands from the Typer app instead of parsing decorators, so a command registered under two names cannot hide from it | `src/neuralstrike/main.py`, `src/neuralstrike/evaluation/compare.py`, `src/neuralstrike/evaluation/baseline.py`, `tests/test_command_spine.py`, `tests/test_phase4_plan.py`, `docs/LIVE_TARGET_GUIDE.md` | release engineer | — |
| P4-2 | Artifact binding | one release binds version, tag, source commit, wheel, image digest, SBOM and provenance; the wheel and the container are installed and exercised **independently of the editable checkout** | **PARTIAL** — the wheel half is implemented: a CI `artifact` job builds sdist+wheel, installs the wheel into a clean venv outside the checkout, asserts the import resolves to `site-packages` and not the repository, runs the offline smoke from outside, generates the SBOM of that installed environment and binds all three digests with tag and commit into `release-manifest.json` via `scripts/release_manifest.py`; `release.yml` binds the image digest into the same manifest and attaches it to the release. The wheel half is CI-verified: run `42934094480` at `d2acde5`, job `artifact` green through all nine steps, and the downloaded `release-manifest.json` re-verifies **3/3 digests** against the uploaded wheel, sdist and SBOM, with `signed: false` and `image: null`. Container half CI-verified at `9824c7a` (run `42937379076`). **Shortfall: no dispatched release exists, so the image-digest binding in the release manifest is written but unproven** | `.github/workflows/ci.yml` job `artifact`, `.github/workflows/release.yml`, `scripts/release_manifest.py`, `tests/test_release_manifest.py` | release engineer | — |
| P4-3 | Signing policy explicit | the documentation states whether signing is performed, on which artifacts, and that unsigned artifacts are not claimed as signed | **MET** — §Signing policy below states optional-and-off-by-default, names the image digest and SBOM attestation as the only signed objects, and forbids calling any artifact signed without a recorded signature; the README repeats that nothing is signed, and a contract asserts the cosign steps stay conditional on `inputs.sign` | `.github/workflows/release.yml`, this document §Signing policy, `README.md`, `tests/test_phase4_plan.py` | release engineer | — |
| P4-4 | Scheduled dependency health | a scheduled job audits the pinned locks on a fixed cadence, independently of commits, and its result is readable as an artifact | **MET** — `.github/workflows/dependency-check.yml` runs Mondays 06:17 UTC and on demand, audits both hashed locks, uploads JSON with `if: always()`, and holds `contents: read`; dispatched run `42931775244` at `41670a7` completed **success** with the audit artifact attached. The cron trigger itself has not yet fired on a Monday; the scheduled *mechanism* is what this gate claims | `.github/workflows/dependency-check.yml`, run `42931775244` | release engineer | — |
| P4-5 | Pilot-facing docs | an offline example, an authenticated live-target guide, and a supported-versus-experimental matrix with measured limits | **MET** — [SUPPORT_MATRIX.md](../SUPPORT_MATRIX.md) partitions supported / experimental / excluded from the Phase 2 acceptance record and states measured limits; [LIVE_TARGET_GUIDE.md](../LIVE_TARGET_GUIDE.md) documents the credentialed path and names the `scan` authentication gap; [OFFLINE_EXAMPLE.md](../OFFLINE_EXAMPLE.md) is a verified no-model, no-network run. Contracts assert the documents exist, are linked, and name only registered commands | `docs/SUPPORT_MATRIX.md`, `docs/LIVE_TARGET_GUIDE.md`, `docs/OFFLINE_EXAMPLE.md` | release engineer | — |
| P4-6 | Pilot evidence | three independent teams complete install → compatible scan → review → fix → rerun, at least two without implementation-author assistance, with time to first useful result, setup failures, cost, usefulness and willingness to pay recorded | **OPEN** — no team, no consent, no recorded result, no commercial signal | — | pilot owner | — |
| P4-7 | Platform claims | platform and container claims are limited to combinations actually exercised, with container runtime and multi-arch validation as a gate rather than an assumption | **PARTIAL** — a CI `container` job builds the image, asserts it runs as uid 1000, runs the full offline smoke inside `linux/amd64` and checks the artifact is mode 600; `linux/arm64` is built under QEMU and exercised for import and `--help` only, and the support matrix states that depth instead of implying a full arm64 smoke. CI-verified at `9824c7a`, run `42937379076`: `container` job green — uid 1000, smoke passed (3 scenarios, ASR 33.3 %, coverage 100 %), artifact 61843 bytes mode 600, and the arm64 image started under emulation (`arch: aarch64`). The first push of this job failed (`42936253073`) on a quoting bug in the arm64 step, which is why the run id is the evidence and the intention is not | `.github/workflows/ci.yml` job `container`, `docs/SUPPORT_MATRIX.md`, `.github/workflows/release.yml` | release engineer | — |

Five gates are closed: P4-1 by code, P4-3 and P4-4 by stated policy and a real run, P4-5 by three
written documents, and P4-7 at the depth its criterion declares. P4-2 is short exactly one thing — a
dispatched release — which is a decision, not an implementation. P4-6 is entirely people, and it is
the gate the master plan actually cares about: a paid pilot is the demand test, and no amount of
work on the other six substitutes for it.

## Signing policy

Stated rather than implied, because "we have cosign in the workflow" is not a policy:

- Signing is **optional and off by default**. It runs only when the release is dispatched with
  both `publish` and `sign` true.
- When enabled, it signs the **container image digest** and attaches the CycloneDX SBOM as a
  Rekor attestation. It does **not** sign the wheel, the GitHub release asset or the source
  archive, and no gate above may cite a signature that does not exist.
- No document in this repository may describe an artifact as signed unless a signature for that
  exact artifact digest is recorded in the release evidence. As of `17b9832` there is no such
  record, so every artifact is **unsigned**.
- Keyless OIDC signing proves *who ran the workflow*, not that the build is reproducible. The
  reproducibility claim in P4-2 is separate and is not satisfied by a signature.

## Delivery order

Ordered by what unblocks what, not by size:

1. ~~**P4-4** — the scheduled check.~~ **Done 2026-11-10**, dispatched run `42931775244`.
2. ~~**P4-3** — the signing policy.~~ **Done 2026-11-10**, stated in §Signing policy.
3. ~~**P4-5** — the offline example and the supported-versus-experimental matrix.~~ **Done
   2026-11-10**, three documents written from the declared profiles rather than from ambition.
4. ~~**P4-2**, then **P4-7**~~ — wheel **and** container are now exercised outside the editable
   checkout, and the second architecture is started under emulation with its depth stated. What
   remains for P4-2 is a dispatched release to prove the image-digest binding; that needs a
   release decision, not more code.
5. ~~**P4-1** — the command spine~~ **Done 2026-11-11**: one assessment callback under two names
   (`assess`, deprecated `corpus`), one offline `compare` that reuses the live gate's decision
   function, and the `scan` credential gap closed. Only P4-2 (a release decision) and P4-6
   (people) remain.
6. **P4-6** — people. It cannot be started by code, and it is the only gate that can justify
   the phase.

## What this document does not do

It does not release anything, and it does not claim that any artifact is signed, reproducible or
independently verified. It does not move Phase 3: P3-1 to P3-6 stay exactly as recorded in
[PHASE3_ACCEPTANCE.md](PHASE3_ACCEPTANCE.md), and P3-7 stays `MET` and unsigned. It does not
create a release, a tag, a wheel or an image, and nothing here is a pilot result.
