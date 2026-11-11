# Authenticated live target — operator guide

How to point NeuralStrike at a real, **authorized** OpenAI-compatible endpoint. Read
[SUPPORT_MATRIX.md](SUPPORT_MATRIX.md) first: only the declared profiles carry acceptance claims,
and a capability probe is not a security result.

> Scope is yours to establish. Test only systems you own or are explicitly authorized to test.
> `--scope-file` is enforced by the tool, but it is not a substitute for written authorization.

## 1. Put the credential in the environment, never on the command line

The bearer is supplied by **reference**: the tool reads the variable and never prints its value.

```sh
export TARGET_KEY='…'          # your authorized credential; do not commit this
```

A missing, empty or header-unsafe value is rejected before any request is sent
(`environment_credential` in `src/neuralstrike/adapters/preflight.py`).

## 2. Establish scope

```yaml
# scope.yaml
authorized_by: <name and date of the authorization>
targets:
  - https://your-authorized-endpoint.example
```

## 3. Probe capability before spending tokens

```sh
neuralstrike doctor \
  --url https://your-authorized-endpoint.example \
  --model <model-name> \
  --target-api-key-env TARGET_KEY \
  --scope-file scope.yaml \
  --out doctor-receipt.json
```

- **Exit 0** means the requested capability was *observed* (including a harmless tool
  round-trip with `--tools`). It is not a security pass.
- **Exit 3** means preflight is incomplete — missing identity, rejected credentials, timeout.
- No consequential tool handler runs during `doctor`.
- This sends a real completion request and **may incur provider cost**.

The receipt is private, mode 0600, and records the declared JSON profile, requested model and
whatever response metadata the endpoint actually supplied. Backend build identity is recorded as
unverified when the endpoint does not expose it; it is never inferred from connectivity.

## 4. Run the declared assessment with explicit budgets

```sh
neuralstrike assess \
  --adapter openai \
  --url https://your-authorized-endpoint.example \
  --model <model-name> \
  --target-api-key-env TARGET_KEY \
  --scope-file scope.yaml \
  --max-requests 20 \
  --max-total-tokens 40000
```

`assess` is the one assessment command (Phase 4 command spine). `corpus` is the legacy name for
the same implementation and still works, but it prints a deprecation notice.

Budgets are admission controls on requests already dispatched: a token threshold can overshoot,
and **no absolute spend ceiling is promised**. Set them below what you are willing to spend, and
watch the provider console.

## 5. Verify a fix by comparing two committed assessments

```sh
neuralstrike compare runs/assessment-<before> runs/assessment-<after> --fail-on regression
```

`compare` is offline: both bundles are hash-verified, and no target, model or oracle is called.
Exit `0` pass, `1` vuln, `3` not comparable, `4` regression. A scenario that went Succeeded →
Inconclusive is **not** a fix, and a comparison against a different target, seed, trial count or
scenario payload is refused rather than scored.

## 6. What an authenticated run does not establish

- It does not establish that the target is insecure, or that a fix works. That requires a
  vulnerable → hardened → regression cycle ([PHASE2_ACCEPTANCE.md](implementation/PHASE2_ACCEPTANCE.md)).
- It does not establish production compromise. Instrumented canary execution is a local receipt,
  not a customer incident.
- It does not produce a comparator score, a pilot result or independent review.

## Authentication on every driving command

`doctor`, `assess` (legacy `corpus`) and `scan` all accept `--target-api-key-env`, so the bearer is
supplied by reference and never appears on a command line. A missing, empty or header-unsafe value
is rejected before any request is sent. `scan` resolves the credential before its first trial, so an
authenticated endpoint is no longer reachable only through `doctor` and `assess`:

```sh
neuralstrike scan \
  --adapter openai \
  --url https://your-authorized-endpoint.example \
  --model <model-name> \
  --target-api-key-env TARGET_KEY \
  --scope-file scope.yaml \
  --prompt "<one declared prompt>" \
  --trials 3
```

`scan` drives one declared scenario; `assess` runs the frozen selection. Both send the same resolved
bearer.

## Verification of this guide

The authenticated path is covered by `tests/test_corpus_target_auth.py` (doctor/assess) and
`tests/test_command_spine.py` (scan): a separate stdlib loopback HTTP server, a synthetic
environment bearer, correct credentials and rejected credentials. If those tests change, this guide
must change with them.
