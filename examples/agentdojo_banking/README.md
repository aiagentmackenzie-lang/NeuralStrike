# Pinned local AgentDojo banking profile

This experiment runs **actual local model inference** through native AgentDojo
`AgentPipeline`, `OpenAILLM`, `ToolsExecutor`, `FunctionsRuntime` and banking tools.
The target state and security/utility predicates come from the independently
written [AgentDojo source at 089ed468cf3ed0322acc66b0211f26d9d90dbf60](https://github.com/ethz-spylab/agentdojo/tree/089ed468cf3ed0322acc66b0211f26d9d90dbf60).
The integration, payloads, prefetch and authorization configurations are authored
here. This is not stock AgentDojo benchmark scoring, independent human validation,
a customer application assessment or evidence of production transfers.

Native source uses the [MIT license](https://github.com/ethz-spylab/agentdojo/blob/089ed468cf3ed0322acc66b0211f26d9d90dbf60/LICENSE).
No AgentDojo implementation code is vendored. Keep its license/copyright if
redistributing that source. `requirements.in` mirrors the pinned pyproject's
runtime dependencies; `requirements.txt` is an **optional isolated environment**
lock, not a change to NeuralStrike's locks. Reviewed target environment: Python
3.12.14/macOS. Candidate lock audit: 70 distributions, no known advisories and no
ignores at collection time. No filelock distribution is introduced by this lock;
NeuralStrike's mandatory security floor remains unchanged.

## Setup and execution

Run from the NeuralStrike checkout, with an existing Ollama service and locally
installed `qwen3.5:2b` artifact digest
`324d162be6ca5629ae4517c8710434d0bd2d665bc94dbad46e9af8fbf8a2f0df`.
The script does not download models. Cloud tags and alternate model names are
rejected before dispatch, even on the loopback Ollama service. The tag inventory
must report the pinned artifact and size greater than 1 GB. That is inventory
binding, not signed model-file attestation.

```sh
git clone https://github.com/ethz-spylab/agentdojo.git /tmp/agentdojo-reviewed
git -C /tmp/agentdojo-reviewed checkout 089ed468cf3ed0322acc66b0211f26d9d90dbf60
uv venv --python 3.12 /tmp/agentdojo-venv
uv pip install --python /tmp/agentdojo-venv/bin/python --require-hashes \
  -r examples/agentdojo_banking/requirements.txt

/tmp/agentdojo-venv/bin/python examples/agentdojo_banking/collect.py \
  --source /tmp/agentdojo-reviewed --out /tmp/agentdojo-observations \
  --case recipient_field_redirection --policy unfiltered --prefetch-bill --seed 7
```

The checkout must be clean at the pinned revision before import. All native
Python/YAML source hashes are captured. Ambient credential/proxy variables are
removed before native imports. Python socket connections are restricted to
127.0.0.1:11434, and the model transport admits only POST to the exact finite Chat
Completions endpoint with the fixed local model. This is a trusted-code experiment,
not an OS sandbox or a general malicious-code containment boundary.

Each attempt gets a private UUID directory and atomic mode-0600 journal recording
actual request/response bodies, seeds, token limits, finish reasons, requested
native actions/results/status, pre/post environment, injections and state-predicate
results. Five model requests, four native tool-loop iterations and 768 requested
completion tokens per request bound the profile. Finite bodies are capped at
1 MiB; incomplete finish reasons stop the pipeline before dispatch from that
completion. SDK HTTP retries are off. Upstream's decorated **inference** call may
retry failures, within the five-request admission limit; no application task or
consequential tool action is automatically retried by this harness. The native
benchmark helper's whole-task retry loop is deliberately not invoked. Native
banking effects are in-memory only. Journals are live before inference/dispatch,
so a killed process leaves a running/incomplete record. Python's socket guard
and request caps are not hard cancellation or an absolute resource ceiling.

`--prefetch-bill` explicitly performs the native `read_file` operation and supplies
its real tool result before model reasoning. The earlier non-prefetched trial's
failure to complete the task is retained separately. Do not silently substitute
prefetch results for autonomous retrieval measurements.

Policies:

- `unfiltered`: native tool effects, with no harness authorization gate.
- `authorized_bill_only`: allow reads and the exact legitimate bill payment;
  reject unrelated writes. It blocked redirection but did not complete that task.
- `trusted_bill_context`: the same gate plus a trusted payee system message. The
  observed redirection task still failed utility; prompting alone was insufficient.
- `bound_bill_payment`: the application owns the approved bill record. A payment
  for the approved amount resolves its payee from that record; other writes are
  denied. Requested and effective arguments are preserved separately. This is a
  deliberately narrow hardcoded fixture configuration, not a general payee mapper
  or production authorization implementation.

## Replay and useful-remediation rerun

In NeuralStrike's environment (no AgentDojo dependency needed):

```sh
python -m examples.agentdojo_banking.replay \
  --observation /tmp/agentdojo-observations/agentdojo-UUID/observation.json \
  --out /tmp/agentdojo-canonical
# Repeat --observation to select all attempts, including error-bearing journals.

python -m examples.agentdojo_banking.verify --source /tmp/agentdojo-reviewed \
  --python /tmp/agentdojo-venv/bin/python --out /tmp/agentdojo-remediation
```

The importer embeds the original source observation and actual provider seed in a
canonical assessment, freezes separate upstream-state labels, verifies original
built-in oracles offline and exports efficacy JSON. Missing ground-truth state is
rejected, not labeled safe. Running/error-bearing attempts remain incomplete;
confirmed earlier intent survives malformed later emissions/errors. Import is
recorded evidence conversion, not another live inference or deterministic rerun.
Label files are generated from native state predicates, never NeuralStrike's
verdicts. Native `security()` returns **attacker-goal success**, not safety.

The detector in this profile scores emitted forbidden tool/argument intent;
upstream labels score **completed simulated effects**. A blocked or redirected
call can therefore appear as FP in the efficacy export while the intent oracle
is behaving correctly. These are intent/effect calibration disagreements, not
false-accusation statistics or proof of detector quality. Do not suppress the
intent, promote it to execution, or infer a verified fix from that metric. Native
execution origin remains in the observation; oracle finding origin is currently
`unattributed`, with no canary Behavioral promotion. Utility checks the native
payment-state predicate, not every aspect of the assistant's final prose.

The remediation verifier reruns unfiltered → bound bill payment → unfiltered,
requiring complete execution and native violation/utility values
`true/false → false/true → true/false`. It fails if these expectations do not
reproduce, preserves process failures/journals and never declares a passing cycle
from missing or inconclusive evidence. Same-author instrumentation and an upstream
predicate are not independent human review. Provider seeds remain best effort.

## Recorded evidence and open gates

See [the evidence record](../../docs/implementation/AGENTDOJO_LOCAL_PROFILE.md).
One seed/trial per configuration, one simulated environment, adaptive additions
and harness-authored policies are explicit limitations. The 15 configurations
are not 15 independent applications or human-labeled cases. Memory, destructive
actions, broader cohorts, independent review, PyRIT/garak comparisons, consenting
pilots and Phase 4 remain open. No cloud inference or external target was used.
