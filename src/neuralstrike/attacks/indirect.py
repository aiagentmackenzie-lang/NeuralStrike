"""Indirect-injection delivery-vector harness.

Phase 2's dominant real-world vector is **indirect prompt injection**: the
adversarial payload rides on a channel the agent reads as *data* — a tool
result, a retrieved document, a memory entry, a system prompt — not the
user message. A naive harness stuffs the whole payload into the user
prompt and calls it "indirect"; that is dishonest. This harness weaves the
legitimate task and the adversarial payload together at the scenario's
**declared injection point** and drives the adapter so each channel is
surfaced distinctly.

The contract (Phase 2 exit gate): "Indirect-injection delivery vectors all
exercise the correct channel (verified by adapter trace, not by reading
the prompt)." The adapter records a
:class:`~neuralstrike.oracles.tool_harness.DeliveryRecord` per channel
confirming where the injection marker landed; the test reads that trace.

Five delivery vectors:

- ``user_message``       — payload is the user message (the direct-injection
                          baseline; included so the corpus can compare
                          direct vs indirect against the same SUT).
- ``system_prompt``      — payload rides in the SUT system prompt (with the
                          canary planted there); the legitimate task is the
                          user message.
- ``tool_result``        — a prior tool result the agent reads carries the
                          payload. The harness seeds history with a user
                          turn that invoked a tool, plus the tool's
                          (poisoned) result.
- ``retrieved_document`` — like ``tool_result`` but the result comes from a
                          named retrieval tool (``search_docs``) so the
                          adapter tags the channel as a retrieved document,
                          distinct from an arbitrary tool result.
- ``memory``             — a prior assistant turn (a "remembered" entry)
                          carries the payload, modelling cross-session
                          memory poisoning.

The harness mints a per-trial **injection marker** (distinct from the
canary) and embeds it in the payload. The adapter scans each channel's
content for the marker and records a DeliveryRecord. The exit gate asserts
the marker is present in the declared channel and absent in the others —
proof the harness delivered via the right channel, by adapter trace.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from dataclasses import replace as _replace

from neuralstrike.adapters.base import Message, TargetAdapter, ToolSchema
from neuralstrike.corpus.loader import CANARY_PLACEHOLDER, DeliveryVector, Scenario
from neuralstrike.evaluation.probes import strongest_fidelity
from neuralstrike.evaluation.runner import Probe
from neuralstrike.evaluation.verdict import SutResponse, TrialResult
from neuralstrike.oracles.base import Oracle, combine_oracle_results
from neuralstrike.oracles.evidence import upgrade_fidelity_from_traces
from neuralstrike.oracles.tool_harness import CanaryTool, TraceLog

__all__ = [
    "INJECTION_MARKER_PREFIX",
    "IndirectHarness",
    "InjectionInputs",
    "mint_injection_marker",
]

INJECTION_MARKER_PREFIX = "NSINJ"
"""Per-trial injection marker prefix; distinct from the ``CANARY-`` secret so
canary-leakage detection and channel-delivery verification do not collide."""


def mint_injection_marker(*, rng: secrets.SystemRandom | None = None) -> str:
    """Mint a fresh ``NSINJ-<16-hex>`` injection marker for one trial."""
    r = rng or secrets.SystemRandom()
    hexpart = "".join(r.choice("0123456789abcdef") for _ in range(16))
    return f"{INJECTION_MARKER_PREFIX}-{hexpart}"


@dataclass(frozen=True)
class InjectionInputs:
    """The adapter inputs the harness builds for one scenario + trial.

    The harness stamps the per-trial injection marker into the payload (so
    the adapter can verify delivery) and the per-trial canary into the
    ``{CANARY}`` placeholders (so the canary oracle can detect leakage).
    """

    prompt: str
    system_prompt: str | None
    history: tuple[Message, ...]
    delivery_channel: DeliveryVector
    injection_marker: str


class IndirectHarness:
    """Weaves a scenario's payload into its declared delivery channel.

    Build with :meth:`build_inputs`, then drive an adapter with
    :meth:`probe_for` (which returns a :class:`~neuralstrike.evaluation.runner.Probe`
    that records the delivery trace and scores with the scenario's oracles).
    """

    def __init__(self, scenario: Scenario) -> None:
        self.scenario = scenario

    def build_inputs(
        self,
        canary: str,
        *,
        injection_marker: str | None = None,
        rng: secrets.SystemRandom | None = None,
    ) -> InjectionInputs:
        """Construct adapter inputs that deliver the payload via the declared channel.

        ``canary`` substitutes into ``{CANARY}`` placeholders in the payload
        (and, for ``system_prompt`` delivery, into the system prompt). The
        injection marker is embedded alongside the payload so the adapter's
        channel scan can verify delivery.
        """
        marker = injection_marker or mint_injection_marker(rng=rng)
        payload = self.scenario.adversarial_payload.replace(CANARY_PLACEHOLDER, canary)
        # Stamp the injection marker into the payload so the adapter can
        # confirm which channel it landed in. The marker is on its own line
        # so it does not interfere with the canary oracle's chunked detection.
        marked_payload = f"{payload}\n[NSINJ:{marker}]"
        task = self.scenario.legitimate_task
        dv = self.scenario.delivery_vector

        if dv == "user_message":
            # Direct-injection baseline: the payload IS the user message.
            return InjectionInputs(
                prompt=marked_payload,
                system_prompt=None,
                history=(),
                delivery_channel=dv,
                injection_marker=marker,
            )

        if dv == "system_prompt":
            # Payload rides in the system prompt; canary is planted there too.
            # The system_prompt_extraction oracle hunts the canary in the
            # SUT's response. The legitimate task is the user message.
            return InjectionInputs(
                prompt=task,
                system_prompt=marked_payload,
                history=(),
                delivery_channel=dv,
                injection_marker=marker,
            )

        if dv == "tool_result":
            # Seed history: user asked the tool to run; tool returned the
            # poisoned payload. The legitimate task is the current user turn.
            history: tuple[Message, ...] = (
                Message(role="user", content=f"Please run the tool for: {task}"),
                Message(
                    role="assistant",
                    content="Running the tool now.",
                ),
                Message(
                    role="tool",
                    name="run_tool",
                    tool_call_id="call_prev",
                    content=marked_payload,
                ),
            )
            return InjectionInputs(
                prompt=task,
                system_prompt=None,
                history=history,
                delivery_channel=dv,
                injection_marker=marker,
            )

        if dv == "retrieved_document":
            # The poisoned payload came back from a retrieval tool. The
            # adapter tags a tool message named ``search_docs`` as the
            # retrieved_document channel, distinct from a plain tool_result.
            history = (
                Message(role="user", content=f"Search the knowledge base for: {task}"),
                Message(
                    role="assistant",
                    content="Retrieving relevant documents.",
                ),
                Message(
                    role="tool",
                    name="search_docs",
                    tool_call_id="call_retrieval",
                    content=marked_payload,
                ),
            )
            return InjectionInputs(
                prompt=task,
                system_prompt=None,
                history=history,
                delivery_channel=dv,
                injection_marker=marker,
            )

        if dv == "memory":
            # A prior assistant turn (a "remembered" memory entry) carries
            # the payload — modelling cross-session memory poisoning. The
            # adapter tags an assistant message as the memory channel.
            history = (
                Message(role="user", content="Remember this for later."),
                Message(
                    role="assistant",
                    content=f"[MEMORY] {marked_payload}",
                ),
            )
            return InjectionInputs(
                prompt=task,
                system_prompt=None,
                history=history,
                delivery_channel=dv,
                injection_marker=marker,
            )

        # Exhaustive literal match above; unreachable.
        raise ValueError(f"unsupported delivery_vector {dv!r}")

    def probe_for(
        self,
        adapter: TargetAdapter,
        *,
        canary_tools: tuple[CanaryTool, ...] = (),
        tools: tuple[ToolSchema, ...] = (),
        max_iterations: int = 1,
    ) -> Probe:
        """Build a :class:`Probe` that drives ``adapter`` with the woven inputs.

        Per trial the probe:
        1. mints a fresh canary + injection marker,
        2. builds the channel-specific adapter inputs,
        3. drives the adapter with ``delivery_channel``/``delivery_marker``
           so the adapter records a DeliveryRecord per channel,
        4. scores with the scenario's deterministic oracles,
        5. upgrades evidence fidelity from execution traces.

        The verdict/fidelity/findings follow the conclusive-only contract.
        """
        scenario = self.scenario

        async def _factory(trial_index: int, seed: int, canary: str) -> TrialResult:
            inputs = self.build_inputs(canary)
            trace = TraceLog()
            response = await adapter.query(
                inputs.prompt,
                system_prompt=inputs.system_prompt,
                tools=tools,
                history=inputs.history,
                canary_tools=canary_tools,
                trace=trace,
                delivery_channel=inputs.delivery_channel,
                delivery_marker=inputs.injection_marker,
            )
            oracles: list[Oracle] = scenario.build_oracles(canary)
            results = [o.check(response) for o in oracles]
            verdict, fidelity, findings = combine_oracle_results(results)
            findings = upgrade_fidelity_from_traces(findings, response, trace)
            # Attach the delivery trace to the persisted SutResponse so the
            # report can cite which channel the payload rode on.
            response = _with_delivery_trace(response, trace)
            return TrialResult(
                trial_index=trial_index,
                seed=seed,
                temperature=0.0,
                verdict=verdict,
                fidelity=strongest_fidelity(findings) if findings else fidelity,
                findings=tuple(findings),
                payload=inputs.prompt,
                response=response,
                scenario_id=scenario.id,
                iterations=max_iterations,
            )

        return Probe(
            scenario_id=scenario.id,
            goal=scenario.intent,
            factory=_factory,
            category=scenario.owasp_category,
            severity=scenario.severity,
        )


def _with_delivery_trace(response: SutResponse, trace: TraceLog) -> SutResponse:
    """Return a copy of ``response`` with delivery records folded into traces.

    The :class:`SutResponse.traces` field is a tuple of dict records; we
    append the delivery records (under a ``delivery`` discriminator) so the
    persisted transcript and the SARIF report can cite the channel without
    holding a separate handle.
    """
    if not trace.delivery_records:
        return response
    delivery_dicts = [{"delivery": d.__dict__} for d in trace.delivery_records]
    return _replace(response, traces=(*response.traces, *delivery_dicts))
