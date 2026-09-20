"""SecurityScarletAI SIEM producer — the red-team exercise telemetry pipe.

Fleet Wave 2 (2026-09-20): the offensive third of the local stack reports
PLANNED, AUTHORIZED exercises through Scarlet's ``POST /api/v1/ingest`` so
the SIEM sees the exercise, its probe verdicts, and (via NeuralGuard's own
fan-out, keyed on the run-scoped tenant) the firewall verdicts the same
payloads drove through the firewall. The purple-report join walks that
window (Wave 3).

**Doctrine (mirrors NeuralGuard's P2-7 SIEM routing):** telemetry is
OBSERVABILITY, never a control.

- A dead/unreachable/misconfigured SIEM is logged and counted, NEVER
  raised into the attack run. ``post_events`` returns ``False``; callers
  decide nothing with it.
- Opt-in: telemetry is OFF unless a Scarlet ingest URL + token are
  configured (CLI flags or ``NEURALSTRIKE_SCARLETAI_*`` env).
- Canary token VALUES never leave this process — the exercise's canaries
  are scored locally and the local run receipt holds the mapping. SIEM
  events carry verdicts and ids, never payload canaries.
- Tokens are held server-side and never logged (pinned by test).

**Event contract (SecurityScarletAI ``IngestEvent``, verified against
``src/api/ingest.py`` + ``src/ingestion/schemas.py`` 2026-09-20):**

- ``source`` = ``neuralstrike``, ``event_category`` = ``ai`` (the closed
  vocabulary's red-team exercise family, registered 2026-09-20 as a
  reviewed per-token decision: ``exercise_start`` / ``exercise_end`` /
  ``probe_succeeded`` / ``probe_resisted`` / ``probe_inconclusive``).
- ``event_type`` = ``start`` (lifecycle begin) / ``end`` (lifecycle end) /
  ``info`` (probes) — all three legal for the ``ai`` category.
- ``severity`` — ``probe_succeeded`` maps ``high`` (a red-team attack
  SUCCEEDED against the target under test; with the firewall in path this
  is defense-gap evidence); every other family event maps ``info``
  (lifecycle bookends and coverage data are not incidents).
- ``user_name`` = the exercise ACTOR (operator/tenant slot per Scarlet's
  ai_usage convention — the join key with NeuralGuard's verdict events is
  user_name + the exercise window).
- ``process_name`` = the NeuralStrike module (the free-form per-rule
  grouping dimension; ``payload_id`` rides raw_data).
- ``raw_data`` = chain of custody (run id, payload id, phase, module,
  firewall family, verdicts, OWASP/ATLAS ids) — NOT Sigma-selectable; the
  flat columns above are the rule surface.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx

from neuralstrike.integrations.attack_chain import canonical_attack_chain
from neuralstrike.utils.logging import get_logger

__all__ = [
    "SCARLETAI_SOURCE",
    "ExerciseTelemetry",
    "build_exercise_end_event",
    "build_exercise_start_event",
    "build_probe_event",
    "post_events",
]

logger = get_logger("neuralstrike.integrations.scarletai")

SCARLETAI_SOURCE = "neuralstrike"
_EXERCISE_CATEGORY = "ai"

# ScarletAI IngestEvent field caps (src/api/ingest.py, verified 2026-09-20).
_HOST_CAP = 253
_ACTOR_CAP = 256
_PROCESS_CAP = 256

# Probe verdict → IngestEvent severity. Only a SUCCEEDED probe is alert-grade
# (a red-team success against deployed controls); everything else is coverage
# data, never an incident.
_PROBE_SEVERITY = {
    "SUCCEEDED": "high",
    "RESISTED": "info",
    "INCONCLUSIVE": "info",
}

_VERDICT_TO_ACTION = {
    "SUCCEEDED": "probe_succeeded",
    "RESISTED": "probe_resisted",
    "INCONCLUSIVE": "probe_inconclusive",
}


def _sanitize_host(host: str) -> str:
    """Strip control characters (Scarlet's own hostname sanitizer semantics)."""
    return "".join(c for c in host if c.isprintable() and c not in "\n\r\t")[:_HOST_CAP]


def _cap(value: str | None, cap: int) -> str | None:
    if value is None:
        return None
    return value[:cap]


@dataclass(frozen=True)
class ExerciseTelemetry:
    """The ScarletAI exercise telemetry configuration (opt-in).

    ``ingest_url`` is the FULL ingest endpoint (e.g.
    ``http://localhost:8000/api/v1/ingest`` — the same knob semantics as
    NeuralGuard's ``NEURALGUARD_SIEM_SCARLETAI_URL``). ``run_host`` is the
    run-scoped hostname stamped on every exercise event
    (``neuralstrike-<runid>``) — the ILIKE-friendly join key for the
    purple-report's alert lookup. ``actor`` rides ``user_name`` (the
    attribution join key with NeuralGuard's tenant-mapped verdict events).
    """

    ingest_url: str
    token: str
    run_host: str
    actor: str = "neuralstrike-operator"
    timeout: float = 10.0

    def __post_init__(self) -> None:
        if not self.ingest_url.startswith(("http://", "https://")):
            raise ValueError(f"ingest_url must be http(s)://, got {self.ingest_url!r}")
        if not self.token:
            raise ValueError("token must be non-empty (the scoped INGEST_BEARER_TOKEN)")


def _base_event(
    config: ExerciseTelemetry,
    *,
    event_type: str,
    event_action: str,
    severity: str,
    timestamp: datetime,
) -> dict[str, Any]:
    """The common IngestEvent skeleton (exact verified field shape)."""
    return {
        "@timestamp": timestamp.isoformat(),
        "host_name": _sanitize_host(config.run_host),
        "source": SCARLETAI_SOURCE,
        "event_category": _EXERCISE_CATEGORY,
        "event_type": event_type,
        "event_action": event_action,
        "severity": severity,
        "user_name": _cap(config.actor, _ACTOR_CAP),
        "process_name": None,
        "raw_data": {},
    }


def build_exercise_start_event(
    config: ExerciseTelemetry,
    *,
    timestamp: datetime | None = None,
    target: str = "",
    screen: str = "",
    n_payloads: int = 0,
    seed: int = 0,
) -> dict[str, Any]:
    """The ``exercise_start`` bookend — one per exercise, emitted BEFORE the
    chain runs (a start without a matching end is the honest crashed-exercise
    signal)."""
    ts = timestamp or datetime.now(timezone.utc)
    event = _base_event(
        config, event_type="start", event_action="exercise_start", severity="info", timestamp=ts
    )
    event["raw_data"] = {
        "neuralstrike": {
            "kind": "exercise_start",
            "actor": config.actor,
            "target": target,
            "screen": screen,
            "n_payloads": n_payloads,
            "seed": seed,
        }
    }
    return event


def build_exercise_end_event(
    config: ExerciseTelemetry,
    *,
    timestamp: datetime | None = None,
    summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The ``exercise_end`` bookend — the final ASRs + delta + catch rate ride
    raw_data (chain of custody; the purple report's local truth)."""
    ts = timestamp or datetime.now(timezone.utc)
    event = _base_event(config, event_type="end", event_action="exercise_end", severity="info", timestamp=ts)
    event["raw_data"] = {
        "neuralstrike": {"kind": "exercise_end", "actor": config.actor, "summary": summary or {}}
    }
    return event


def build_probe_event(
    config: ExerciseTelemetry,
    *,
    payload_id: str,
    phase: str,
    module: str,
    family: str,
    verdict: str,
    fidelity: str = "",
    firewall_verdict: str = "",
    timestamp: datetime | None = None,
) -> dict[str, Any]:
    """One probe result as an ``ai``-category exercise event.

    ``verdict`` is the runner's conclusive-only verdict value (SUCCEEDED /
    RESISTED / INCONCLUSIVE) → the closed probe_* token + severity ladder
    (succeeded = high — defense-gap evidence; resisted/inconclusive = info).
    ``module`` rides ``process_name`` (the free-form per-rule grouping
    dimension); ``payload_id``, the mapped NeuralGuard family, and both arm
    verdicts ride raw_data. Canary VALUES are never carried.
    """
    action = _VERDICT_TO_ACTION.get(verdict.upper())
    if action is None:
        # Fail-closed: an unknown verdict must not silently become a guessed
        # token. The caller's mapping is the contract; this is defensive depth.
        raise ValueError(f"unknown probe verdict {verdict!r} — no closed exercise token")
    ts = timestamp or datetime.now(timezone.utc)
    event = _base_event(
        config,
        event_type="info",
        event_action=action,
        severity=_PROBE_SEVERITY[verdict.upper()],
        timestamp=ts,
    )
    event["process_name"] = _cap(module, _PROCESS_CAP)
    event["raw_data"] = {
        "neuralstrike": {
            "kind": action,
            "actor": config.actor,
            "payload_id": payload_id,
            "phase": phase,
            "module": module,
            "neuralguard_family": family,
            "firewall_verdict": firewall_verdict,
            "fidelity": fidelity,
        }
    }
    return event


def build_exercise_events(
    config: ExerciseTelemetry,
    delta: Any,
    *,
    started_at: datetime,
    target: str = "",
    seed: int = 0,
) -> list[dict[str, Any]]:
    """The complete post-run batch: ``exercise_end`` + one ``probe_*`` per
    payload (the ``exercise_start`` event is posted separately at the
    exercise's begin, so a crashed exercise leaves an honest open window).

    Mapping is pure and total: every ``PayloadArmResult`` yields exactly one
    event; a mapping failure logs and degrades to dropping THAT event, never
    raising into the run (telemetry never affects verdicts).
    """
    events: list[dict[str, Any]] = []
    # payload_id -> (module, NeuralGuard family) from the canonical chain —
    # PayloadArmResult carries ids only; the module/family tags make the SIEM
    # events groupable per attack module (the process_name dimension).
    chain_meta = {p.id: (p.neuralstrike_module, p.neuralguard_family) for p in canonical_attack_chain()}
    for arm in delta.payloads:
        module, family = chain_meta.get(arm.payload_id, (arm.phase.value, ""))
        try:
            events.append(
                build_probe_event(
                    config,
                    payload_id=arm.payload_id,
                    phase=arm.phase.value,
                    module=module,
                    family=family,
                    verdict=arm.defended_verdict.value,
                    firewall_verdict=arm.firewall_verdict,
                )
            )
        except Exception as exc:  # pragma: no cover — mapping of a typed model
            logger.warning("scarletai_probe_event_build_failed %s %s", arm.payload_id, exc.__class__.__name__)
    events.append(
        build_exercise_end_event(
            config,
            summary={
                "screen": delta.screen,
                "victim": delta.victim,
                "n": delta.n,
                "baseline_asr": delta.baseline_asr,
                "defended_asr": delta.defended_asr,
                "delta": delta.delta,
                "firewall_caught": delta.firewall_caught,
                "catch_rate": delta.catch_rate,
                "target": target,
                "seed": seed,
            },
        )
    )
    return events


async def post_events(
    ingest_url: str,
    token: str,
    events: list[dict[str, Any]],
    *,
    timeout: float = 10.0,
    transport: httpx.AsyncBaseTransport | None = None,
) -> bool:
    """POST one batch of IngestEvent dicts to Scarlet's ingest endpoint.

    **Best-effort, fail-soft:** a transport error, non-2xx status, or
    malformed response is logged and counted, and ``False`` is returned —
    never raised. A dead SIEM must never fail an exercise or change a
    verdict (the P2-7 doctrine mirrored from NeuralGuard's SIEM router).
    The batch is bounded by the caller (the exercise emits ≤ ~n+2 events,
    far under Scarlet's 1000-event cap; a defensive chunk-split keeps any
    future caller safe).
    """
    if not events:
        return True  # nothing to deliver is a no-op success, not an error
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    try:
        async with httpx.AsyncClient(timeout=timeout, transport=transport) as client:
            resp = await client.post(ingest_url, json=events, headers=headers)
        if resp.status_code != 202:
            logger.warning("scarletai_ingest_non_2xx status=%s n_events=%d", resp.status_code, len(events))
            return False
        accepted = None
        try:
            body = resp.json()
            accepted = body.get("accepted") if isinstance(body, dict) else None
        except ValueError:
            pass
        logger.info(
            "scarletai_ingest_delivered url=%s n_events=%s accepted=%s",
            ingest_url,
            len(events),
            accepted,
        )
        return True
    except httpx.HTTPError as exc:
        logger.warning("scarletai_ingest_transport_error %s", exc.__class__.__name__)
        return False
    except Exception as exc:  # pragma: no cover — defensive depth on unexpected shapes
        logger.warning("scarletai_ingest_unexpected_error %s", exc.__class__.__name__)
        return False
