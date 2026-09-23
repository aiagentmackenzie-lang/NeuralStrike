"""Purple-report — the detection-coverage join between an exercise receipt
and what the SIEM (SecurityScarletAI) actually saw.

Fleet Wave 3 (2026-09-20). After a telemetry-on exercise
(``neuralguard-bench --scarletai-url … --json-out receipt.json``), this
module re-reads the exercise window from Scarlet's VERIFIED read APIs and
joins it with the local run receipt:

- ``GET /api/v1/alerts`` — Sigma-rule alerts keyed on the run-stamped host
  (``host_name`` ILIKE filter) + a windowed walk of recent alerts for the
  NG-producer-rule alerts (their ``host_name`` is the firewall's, not the
  run's — attribution rides the time window).
- ``GET /api/v1/logs`` — flat log rows; partitioned client-side into the
  exercise's own events (``source=neuralstrike``, ``host_name`` = the
  run-stamped host) and the firewall verdict events the SAME exercise drove
  through NeuralGuard (``source=neuralguard``, ``user_name`` = the NG
  tenant the fleet key binds — see the fleet runbook; attribution is by
  ``user_name`` + window because /logs has no user_name filter).

The output is the DETECTION-COVERAGE report: X attacks, Y caught by NG
(with rule ids from the local receipt), Z Scarlet alerts fired, the
per-payload detected/undetected table, and the TREND vs the previous
exercise's receipt. **The undetected-Succeeded list is the real
defense-gap list** — attacks that passed the firewall AND beat the victim.

Trust posture (documented, deliberate): the read path uses the operator's
ADMIN-class Scarlet API token (``/alerts`` + ``/logs`` are read-only uses);
the scoped INGEST token CANNOT read (viewer-class, ingest-router-only by
design) — the purple-report is the same operator, no new credentials.

**Failure posture — deliberately DIFFERENT from the telemetry pipe:**
``post_events`` (the producer) is best-effort fail-soft because telemetry
must never fail a run. The purple-report is a REPORT command: a query
failure makes the report WRONG, and a silently-wrong report is worse than
no report — so every fetch raises on failure and the CLI exits non-zero.
Fail loud here, fail soft in the run.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from neuralstrike.utils.logging import get_logger

__all__ = [
    "PurpleReadConfig",
    "build_purple_report",
    "classify_payload_status",
    "fetch_alerts_for_run",
    "fetch_alerts_window",
    "fetch_logs_window",
    "partition_logs",
    "window_minutes_for",
]

# Scarlet read-API bounds (verified against src/api/alerts.py + logs.py):
# /alerts limit ≤1000, /logs limit ≤500. Pagination caps keep a runaway
# window from pinning memory; the fleet's exercise windows are small.
_ALERTS_PAGE = 1000
_LOGS_PAGE = 500

_NG_SOURCE = "neuralguard"
_NS_SOURCE = "neuralstrike"

# Per-payload status taxonomy (the honest four):
#   caught        — the firewall stopped the payload (verdict != allow/error/auth_error)
#   gap           — the payload passed the firewall AND beat the victim
#                    (defended verdict SUCCEEDED): THE defense-gap list
#   resisted      — the payload passed the firewall but the victim's oracle
#                    held (defense-in-depth win; the firewall missed it)
#   inconclusive  — unscoreable (blocked payloads under the conclusive-only
#                    contract, or a screen transport error)
_STATUS_CAUGHT = "caught"
_STATUS_GAP = "gap"
_STATUS_RESISTED = "resisted"
_STATUS_INCONCLUSIVE = "inconclusive"

logger = get_logger("neuralstrike.integrations.purple_report")


@dataclass(frozen=True)
class PurpleReadConfig:
    """The purple-report's Scarlet read configuration (OPT-IN).

    ``base_url`` is Scarlet's ROOT (e.g. ``http://localhost:8000``); the
    fetchers append the versioned read routes themselves. ``api_token`` is
    the ADMIN-class API bearer (never logged, pinned by test).
    """

    base_url: str
    api_token: str
    timeout: float = 15.0
    max_pages: int = 20

    def __post_init__(self) -> None:
        if not self.base_url.startswith(("http://", "https://")):
            raise ValueError(f"base_url must be http(s)://, got {self.base_url!r}")
        if not self.api_token:
            raise ValueError("api_token must be non-empty (Scarlet's admin-class API token)")
        if self.max_pages < 1:
            raise ValueError("max_pages must be >= 1")


def _headers(api_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_token}"}


def _parse_ts(value: object) -> datetime | None:
    """Parse the timestamp shapes the two read APIs emit (tolerant).

    Logs/alerts carry ``time`` / ``@timestamp`` as ISO text (the APIs
    isoformat datetimes for JSON). Returns None for anything unparseable —
    the caller decides whether that row is attributable (skipping an
    unparseable row in a REPORT is honest: it is never fabricated into an
    attribution; the raw rows ride the report).
    """
    if not isinstance(value, str) or not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


async def _get_paginated(
    config: PurpleReadConfig,
    path: str,
    params: dict[str, str | int],
    page_size: int,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> list[dict[str, Any]]:
    """Walk a read endpoint with offset pagination until a short page.

    LOUD failure contract: transport errors, non-2xx statuses, and malformed
    bodies raise (RuntimeError) — the caller is the report CLI, which must
    never present a partial report as complete.
    """
    rows: list[dict[str, Any]] = []
    offset = 0
    for _ in range(config.max_pages):
        page_params = dict(params)
        page_params["limit"] = page_size
        page_params["offset"] = offset
        try:
            async with httpx.AsyncClient(timeout=config.timeout, transport=transport) as client:
                logger.debug("scarlet_request %s offset=%d", path, offset)
                resp = await client.get(
                    f"{config.base_url.rstrip('/')}{path}",
                    params=page_params,
                    headers=_headers(config.api_token),
                )
        except httpx.HTTPError as exc:
            raise RuntimeError(
                f"scarlet read failed ({path}): transport error {exc.__class__.__name__}"
            ) from exc
        if resp.status_code != 200:
            raise RuntimeError(f"scarlet read failed ({path}): HTTP {resp.status_code}")
        try:
            page = resp.json()
        except ValueError as exc:
            raise RuntimeError(f"scarlet read failed ({path}): malformed JSON body") from exc
        if not isinstance(page, list):
            raise RuntimeError(
                f"scarlet read failed ({path}): expected a JSON array, got {type(page).__name__}"
            )
        rows.extend(row for row in page if isinstance(row, dict))
        if len(page) < page_size:
            return rows
        offset += page_size
    raise RuntimeError(
        f"scarlet read ({path}) hit the pagination cap ({config.max_pages} pages) — "
        "window too large or rows too many; narrow the window or raise the cap"
    )


async def fetch_alerts_for_run(
    config: PurpleReadConfig,
    run_host: str,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> list[dict[str, Any]]:
    """Alerts whose ``host_name`` matches the run-stamped host (ILIKE server-side)."""
    return await _get_paginated(
        config,
        "/api/v1/alerts",
        {"host_name": run_host},
        _ALERTS_PAGE,
        transport=transport,
    )


async def fetch_alerts_window(
    config: PurpleReadConfig,
    *,
    since: datetime,
    until: datetime,
    transport: httpx.AsyncBaseTransport | None = None,
) -> list[dict[str, Any]]:
    """Walk recent alerts (newest first) until older than ``since``.

    The alerts API has NO time filter — this pages ``time DESC`` and stops at
    the window edge, so the NG-producer-rule alerts (whose ``host_name`` is
    the firewall's, not the run's) are still attributed by TIME. Capped by
    ``max_pages`` (loud failure, like every read here).
    """
    rows = await _get_paginated(config, "/api/v1/alerts", {}, _ALERTS_PAGE, transport=transport)
    window: list[dict[str, Any]] = []
    for row in rows:
        ts = _parse_ts(row.get("time"))
        if ts is None:
            continue  # unattributable row — skipped, never fabricated
        if ts < since:
            break
        if ts <= until:
            window.append(row)
    return window


async def fetch_logs_window(
    config: PurpleReadConfig,
    *,
    minutes: int,
    transport: httpx.AsyncBaseTransport | None = None,
) -> list[dict[str, Any]]:
    """Logs from the last ``minutes`` minutes (the exercise window), paginated."""
    return await _get_paginated(
        config,
        "/api/v1/logs",
        {"time_minutes": max(1, int(minutes))},
        _LOGS_PAGE,
        transport=transport,
    )


def partition_logs(
    rows: list[dict[str, Any]],
    *,
    run_host: str,
    ng_tenant: str | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split windowed log rows into (exercise events, firewall verdict events).

    - exercise events: ``source=neuralstrike`` AND ``host_name`` EXACTLY the
      run-stamped host (a client-side exact match on top of the API's ILIKE
      fetch — a defensive tightening, not a guess).
    - firewall events: ``source=neuralguard`` AND — when the fleet's tenant
      is known — ``user_name`` equal to it (the actor slot NG's producer
      mapping fills from the tenant binding).
    """
    exercise = [r for r in rows if r.get("source") == _NS_SOURCE and r.get("host_name") == run_host]
    ng = [
        r
        for r in rows
        if r.get("source") == _NG_SOURCE and (ng_tenant is None or r.get("user_name") == ng_tenant)
    ]
    return exercise, ng


def classify_payload_status(firewall_verdict: str, defended_verdict: str) -> str:
    """The honest four-way status for one payload (see module docstring).

    Verdict comparisons are CASE-INSENSITIVE: the live-fire receipt found the
    enum values arrive lowercase (``succeeded``/``resisted``/``inconclusive``)
    while earlier fixtures assumed uppercase — the taxonomy must be robust to
    both (2026-09-20 fleet live-fire finding).
    """
    firewall = firewall_verdict.strip().lower()
    defended = defended_verdict.strip().lower()
    if firewall in ("error", "auth_error"):
        # A screen transport error is NOT a catch — never counted as one.
        # FT-001 (fleet Wave F): an NG auth/config rejection (auth_error)
        # is likewise a non-measurement — the firewall never evaluated
        # the payload, so it can hardly have stopped it.
        return _STATUS_INCONCLUSIVE
    if firewall != "allow":
        return _STATUS_CAUGHT
    if defended == "succeeded":
        return _STATUS_GAP
    if defended == "resisted":
        return _STATUS_RESISTED
    return _STATUS_INCONCLUSIVE


def _rule_ids(findings: object) -> list[str]:
    """Rule ids from the receipt's serialized ``firewall_rule_ids`` (strings).

    Tolerates the in-memory findings shape (list of dicts with rule_id) too —
    the receipt contract is the string list; the tuple-of-dicts form is what
    ``PayloadArmResult.firewall_findings`` carries before serialization.
    """
    if not isinstance(findings, (list, tuple)):
        return []
    ids: list[str] = []
    for f in findings:
        if isinstance(f, str):
            ids.append(f)
        elif isinstance(f, dict) and isinstance(f.get("rule_id"), str):
            ids.append(f["rule_id"])
    return ids


def _probe_event_per_payload(exercise_events: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Map payload_id → its Scarlet probe event (from raw_data chain-of-custody).

    ``raw_data`` may arrive as a JSON STRING (asyncpg's jsonb → text path in
    some drivers) or a dict — both are handled (found in fleet live-fire:
    the join was blind to string-encoded raw_data).
    """
    by_payload: dict[str, dict[str, Any]] = {}
    for row in exercise_events:
        raw = row.get("raw_data")
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except ValueError:
                raw = None
        inner = raw.get("neuralstrike") if isinstance(raw, dict) else None
        payload_id = inner.get("payload_id") if isinstance(inner, dict) else None
        if isinstance(payload_id, str) and payload_id:
            by_payload.setdefault(payload_id, row)
    return by_payload


def _probe_action(row: dict[str, Any] | None) -> str | None:
    """The closed event_action of a payload's Scarlet probe event (or None)."""
    if not isinstance(row, dict):
        return None
    action = row.get("event_action")
    return action if isinstance(action, str) else None


def _as_float(value: object) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    return None


def _trend(receipt: dict[str, Any], previous: dict[str, Any]) -> dict[str, Any]:
    """Coverage trend: this exercise vs the previous receipt."""
    rate = _as_float(receipt.get("catch_rate"))
    prev_rate = _as_float(previous.get("catch_rate"))
    return {
        "catch_rate": rate,
        "catch_rate_previous": prev_rate,
        "catch_rate_delta": (rate - prev_rate if (rate is not None and prev_rate is not None) else None),
        "firewall_caught": receipt.get("firewall_caught"),
        "firewall_caught_previous": previous.get("firewall_caught"),
    }


def build_purple_report(
    receipt: dict[str, Any],
    *,
    exercise_events: list[dict[str, Any]],
    ng_events: list[dict[str, Any]],
    run_alerts: list[dict[str, Any]],
    window_alerts: list[dict[str, Any]],
    ng_tenant: str | None = None,
    previous_receipt: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Join the local receipt with the SIEM side; emit the coverage report dict.

    Pure function — all fetches happen in the fetchers; this computes the
    join and the trend. Alert attribution: run-host alerts (the exercise
    rules) + window alerts (the NG-producer rules the SAME exercise drove);
    dedup by alert ``id``. A receipt without a run identity raises — the
    report must never be built from a telemetry-off receipt (there is no
    window to join against).
    """
    run = receipt.get("run")
    if not isinstance(run, dict):
        raise ValueError(
            "receipt has no run identity — purple-report needs a telemetry-on "
            "receipt (re-run the bench with --scarletai-url/--scarletai-token)"
        )

    exercise_actions: dict[str, int] = {}
    for row in exercise_events:
        action = row.get("event_action")
        if isinstance(action, str):
            exercise_actions[action] = exercise_actions.get(action, 0) + 1

    ng_actions: dict[str, int] = {}
    for row in ng_events:
        action = row.get("event_action")
        if isinstance(action, str):
            ng_actions[action] = ng_actions.get(action, 0) + 1

    probe_by_payload = _probe_event_per_payload(exercise_events)
    seen_alert_ids: set[object] = set()
    alerts_joined: list[dict[str, Any]] = []
    for row in [*run_alerts, *window_alerts]:
        alert_id = row.get("id")
        if alert_id in seen_alert_ids:
            continue
        seen_alert_ids.add(alert_id)
        alerts_joined.append(
            {
                "id": alert_id,
                "rule_name": row.get("rule_name"),
                "severity": row.get("severity"),
                "host_name": row.get("host_name"),
                "time": row.get("time"),
            }
        )

    payloads: list[dict[str, Any]] = []
    gap_payloads: list[str] = []
    for a in receipt.get("payloads", []):
        if not isinstance(a, dict):
            continue
        payload_id = a.get("id", a.get("payload_id"))
        firewall_verdict = str(a.get("firewall_verdict", ""))
        defended = str(a.get("defended_verdict", ""))
        status = classify_payload_status(firewall_verdict, defended)
        if status == _STATUS_GAP and isinstance(payload_id, str):
            gap_payloads.append(payload_id)
        probe_row = probe_by_payload.get(payload_id) if isinstance(payload_id, str) else None
        payloads.append(
            {
                "payload_id": payload_id,
                "phase": a.get("phase"),
                "firewall_verdict": firewall_verdict,
                "firewall_rule_ids": _rule_ids(a.get("firewall_rule_ids", a.get("firewall_findings"))),
                "defended_verdict": defended,
                "scarlet_probe_action": _probe_action(probe_row),
                "status": status,
            }
        )

    # Alert attribution (the standing fleet carries REAL production telemetry
    # — the window walk catches unrelated alerts; honesty demands they are
    # PARTITIONED, never silently attributed):
    #   exercise alerts — host_name ILIKE-matches the run-stamped host
    #   firewall alerts — the NG producer rules (host = the firewall's)
    #   window-coincident — everything else in the window (NOT attributed)
    exercise_alerts = [a for a in alerts_joined if a.get("host_name") == run.get("run_host")]
    firewall_alerts = [
        a
        for a in alerts_joined
        if a.get("host_name") != run.get("run_host")
        and isinstance(a.get("host_name"), str)
        and "neuralguard" in str(a.get("host_name")).lower()
    ]
    attributed_ids = {a.get("id") for a in exercise_alerts} | {a.get("id") for a in firewall_alerts}
    window_coincident = [a for a in alerts_joined if a.get("id") not in attributed_ids]

    report: dict[str, Any] = {
        "run": {
            "run_host": run.get("run_host"),
            "actor": run.get("actor"),
            "started_at": run.get("started_at"),
            "screen": receipt.get("screen"),
            "victim": receipt.get("victim"),
        },
        "attacks": {
            "n": receipt.get("n"),
            "firewall_caught": receipt.get("firewall_caught"),
            "catch_rate": receipt.get("catch_rate"),
            "defended_succeeded": receipt.get("defended_succeeded"),
            "defended_conclusive": receipt.get("defended_conclusive"),
        },
        "scarlet": {
            "exercise_events": exercise_actions,
            "firewall_events": ng_actions,
            "alerts": alerts_joined,
            "alert_count": len(alerts_joined),
            # Honest attribution split (standing-telemetry noise is REAL —
            # it just didn't come from this exercise):
            "exercise_alerts": exercise_alerts,
            "firewall_alerts": firewall_alerts,
            "window_coincident_alerts": window_coincident,
            "attributed_alert_count": len(exercise_alerts) + len(firewall_alerts),
        },
        "payloads": payloads,
        # THE gap list: payloads that passed the firewall AND beat the victim.
        "defense_gaps": gap_payloads,
        "gap_headline": (
            f"defense gaps: {len(gap_payloads)}/{len(payloads)} payloads passed "
            "the firewall AND succeeded against the victim"
        ),
    }
    if ng_tenant:
        report["run"]["ng_tenant"] = ng_tenant
    if previous_receipt is not None:
        report["trend"] = _trend(receipt, previous_receipt)
    return report


def window_minutes_for(started_at: datetime, *, grace_minutes: int, now: datetime | None = None) -> int:
    """The /logs ``time_minutes`` value covering [started_at - grace, now].

    ``delta`` already includes the grace (it is measured from the grace-extended
    start), so the value is ceil(delta minutes) + 1 for the inclusive edge.
    """
    now = now or datetime.now(timezone.utc)
    delta = now - (started_at - timedelta(minutes=grace_minutes))
    return max(1, int(delta.total_seconds() // 60) + 1)
