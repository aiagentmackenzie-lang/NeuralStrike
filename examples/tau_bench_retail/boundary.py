"""Fail-closed principal binding at the target's tool-dispatch boundary.

The target's tools take their own object identifier from the caller
(``user_id`` / ``order_id``). Nothing upstream checks that the identifier belongs to
the session principal. :class:`BoundDispatch` resolves the principal from
``env.task.user_id`` — the environment's own authenticated-customer field — and refuses
every scoped dispatch whose target resolves to a different owner.

Refusals are typed, journalled with a reason, returned to the model as the tool result
(so the native loop continues instead of terminating), and never mutate state. The
guard does not depend on the journal: it is a pure function of
``(principal, data, tool, kwargs)``. The target itself is not patched; only the bound
``env.step`` instance attribute is replaced.

Two layers, deliberately separable for the fail-closed test:

* :class:`RecordingDispatch` — pass-through recorder. Journal and state snapshots only.
  This is the unguarded baseline instrumentation.
* :class:`BoundDispatch` — adds :func:`decide`. Enforcement lives here, not in the
  recorder.

State is snapshotted *before* each dispatch because the native ``calculate_reward()``
destructively replaces ``env.data`` with a replay of the task's gold actions.
"""

from __future__ import annotations

import contextlib
import copy
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from examples.tau_bench_retail.profile import (
    GLOBAL_TOOLS,
    MUTATING_TOOLS,
    PASSTHROUGH_ACTIONS,
    TOOL_REGISTRY,
    atomic,
    digest,
    owner_of,
)

BOUNDARY = "tool_dispatch"
REASON_PRINCIPAL_UNRESOLVED = "principal_unresolved"
REASON_TARGET_UNKNOWN = "target_unknown"
REASON_CROSS_PRINCIPAL = "cross_principal"
REASON_TOOL_UNREGISTERED = "tool_unregistered"
REASONS = frozenset(
    {REASON_PRINCIPAL_UNRESOLVED, REASON_TARGET_UNKNOWN, REASON_CROSS_PRINCIPAL, REASON_TOOL_UNREGISTERED}
)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str | None
    tool: str
    scope: str | None = None
    identifier: str | None = None
    owner: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "tool": self.tool,
            "scope": self.scope,
            "identifier": self.identifier,
            "owner": self.owner,
        }


def resolve_principal(env: Any) -> str | None:
    """The session principal, taken from the environment's own task, never from a tool call."""
    task = getattr(env, "task", None)
    principal = getattr(task, "user_id", None)
    data = getattr(env, "data", None)
    if not isinstance(principal, str) or not principal or not isinstance(data, dict):
        return None
    users = data.get("users")
    if not isinstance(users, dict) or principal not in users:
        return None
    return principal


def decide(principal: str | None, data: Any, tool: str, kwargs: Any) -> Decision:
    """Pure, fail-closed authorisation decision. No I/O, no model, no journal."""
    if tool in PASSTHROUGH_ACTIONS or tool in GLOBAL_TOOLS:
        return Decision(True, None, tool)
    entry = TOOL_REGISTRY.get(tool)
    scope, argument = (entry[0], entry[1]) if entry is not None else (None, None)
    raw = kwargs.get(argument) if isinstance(kwargs, dict) and argument else None
    identifier = raw if isinstance(raw, str) and raw else None
    owner = owner_of(data, scope, identifier) if scope is not None else None
    reason = (
        REASON_TOOL_UNREGISTERED
        if entry is None
        else REASON_PRINCIPAL_UNRESOLVED
        if principal is None
        else REASON_TARGET_UNKNOWN
        if owner is None
        else REASON_CROSS_PRINCIPAL
        if owner != principal
        else None
    )
    return Decision(reason is None, reason, tool, scope, identifier, owner)


def refusal_payload(decision: Decision) -> dict[str, Any]:
    """Model-facing refusal. Names the rule, not the other principal's account."""
    return {
        "refused": True,
        "boundary": BOUNDARY,
        "reason": decision.reason,
        "tool": decision.tool,
        "scope": decision.scope,
        "target": decision.identifier,
        "detail": "the requested object is not owned by the authenticated session principal",
    }


def env_response(task: Any, tool: str, payload: dict[str, Any]) -> Any:
    from tau_bench.types import EnvInfo, EnvResponse  # noqa: PLC0415

    return EnvResponse(
        observation=json.dumps(payload, sort_keys=True),
        reward=0.0,
        done=False,
        info=EnvInfo(task=task, source=tool),
    )


class RecordingDispatch:
    """Pass-through recorder: no authority. Baseline instrumentation and journal."""

    def __init__(self, env: Any, journal_path: Path | None = None) -> None:
        self.env = env
        self.journal_path = journal_path
        self.native_step = env.step
        self.native_reset = env.reset
        self.native_calculate_reward = env.calculate_reward
        self.principal: str | None = resolve_principal(env)
        self.entries: list[dict[str, Any]] = []
        self.initial_state: dict[str, Any] = copy.deepcopy(getattr(env, "data", {}))
        self.last_settled: dict[str, Any] = copy.deepcopy(getattr(env, "data", {}))
        self.state_unresolved = False
        self.reward_replays = 0
        self.schema_digest = digest(env.tools_info)
        self.rewards: list[float] = []

    def reset(self, task_index: int | None = None) -> Any:
        response = self.native_reset(task_index=task_index)
        self.principal = resolve_principal(self.env)
        self.initial_state = copy.deepcopy(self.env.data)
        self.last_settled = copy.deepcopy(self.env.data)
        self.entries = []
        self.state_unresolved = False
        self.reward_replays = 0
        return response

    def step(self, action: Any) -> Any:
        before = copy.deepcopy(self.env.data)
        response = self.native_step(action)
        if response.done and getattr(action, "name", None) in MUTATING_TOOLS:
            self.state_unresolved = True
        elif not response.done:
            self.last_settled = copy.deepcopy(self.env.data)
        self._record(action, response, None, before)
        return response

    def calculate_reward(self) -> Any:
        """Native reward replay must not be observed or authorised as agent dispatch.

        ``Env.calculate_reward`` replaces ``env.data`` with a replay of the task's gold
        actions by calling ``self.step``. Left bound, that replay is recorded as if the
        agent had issued it, and post-state would be the gold state. The dispatcher is
        detached for the duration.
        """
        self.reward_replays += 1
        previous = self.env.step
        self.env.step = self.native_step
        try:
            return self.native_calculate_reward()
        finally:
            self.env.step = previous

    def _record(self, action: Any, response: Any, decision: Decision | None, before: Any) -> None:
        self.rewards.append(float(getattr(response, "reward", 0.0) or 0.0))
        entry = {
            "sequence": len(self.entries),
            "tool": getattr(action, "name", None),
            "kwargs": _plain(getattr(action, "kwargs", {})),
            "principal": self.principal,
            "allowed": True if decision is None else decision.allowed,
            "reason": None if decision is None else decision.reason,
            "boundary": None if decision is None else BOUNDARY,
            "observation": getattr(response, "observation", ""),
            "observation_digest": digest(str(getattr(response, "observation", ""))),
            "reward": float(getattr(response, "reward", 0.0) or 0.0),
            "done": bool(getattr(response, "done", False)),
            "state_before_digest": digest(before),
            "state_after_digest": digest(self.env.data) if not response.done else None,
        }
        if decision is not None and decision.owner is not None:
            entry["owner"] = decision.owner
        self.entries.append(entry)

    def flush(self, document: dict[str, Any]) -> None:
        if self.journal_path is not None:
            atomic(self.journal_path, document)


class BoundDispatch(RecordingDispatch):
    """RecordingDispatcher plus fail-closed principal binding."""

    def step(self, action: Any) -> Any:
        name = getattr(action, "name", None) or ""
        kwargs = getattr(action, "kwargs", {}) or {}
        decision = decide(self.principal, self.env.data, name, kwargs)
        if not decision.allowed:
            response = env_response(self.env.task, name, refusal_payload(decision))
            self._record(action, response, decision, copy.deepcopy(self.env.data))
            return response
        before = copy.deepcopy(self.env.data)
        response = self.native_step(action)
        if response.done and name in MUTATING_TOOLS:
            self.state_unresolved = True
        elif not response.done:
            self.last_settled = copy.deepcopy(self.env.data)
        self._record(action, response, decision, before)
        return response

    @property
    def refusals(self) -> list[dict[str, Any]]:
        return [entry for entry in self.entries if entry["reason"] is not None]


def _plain(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value, sort_keys=True))
    except TypeError:
        return {"unserialisable": type(value).__name__}


def install(env: Any, policy: str, journal_path: Path | None = None) -> RecordingDispatch:
    """Bind the declared policy onto one environment instance. Model-facing schema untouched."""
    if policy not in {"unfiltered", "bound"}:
        raise ValueError(f"unknown policy {policy!r}")
    dispatcher = (BoundDispatch if policy == "bound" else RecordingDispatch)(env, journal_path)
    env.step = dispatcher.step
    env.reset = dispatcher.reset
    env.calculate_reward = dispatcher.calculate_reward
    return dispatcher


def uninstall(env: Any) -> None:
    """Drop the instance bindings so the native methods resolve again."""
    for attribute in ("step", "reset", "calculate_reward"):
        with contextlib.suppress(AttributeError):
            delattr(env, attribute)
