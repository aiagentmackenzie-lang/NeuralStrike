"""Scope file / rules-of-engagement validation.

Every attack should validate scope before running. Out-of-scope discoveries
are reported, never probed.
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from neuralstrike.core.exceptions import ValidationError


@dataclass(frozen=True)
class ScopeRule:
    """A single glob-style scope rule."""

    patterns: tuple[str, ...]

    @classmethod
    def from_obj(cls, obj: str | list[str] | None) -> ScopeRule:
        if obj is None:
            return cls(patterns=())
        if isinstance(obj, str):
            return cls(patterns=(obj.strip(),))
        return cls(patterns=tuple(str(p).strip() for p in obj if str(p).strip()))

    def matches(self, value: str) -> bool:
        if not self.patterns:
            return False
        return any(fnmatch.fnmatchcase(value, pat) for pat in self.patterns)


@dataclass(frozen=True)
class Scope:
    """Rules of engagement loaded from a scope file."""

    in_scope: ScopeRule
    intents: ScopeRule
    exclusions: ScopeRule
    exclusion_intents: ScopeRule
    start: datetime | None
    end: datetime | None
    raw: dict[str, Any]

    def allows(
        self,
        target: str,
        intent: str | None = None,
        *,
        now: datetime | None = None,
    ) -> bool:
        """Return True if target/intent are in scope and within the testing window."""
        target = target.strip()
        if self.exclusions.matches(target):
            return False
        if self.in_scope.patterns and not self.in_scope.matches(target):
            return False
        if intent is not None:
            intent = intent.strip()
            if self.exclusion_intents.patterns and self.exclusion_intents.matches(intent):
                return False
            if self.intents.patterns and not self.intents.matches(intent):
                return False
        if now is None:
            now = datetime.now(timezone.utc)
        before_start = self.start is not None and now < self.start
        after_end = self.end is not None and now > self.end
        return not (before_start or after_end)

    def assert_allows(self, target: str, intent: str | None = None, *, now: datetime | None = None) -> None:
        """Raise ValidationError with a clear reason when out of scope."""
        if self.allows(target, intent, now=now):
            return
        target = target.strip()
        if self.exclusions.matches(target):
            raise ValidationError(f"target {target!r} is explicitly excluded by scope")
        if self.in_scope.patterns and not self.in_scope.matches(target):
            raise ValidationError(
                f"target {target!r} is not in scope "
                f"(allowed patterns: {self.in_scope.patterns!r})"
            )
        if intent is not None:
            intent = intent.strip()
            if self.exclusion_intents.patterns and self.exclusion_intents.matches(intent):
                raise ValidationError(f"intent {intent!r} is explicitly excluded by scope")
            if self.intents.patterns and not self.intents.matches(intent):
                raise ValidationError(
                    f"intent {intent!r} is not in scope "
                    f"(allowed intents: {self.intents.patterns!r})"
                )
        now = now or datetime.now(timezone.utc)
        if self.start is not None and now < self.start:
            raise ValidationError(f"testing window has not started (start={self.start.isoformat()})")
        if self.end is not None and now > self.end:
            raise ValidationError(f"testing window has expired (end={self.end.isoformat()})")
        # Should be unreachable if allows is consistent.
        raise ValidationError(f"target {target!r} is out of scope")


def _parse_dt(value: str | datetime | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    # ISO-8601 strings; if no tz, assume UTC.
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def load_scope(path: str | Path) -> Scope:
    """Load a scope file (YAML or JSON)."""
    p = Path(path)
    if not p.is_file():
        raise ValidationError(f"scope file not found: {path}")
    text = p.read_text(encoding="utf-8")
    suffix = p.suffix.lower()
    if suffix in {".yaml", ".yml"}:
        raw = yaml.safe_load(text) or {}
    elif suffix == ".json":
        raw = json.loads(text)
    else:
        raise ValidationError(f"scope file must be .yaml/.yml/.json (got {suffix!r})")

    in_scope = raw.get("in_scope", {})
    exclusions = raw.get("exclusions", {})
    window = raw.get("testing_window", {})
    return Scope(
        in_scope=ScopeRule.from_obj(in_scope.get("targets")),
        intents=ScopeRule.from_obj(in_scope.get("intents")),
        exclusions=ScopeRule.from_obj(exclusions.get("targets")),
        exclusion_intents=ScopeRule.from_obj(exclusions.get("intents")),
        start=_parse_dt(window.get("start")),
        end=_parse_dt(window.get("end")),
        raw=raw,
    )
