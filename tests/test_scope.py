"""Tests for scope / rules-of-engagement validation."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from neuralstrike.core.exceptions import ValidationError
from neuralstrike.scope import Scope, load_scope


class TestScopeRules:
    def test_default_rule_allows_anything(self) -> None:
        s = Scope.in_scope_defaults()
        assert s.allows("http://anything.example")

    def test_target_must_match_in_scope(self) -> None:
        s = Scope.in_scope_only("localhost:*")
        assert s.allows("localhost:11434")
        assert not s.allows("https://prod.example.com")

    def test_exclusion_overrules_in_scope(self) -> None:
        s = Scope.with_exclusions("*", "prod.example.com")
        assert not s.allows("prod.example.com")

    def test_intent_filter(self) -> None:
        s = Scope.with_intents("*", ["canary-leak", "data-exfil"])
        assert s.allows("http://x", "canary-leak")
        assert not s.allows("http://x", "destructive")

    def test_testing_window(self) -> None:
        s = Scope.with_window("*", datetime(2026, 1, 1, tzinfo=timezone.utc), datetime(2026, 12, 31, tzinfo=timezone.utc))
        now = datetime(2026, 7, 1, tzinfo=timezone.utc)
        assert s.allows("http://x", now=now)
        assert not s.allows("http://x", now=datetime(2025, 1, 1, tzinfo=timezone.utc))

    def test_assert_allows_raises_outside_scope(self) -> None:
        s = Scope.in_scope_only("localhost:*")
        with pytest.raises(ValidationError, match="not in scope"):
            s.assert_allows("https://prod.example.com")

    def test_assert_allows_raises_excluded_intent(self) -> None:
        s = Scope.with_excluded_intents("*", "destructive")
        with pytest.raises(ValidationError, match="excluded by scope"):
            s.assert_allows("http://x", "destructive")

    def test_assert_allows_passes_in_scope(self) -> None:
        s = Scope.in_scope_only("*")
        s.assert_allows("http://x", "canary-leak")


class TestLoadScope:
    def test_load_yaml(self, tmp_path: Path) -> None:
        path = tmp_path / "scope.yaml"
        path.write_text(yaml.safe_dump({"in_scope": {"targets": ["localhost:*"], "intents": ["canary-leak"]}}))
        s = load_scope(path)
        assert s.allows("localhost:11434", "canary-leak")

    def test_load_json(self, tmp_path: Path) -> None:
        path = tmp_path / "scope.json"
        path.write_text(json.dumps({"in_scope": {"targets": ["https://test.example.com"], "intents": ["*"]}}))
        s = load_scope(path)
        assert s.allows("https://test.example.com", "anything")

    def test_load_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(ValidationError, match="not found"):
            load_scope(tmp_path / "missing.yaml")

    def test_load_unsupported_extension(self, tmp_path: Path) -> None:
        path = tmp_path / "scope.txt"
        path.write_text("in_scope:")
        with pytest.raises(ValidationError, match=r"must be \.yaml/\.yml/\.json"):
            load_scope(path)

    def test_testing_window_from_yaml(self, tmp_path: Path) -> None:
        path = tmp_path / "scope.yaml"
        path.write_text(
            yaml.safe_dump(
                {
                    "in_scope": {"targets": ["*"], "intents": ["*"]},
                    "testing_window": {"start": "2026-01-01T00:00:00Z", "end": "2026-12-31T23:59:59Z"},
                }
            )
        )
        s = load_scope(path)
        assert s.allows("http://x", now=datetime(2026, 6, 1, tzinfo=timezone.utc))


# Convenience constructors for tests (kept minimal to avoid polluting the public API).


def _scope(
    in_scope: str | list[str],
    intents: str | list[str] | None = None,
    exclusions: str | list[str] | None = None,
    exclusion_intents: str | list[str] | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
) -> Scope:
    from neuralstrike.scope.scope import ScopeRule
    return Scope(
        in_scope=ScopeRule.from_obj(in_scope),
        intents=ScopeRule.from_obj(intents),
        exclusions=ScopeRule.from_obj(exclusions),
        exclusion_intents=ScopeRule.from_obj(exclusion_intents),
        start=start,
        end=end,
        raw={},
    )


# Monkey-patch convenience constructors onto Scope for test use only.
Scope.in_scope_defaults = classmethod(lambda cls: _scope("*", "*"))
Scope.in_scope_only = classmethod(lambda cls, pat: _scope(pat, "*"))
Scope.with_intents = classmethod(lambda cls, pat, intents: _scope(pat, intents))
Scope.with_exclusions = classmethod(lambda cls, pat, excl: _scope(pat, "*", excl))
Scope.with_excluded_intents = classmethod(lambda cls, pat, excl_intent: _scope(pat, "*", exclusion_intents=excl_intent))
Scope.with_window = classmethod(lambda cls, pat, start, end: _scope(pat, "*", start=start, end=end))
