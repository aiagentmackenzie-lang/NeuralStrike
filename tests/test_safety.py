"""Tests for operator-safety / HITL gating."""

from __future__ import annotations

import pytest

from neuralstrike.safety import ActionClass, HITLGate, SafetyError, classify_intent, ttl_for


class TestClassifyIntent:
    def test_empty_is_reversible(self) -> None:
        assert classify_intent(None) == ActionClass.REVERSIBLE
        assert classify_intent("") == ActionClass.REVERSIBLE

    def test_irreversible_keywords(self) -> None:
        assert classify_intent("delete_all_records") == ActionClass.IRREVERSIBLE
        assert classify_intent("exfil data") == ActionClass.IRREVERSIBLE
        assert classify_intent("transfer funds") == ActionClass.IRREVERSIBLE

    def test_compensable_keywords(self) -> None:
        assert classify_intent("grant admin access") == ActionClass.COMPENSABLE
        assert classify_intent("modify permissions") == ActionClass.COMPENSABLE

    def test_reversible_default(self) -> None:
        assert classify_intent("canary leak probe") == ActionClass.REVERSIBLE


class TestTTL:
    def test_ttl_values(self) -> None:
        assert ttl_for(ActionClass.REVERSIBLE) == 60
        assert ttl_for(ActionClass.COMPENSABLE) == 300
        assert ttl_for(ActionClass.IRREVERSIBLE) == 0


class TestHITLGate:
    def test_reversible_never_blocks(self) -> None:
        HITLGate(ActionClass.REVERSIBLE, approved=False).assert_approved()

    def test_irreversible_without_approval_blocks(self) -> None:
        gate = HITLGate(ActionClass.IRREVERSIBLE, intent="delete_database", approved=False)
        with pytest.raises(SafetyError, match="requires --require-approval"):
            gate.assert_approved()

    def test_irreversible_with_approval_passes(self) -> None:
        HITLGate(ActionClass.IRREVERSIBLE, approved=True).assert_approved()

    def test_summary(self) -> None:
        gate = HITLGate(ActionClass.COMPENSABLE, intent="grant", approved=True)
        assert gate.summary()["ttl_seconds"] == 300
        assert gate.summary()["action_class"] == "compensable"
