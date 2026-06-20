"""Tests for NeuralStrike utils (validation, logging/redaction)."""

from __future__ import annotations

import logging

import pytest

from neuralstrike.core.exceptions import ValidationError
from neuralstrike.utils.logging import RedactingFilter, configure_logging
from neuralstrike.utils.validation import (
    validate_iteration_bounds,
    validate_port,
    validate_target_model,
    validate_url,
)


class TestValidation:
    def test_validate_url_accepts_http(self) -> None:
        assert validate_url("http://localhost:11434") == "http://localhost:11434"

    def test_validate_url_accepts_https(self) -> None:
        assert validate_url("https://api.example.com").startswith("https://")

    @pytest.mark.parametrize("bad", ["ftp://x", "file:///etc/passwd", "javascript:alert(1)", "gpt-4"])
    def test_validate_url_rejects_bad_scheme(self, bad: str) -> None:
        with pytest.raises(ValidationError):
            validate_url(bad)

    def test_validate_url_rejects_empty(self) -> None:
        with pytest.raises(ValidationError):
            validate_url("   ")

    def test_validate_url_rejects_no_host(self) -> None:
        with pytest.raises(ValidationError):
            validate_url("http://")

    @pytest.mark.parametrize("port", [0, -1, 70000, 65536])
    def test_validate_port_rejects_out_of_range(self, port: int) -> None:
        with pytest.raises(ValidationError):
            validate_port(port)

    def test_validate_port_accepts_range(self) -> None:
        assert validate_port(1) == 1
        assert validate_port(65535) == 65535

    def test_validate_iteration_bounds(self) -> None:
        assert validate_iteration_bounds(1) == 1
        assert validate_iteration_bounds(100) == 100
        with pytest.raises(ValidationError):
            validate_iteration_bounds(0)
        with pytest.raises(ValidationError):
            validate_iteration_bounds(101)

    def test_validate_target_model_rejects_empty(self) -> None:
        with pytest.raises(ValidationError):
            validate_target_model("")
        with pytest.raises(ValidationError):
            validate_target_model(None)  # type: ignore[arg-type]
        assert validate_target_model("gpt-4") == "gpt-4"


class TestRedactingFilter:
    def test_redacts_openai_key(self) -> None:
        filt = RedactingFilter(enabled=True)
        record = logging.LogRecord("x", logging.INFO, "", 0, "key=sk-abc1234567890xyz", None, None)
        assert filt.filter(record)
        assert "sk-abc1234567890xyz" not in record.msg
        assert "[REDACTED]" in record.msg

    def test_redacts_bearer_token(self) -> None:
        filt = RedactingFilter(enabled=True)
        record = logging.LogRecord(
            "x", logging.INFO, "", 0, "Authorization: Bearer abcdefghijklmnop1234567890", None, None
        )
        filt.filter(record)
        assert "Bearer abcdefghijklmnop1234567890" not in record.msg

    def test_disabled_passes_through(self) -> None:
        filt = RedactingFilter(enabled=False)
        record = logging.LogRecord("x", logging.INFO, "", 0, "sk-abc1234567890xyz", None, None)
        filt.filter(record)
        assert record.msg == "sk-abc1234567890xyz"

    def test_configure_logging_idempotent(self) -> None:
        configure_logging()
        before = len(logging.getLogger().handlers)
        configure_logging()
        assert len(logging.getLogger().handlers) == before
