"""Logging setup with credential-shaped-string redaction.

Configured once at the CLI entry point. Library modules should only call
:func:`get_logger`; never call ``logging.basicConfig`` outside the entry point.
"""

from __future__ import annotations

import logging
import re
from typing import Final

from neuralstrike.core.config import settings

# Patterns that look like credentials. Conservative — false positives only
# redact log content, they do not block operations.
_REDACT_PATTERNS: Final = [
    # sk-... / sk-ant-... style API keys
    re.compile(r"\bsk-[A-Za-z0-9_\-]{12,}\b"),
    # Bearer tokens
    re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-\.]{16,}"),
    # AWS-style keys
    re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"),
    # Generic key=VALUE / token=VALUE / password=VALUE assignments
    re.compile(r"(?i)(api[_-]?key|token|secret|password|passwd|passwd)[\"']?\s*[:=]\s*[\"'][^\"']{6,}[\"']"),
    # JWT-ish blobs
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
]

_REDACT_REPLACEMENT = "[REDACTED]"


class RedactingFilter(logging.Filter):
    """Redact credential-shaped substrings from log records."""

    def __init__(self, *, enabled: bool = True) -> None:
        super().__init__()
        self._enabled = enabled

    def filter(self, record: logging.LogRecord) -> bool:
        if not self._enabled:
            return True
        for attr in ("msg",):
            value = getattr(record, attr, None)
            if isinstance(value, str):
                setattr(record, attr, self._redact(value))
        return True

    @staticmethod
    def _redact(text: str) -> str:
        redacted = text
        for pattern in _REDACT_PATTERNS:
            redacted = pattern.sub(_REDACT_REPLACEMENT, redacted)
        return redacted


def configure_logging(level: int = logging.INFO) -> None:
    """Configure root logging once. Safe to call multiple times."""
    if getattr(configure_logging, "_done", False):
        return
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(name)s - %(levelname)s - %(message)s"))
    handler.addFilter(RedactingFilter(enabled=settings.redact_logs))
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
    configure_logging._done = True  # type: ignore[attr-defined]


def get_logger(name: str) -> logging.Logger:
    """Return a module logger. Use instead of ``logging.getLogger`` for consistency."""
    return logging.getLogger(name)


__all__ = ["RedactingFilter", "configure_logging", "get_logger"]
