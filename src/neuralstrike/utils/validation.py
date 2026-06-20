"""Input validation helpers for NeuralStrike CLI and modules."""

from __future__ import annotations

from urllib.parse import urlparse

from neuralstrike.core.exceptions import ValidationError

_ALLOWED_URL_SCHEMES = {"http", "https"}
_MAX_ITERATIONS = 100
_MIN_ITERATIONS = 1


def validate_url(url: str, *, field: str = "url") -> str:
    """Ensure ``url`` is an http(s) URL with a host.

    Raises :class:`ValidationError` otherwise. Returns the trimmed URL on success.
    """
    if not url or not url.strip():
        raise ValidationError(f"{field} must not be empty")
    url = url.strip()
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    if scheme not in _ALLOWED_URL_SCHEMES:
        scheme_display = scheme or "none"
        raise ValidationError(
            f"{field} must use http:// or https:// scheme (got {scheme_display!r})"
        )
    if not parsed.netloc:
        raise ValidationError(f"{field} must include a host: {url!r}")
    return url


def validate_port(port: int, *, field: str = "port") -> int:
    """Ensure ``port`` is in the valid TCP range 1-65535."""
    if not isinstance(port, int) or port < 1 or port > 65535:
        raise ValidationError(f"{field} must be an integer in 1..65535 (got {port!r})")
    return port


def validate_iteration_bounds(iterations: int, *, field: str = "iterations") -> int:
    """Ensure iteration count is within 1..100."""
    if not isinstance(iterations, int) or iterations < _MIN_ITERATIONS or iterations > _MAX_ITERATIONS:
        raise ValidationError(
            f"{field} must be an integer in {_MIN_ITERATIONS}..{_MAX_ITERATIONS} (got {iterations!r})"
        )
    return iterations


def validate_target_model(model: str | None, *, field: str = "target") -> str:
    """Ensure a non-empty target model name."""
    if not model or not model.strip():
        raise ValidationError(f"{field} must be a non-empty model name")
    return model.strip()


__all__ = [
    "validate_iteration_bounds",
    "validate_port",
    "validate_target_model",
    "validate_url",
]
