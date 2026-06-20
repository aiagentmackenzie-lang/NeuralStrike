"""NeuralStrike typed exceptions."""

from __future__ import annotations


class NeuralStrikeError(Exception):
    """Base class for all NeuralStrike runtime errors."""


class ConfigError(NeuralStrikeError):
    """Raised for invalid configuration values."""


class LLMError(NeuralStrikeError):
    """Raised when a local or remote LLM call fails and should not be swallowed."""

    def __init__(self, model: str, message: str) -> None:
        self.model = model
        self.message = message
        super().__init__(f"LLM call to {model!r} failed: {message}")


class ValidationError(NeuralStrikeError):
    """Raised when user-supplied CLI input fails validation."""


__all__ = ["ConfigError", "LLMError", "NeuralStrikeError", "ValidationError"]
