"""Typed configuration for NeuralStrike.

Settings are loaded from environment variables (prefix ``NEURALSTRIKE_``) and
an optional ``.env`` file at the project root. All keys can also be passed as
constructor arguments for tests.
"""

from __future__ import annotations

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """NeuralStrike runtime configuration."""

    model_config = SettingsConfigDict(
        env_prefix="NEURALSTRIKE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    project_name: str = "NeuralStrike"
    version: str = "0.2.0"

    # Local brain (Attacker + Judge)
    ollama_base_url: str = Field(
        default="http://localhost:11434",
        description="Base URL for the local Ollama instance hosting Attacker/Judge models.",
    )
    attacker_model: str = Field(default="deepseek-r1", description="Attacker model name.")
    judge_model: str = Field(default="llama3.1", description="Judge model name.")

    # Optional remote target credentials
    openai_api_key: str | None = Field(default=None, description="OpenAI API key for remote targets.")
    anthropic_api_key: str | None = Field(
        default=None, description="Anthropic API key for remote targets."
    )

    # Operator-facing safety
    redact_logs: bool = Field(default=True, description="Scrub credential-shaped strings from logs.")

    @field_validator("ollama_base_url")
    @classmethod
    def _validate_ollama_url(cls, value: str) -> str:
        if not value.startswith(("http://", "https://")):
            raise ValueError("ollama_base_url must be an http:// or https:// URL")
        return value


settings = Settings()


__all__ = ["Settings", "settings"]
