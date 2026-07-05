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

    # Local brain (Attacker + Judge). Per Decision D1, the Judge default is
    # the strongest available cloud model, NOT the same as the Attacker, so
    # the judge is harder to confuse than the attacker. The old `llama3.1`
    # default was a fail-open bug (model not installed on this host) — fixed
    # here and verified by a startup reachability check.
    ollama_base_url: str = Field(
        default="http://localhost:11434",
        description="Base URL for the local Ollama instance hosting Attacker/Judge models.",
    )
    attacker_model: str = Field(default="deepseek-r1", description="Attacker model name.")
    judge_model: str = Field(
        default="deepseek-v3.1:671b-cloud",
        description="Judge model name (advisory; distinct from the Attacker per D1).",
    )
    judge_model_fallbacks: tuple[str, ...] = Field(
        default=("kimi-k2.6:cloud", "gpt-oss:120b-cloud", "deepseek-r1:8b"),
        description="Ordered fallback chain tried when the Judge model is unreachable.",
    )
    victim_temperature: float = Field(
        default=0.0, description="Victim temperature (pinned to 0.0 for reproducible runs)."
    )
    attacker_temperature: float = Field(
        default=0.7, description="Attacker temperature (creativity; pinned by seed for replay)."
    )
    skip_reachability_check: bool = Field(
        default=False,
        description="Skip the startup model-reachability check (tests / offline / explicit opt-in).",
    )

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
