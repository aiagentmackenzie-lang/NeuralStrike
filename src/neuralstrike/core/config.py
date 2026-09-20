"""Typed configuration for NeuralStrike.

Settings are loaded from environment variables (prefix ``NEURALSTRIKE_``) and
an optional ``.env`` file at the project root. All keys can also be passed as
constructor arguments for tests.
"""

from __future__ import annotations

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from neuralstrike import __version__


class Settings(BaseSettings):
    """NeuralStrike runtime configuration."""

    model_config = SettingsConfigDict(
        env_prefix="NEURALSTRIKE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    project_name: str = "NeuralStrike"
    # Package version (single-sourced from neuralstrike.__version__ so the
    # pyproject bump and this field can never drift apart again).
    version: str = __version__

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
    anthropic_api_key: str | None = Field(default=None, description="Anthropic API key for remote targets.")

    # SecurityScarletAI exercise telemetry (fleet Wave 2) — OPT-IN.
    # scarletai_url is the FULL ingest endpoint (e.g.
    # http://localhost:8000/api/v1/ingest — the same knob semantics as
    # NeuralGuard's NEURALGUARD_SIEM_SCARLETAI_URL); token = the scoped
    # INGEST_BEARER_TOKEN (viewer-class, ingest-router-only). Both must be
    # set for telemetry to flow; a partial config is a validation error,
    # never a silent half-pipe.
    scarletai_url: str | None = Field(
        default=None,
        description="FULL SecurityScarletAI ingest URL for exercise telemetry; None = telemetry off.",
    )
    scarletai_token: str | None = Field(
        default=None, description="ScarletAI INGEST_BEARER_TOKEN (never logged)."
    )
    telemetry_actor: str = Field(
        default="neuralstrike-operator",
        description="Exercise actor — user_name slot, the attribution join key with NG verdict events.",
    )

    # NeuralGuard screen wiring (fleet Wave 3) — the live firewall the bench
    # drives. api_key may carry NeuralGuard's documented "<key>|<tenant>"
    # credential form (resolve_neuralguard_credential splits it); the tenant
    # MUST match the key's binding (NG 403s a mismatch when
    # enforce_tenant_from_key is on — the fleet default). The key is never
    # logged.
    neuralguard_tenant: str = Field(
        default="neuralstrike",
        description="tenant_id sent to the NeuralGuard screen (must match the API key's bound tenant).",
    )
    neuralguard_api_key: str | None = Field(
        default=None,
        description="NeuralGuard API key (bearer); accepts '<key>|<tenant>' and derives both parts.",
    )

    # SecurityScarletAI READ path (fleet Wave 3, purple-report) — OPT-IN.
    # The purple-report queries GET /api/v1/alerts + GET /api/v1/logs, which
    # require the ADMIN-class API token (NOT the scoped ingest token — that
    # one is ingest-router-only by design). base_url is Scarlet's ROOT (e.g.
    # http://localhost:8000); the report appends /api/v1/... itself. Same
    # partial-config rule as the ingest pipe: both or neither.
    scarletai_base_url: str | None = Field(
        default=None,
        description=(
            "SecurityScarletAI BASE URL for the purple-report read path; None = purple-report reads disabled."
        ),
    )
    scarletai_api_token: str | None = Field(
        default=None,
        description=(
            "ScarletAI API bearer token (admin class — /alerts + /logs are read-only uses; never logged)."
        ),
    )

    # Operator-facing safety
    redact_logs: bool = Field(default=True, description="Scrub credential-shaped strings from logs.")

    @field_validator("ollama_base_url")
    @classmethod
    def _validate_ollama_url(cls, value: str) -> str:
        if not value.startswith(("http://", "https://")):
            raise ValueError("ollama_base_url must be an http:// or https:// URL")
        return value

    @field_validator("scarletai_base_url")
    @classmethod
    def _validate_scarletai_base_url(cls, value: str | None) -> str | None:
        if value is not None and not value.startswith(("http://", "https://")):
            raise ValueError("scarletai_base_url must be an http:// or https:// URL")
        return value


settings = Settings()


__all__ = ["Settings", "settings"]
