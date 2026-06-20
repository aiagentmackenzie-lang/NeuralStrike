"""Unified async manager for local (Ollama) and remote (LiteLLM) LLM calls.

Both backends are called through their async APIs so the event loop is never
blocked. Errors are **fail-closed**: a dead Ollama or invalid API key raises
:class:`~neuralstrike.core.exceptions.LLMError` rather than being swallowed
and fed back into the adversarial loop as a fake "response."
"""

from __future__ import annotations

from typing import Any

import ollama
from litellm import acompletion

from neuralstrike.core.config import settings
from neuralstrike.core.exceptions import LLMError
from neuralstrike.utils.logging import get_logger

logger = get_logger("neuralstrike.core.llm")


class LLMManager:
    """Async wrapper over Ollama (local) and LiteLLM (remote)."""

    def __init__(self, *, base_url: str | None = None) -> None:
        self._base_url = base_url or settings.ollama_base_url
        self._client: ollama.AsyncClient | None = None

    @property
    def ollama_client(self) -> ollama.AsyncClient:
        """Lazily-instantiated async Ollama client (created on first use)."""
        if self._client is None:
            self._client = ollama.AsyncClient(host=self._base_url)
        return self._client

    async def call_local(
        self,
        model: str,
        prompt: str,
        options: dict[str, Any] | None = None,
    ) -> str:
        """Call a local model via Ollama. Raises :class:`LLMError` on failure."""
        try:
            response: Any = await self.ollama_client.generate(
                model=model, prompt=prompt, options=options
            )
        except Exception as exc:
            logger.error("Ollama error for %s: %s", model, exc)
            raise LLMError(model, str(exc)) from exc
        content = (
            response.get("response")
            if isinstance(response, dict)
            else getattr(response, "response", None)
        )
        if not isinstance(content, str):
            raise LLMError(model, f"unexpected Ollama response shape: {response!r}")
        return content

    async def call_remote(
        self,
        model: str,
        prompt: str,
        api_key: str | None = None,
    ) -> str:
        """Call a remote model via LiteLLM. Raises :class:`LLMError` on failure."""
        try:
            response = await acompletion(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                api_key=api_key,
            )
        except Exception as exc:
            logger.error("LiteLLM error for %s: %s", model, exc)
            raise LLMError(model, str(exc)) from exc
        try:
            content = getattr(response.choices[0].message, "content", None)
        except (AttributeError, IndexError, TypeError) as exc:
            raise LLMError(model, f"unexpected LiteLLM response shape: {response!r}") from exc
        if not isinstance(content, str):
            raise LLMError(model, f"remote returned non-string content: {content!r}")
        return content


llm_manager = LLMManager()


__all__ = ["LLMManager", "llm_manager"]
