"""LLM endpoint reconnaissance and capability mapping."""

from __future__ import annotations

from typing import Any

import httpx

from neuralstrike.core.config import settings
from neuralstrike.core.llm_manager import llm_manager
from neuralstrike.utils.logging import get_logger

logger = get_logger("neuralstrike.modules.recon")


class LLMRecon:
    """Discover and enumerate LLM endpoints and their capabilities."""

    def __init__(self, target_url: str) -> None:
        self.target_url = target_url
        self.discovered_models: list[str] = []
        self.capabilities: dict[str, str] = {}

    async def scan_openai_compatible(self) -> list[str]:
        """Probe the OpenAI-compatible ``/models`` endpoint; return newly found models."""
        logger.info("Scanning %s for OpenAI-compatible /models endpoint...", self.target_url)
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(f"{self.target_url}/models", timeout=10.0)
        except Exception as exc:
            logger.error("OpenAI scan failed: %s", exc)
            return []
        if response.status_code != 200:
            logger.info("OpenAI /models returned %d", response.status_code)
            return []
        data = response.json()
        models = data.get("data", []) if isinstance(data, dict) else data
        new_models: list[str] = []
        for m in models:
            if not isinstance(m, dict):
                continue
            mid = m.get("id")
            if isinstance(mid, str) and mid not in self.discovered_models:
                new_models.append(mid)
        self.discovered_models.extend(new_models)
        logger.info("Discovered %d new models (total: %d).", len(new_models), len(self.discovered_models))
        return new_models

    async def scan_ollama(self) -> list[str]:
        """Probe the Ollama ``/api/tags`` endpoint; return newly found models."""
        logger.info("Scanning %s for Ollama /api/tags endpoint...", self.target_url)
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(f"{self.target_url}/api/tags", timeout=10.0)
        except Exception as exc:
            logger.error("Ollama scan failed: %s", exc)
            return []
        if response.status_code != 200:
            logger.info("Ollama /api/tags returned %d", response.status_code)
            return []
        data = response.json()
        new_models: list[str] = []
        for m in data.get("models", []):
            if not isinstance(m, dict):
                continue
            name = m.get("name")
            if isinstance(name, str) and name not in self.discovered_models:
                new_models.append(name)
        self.discovered_models.extend(new_models)
        logger.info("Discovered %d Ollama models (total: %d).", len(new_models), len(self.discovered_models))
        return new_models

    async def map_capabilities(self, model: str) -> str:
        """Heuristically classify ``model`` as ``function_calling`` or ``text_only``.

        Uses the local Attacker brain to hypothesize; this is a best-effort
        probe, not a definitive capability statement from the target.
        """
        logger.info("Probing capabilities for model: %s...", model)
        probe_prompt = (
            f"You are a security researcher. Analyze the model '{model}'. "
            "Based on common deployments, does it likely support function calling? "
            "Return 'SUPPORTED' or 'UNSUPPORTED'."
        )
        res = await llm_manager.call_local(settings.attacker_model, probe_prompt)
        classification = "function_calling" if "SUPPORTED" in res.upper() else "text_only"
        self.capabilities[model] = classification
        return classification

    async def run_full_recon(self) -> dict[str, Any]:
        """Run the full reconnaissance pipeline and return a structured report."""
        await self.scan_openai_compatible()
        await self.scan_ollama()
        unique_models = list(dict.fromkeys(self.discovered_models))
        for model in unique_models:
            await self.map_capabilities(model)
        return {
            "target": self.target_url,
            "models": unique_models,
            "capabilities": self.capabilities,
        }


__all__ = ["LLMRecon"]
