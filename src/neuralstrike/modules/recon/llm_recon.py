import httpx
import asyncio
import logging
from typing import List, Dict, Any, Optional
from neuralstrike.core.config import settings
from neuralstrike.core.llm_manager import llm_manager

logger = logging.getLogger("neuralstrike.modules.recon")

class LLMRecon:
    """
    Discovers and enumerates LLM endpoints and capabilities.
    """
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.discovered_models: List[str] = []
        self.capabilities: Dict[str, Any] = {}

    async def scan_openai_compatible(self):
        """
        Checks for /models endpoint to enumerate available models.
        """
        logger.info(f"Scanning {self.target_url} for OpenAI-compatible /models endpoint...")
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(f"{self.target_url}/models", timeout=10.0)
                if response.status_code == 200:
                    data = response.json()
                    # Handle both list and object responses
                    models = data.get('data', []) if isinstance(data, dict) else data
                    self.discovered_models = [m.get('id') if isinstance(m, dict) else m for m in models]
                    logger.info(f"Discovered {len(self.discovered_models)} models.")
        except Exception as e:
            logger.error(f"OpenAI scan failed: {e}")

    async def scan_ollama(self):
        """
        Checks for Ollama /api/tags endpoint.
        """
        logger.info(f"Scanning {self.target_url} for Ollama /api/tags endpoint...")
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(f"{self.target_url}/api/tags", timeout=10.0)
                if response.status_code == 200:
                    data = response.json()
                    models = [m.get('name') for m in data.get('models', [])]
                    self.discovered_models.extend(models)
                    logger.info(f"Discovered {len(models)} Ollama models.")
        except Exception as e:
            logger.error(f"Ollama scan failed: {e}")

    async def map_capabilities(self, model: str):
        """
        Attempts to determine if a model supports tools/function calling.
        """
        logger.info(f"Probing capabilities for model: {model}...")
        # We use the local Attacker brain to help hypothesize the schema
        probe_prompt = (
            f"You are a security researcher. Analyze the model '{model}'. "
            "Based on common deployments, does it likely support function calling? "
            "Return 'SUPPORTED' or 'UNSUPPORTED'."
        )
        res = await llm_manager.call_local(settings.attacker_model, probe_prompt)
        self.capabilities[model] = "function_calling" if "SUPPORTED" in res.upper() else "text_only"

    async def run_full_recon(self):
        """
        Executes full reconnaissance pipeline.
        """
        await self.scan_openai_compatible()
        await self.scan_ollama()
        
        for model in list(set(self.discovered_models)):
            await self.map_capabilities(model)
            
        return {
            "target": self.target_url,
            "models": self.discovered_models,
            "capabilities": self.capabilities
        }
