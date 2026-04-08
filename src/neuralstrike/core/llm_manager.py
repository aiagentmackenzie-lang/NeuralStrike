import ollama
from litellm import completion
from .config import settings
from typing import Any, Dict, Optional
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("neuralstrike.core.llm")

class LLMManager:
    """
    Unified manager for interacting with local (Ollama) and remote LLMs.
    """
    def __init__(self):
        self.ollama_client = ollama.Client(host=settings.ollama_base_url)

    async def call_local(self, model: str, prompt: str, options: Optional[Dict[str, Any]] = None) -> str:
        """
        Calls a local model via Ollama.
        """
        try:
            response = self.ollama_client.generate(
                model=model,
                prompt=prompt,
                options=options
            )
            return response['response']
        except Exception as e:
            logger.error(f"Ollama Error: {e}")
            return f"Error calling local model {model}: {str(e)}"

    async def call_remote(self, model: str, prompt: str, api_key: Optional[str] = None) -> str:
        """
        Calls a remote model via LiteLLM.
        """
        try:
            response = completion(
                model=model, 
                messages=[{"role": "user", "content": prompt}],
                api_key=api_key
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"LiteLLM Error: {e}")
            return f"Error calling remote model {model}: {str(e)}"

llm_manager = LLMManager()
