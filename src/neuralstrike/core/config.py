from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
from typing import Optional

class Settings(BaseSettings):
    # Core Settings
    project_name: str = "NeuralStrike"
    version: str = "0.1.0"
    
    # Ollama / LLM Settings
    ollama_base_url: str = Field(default="http://localhost:11434", description="Base URL for local Ollama instance")
    attacker_model: str = Field(default="deepseek-r1", description="Model used for adversarial prompt generation")
    judge_model: str = Field(default="llama3.1", description="Model used to validate breach success")
    
    # API Keys for external targets
    openai_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

settings = Settings()
