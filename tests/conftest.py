"""Shared pytest fixtures for NeuralStrike tests."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from neuralstrike.core.llm_manager import LLMManager


@pytest.fixture
def mock_llm() -> LLMManager:
    """A LLMManager whose call_local/call_remote are AsyncMocks (default: echo)."""
    llm = LLMManager.__new__(LLMManager)
    llm._base_url = "http://localhost:11434"
    llm._client = None
    llm.call_local = AsyncMock(return_value="local-response")  # type: ignore[method-assign]
    llm.call_remote = AsyncMock(return_value="remote-response")  # type: ignore[method-assign]
    return llm


@pytest.fixture
def tmp_registry(tmp_path: Path) -> Path:
    """A per-test agent registry file path (does not exist yet)."""
    return tmp_path / "agents.json"
