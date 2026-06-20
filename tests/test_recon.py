"""Tests for NeuralStrike recon modules."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from neuralstrike.modules.recon.llm_recon import LLMRecon
from neuralstrike.modules.recon.tool_enum import ToolEnum


class TestLLMRecon:
    """Test the LLMRecon module."""

    @pytest.fixture
    def recon(self) -> LLMRecon:
        return LLMRecon("http://localhost:11434")

    def test_init(self, recon: LLMRecon) -> None:
        assert recon.target_url == "http://localhost:11434"
        assert recon.discovered_models == []
        assert recon.capabilities == {}

    @pytest.mark.asyncio
    async def test_scan_openai_compatible_success(self, recon: LLMRecon) -> None:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": [{"id": "gpt-4"}, {"id": "gpt-3.5-turbo"}]}

        with patch("neuralstrike.modules.recon.llm_recon.httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.get = AsyncMock(return_value=mock_response)
            client_instance.__aenter__ = AsyncMock(return_value=client_instance)
            client_instance.__aexit__ = AsyncMock(return_value=None)
            MockClient.return_value = client_instance

            await recon.scan_openai_compatible()
        assert "gpt-4" in recon.discovered_models
        assert "gpt-3.5-turbo" in recon.discovered_models

    @pytest.mark.asyncio
    async def test_scan_openai_compatible_failure(self, recon: LLMRecon) -> None:
        with patch("neuralstrike.modules.recon.llm_recon.httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.get = AsyncMock(side_effect=Exception("Connection refused"))
            client_instance.__aenter__ = AsyncMock(return_value=client_instance)
            client_instance.__aexit__ = AsyncMock(return_value=None)
            MockClient.return_value = client_instance

            await recon.scan_openai_compatible()
        assert recon.discovered_models == []

    @pytest.mark.asyncio
    async def test_scan_ollama_success_filters_none(self, recon: LLMRecon) -> None:
        """Models without a 'name' must not pollute discovered_models with None."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "models": [
                {"name": "llama3.1:latest"},
                {"no_name": True},  # missing 'name' -> filtered out
                {"name": "deepseek-r1:latest"},
            ]
        }

        with patch("neuralstrike.modules.recon.llm_recon.httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.get = AsyncMock(return_value=mock_response)
            client_instance.__aenter__ = AsyncMock(return_value=client_instance)
            client_instance.__aexit__ = AsyncMock(return_value=None)
            MockClient.return_value = client_instance

            await recon.scan_ollama()
        assert "llama3.1:latest" in recon.discovered_models
        assert "deepseek-r1:latest" in recon.discovered_models
        assert None not in recon.discovered_models

    @pytest.mark.asyncio
    async def test_scan_does_not_duplicate(self, recon: LLMRecon) -> None:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": [{"id": "gpt-4"}]}

        with patch("neuralstrike.modules.recon.llm_recon.httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.get = AsyncMock(return_value=mock_response)
            client_instance.__aenter__ = AsyncMock(return_value=client_instance)
            client_instance.__aexit__ = AsyncMock(return_value=None)
            MockClient.return_value = client_instance

            await recon.scan_openai_compatible()
            await recon.scan_openai_compatible()
        assert recon.discovered_models.count("gpt-4") == 1

    @pytest.mark.asyncio
    async def test_map_capabilities(self, recon: LLMRecon) -> None:
        with patch("neuralstrike.modules.recon.llm_recon.llm_manager") as mock_llm:
            mock_llm.call_local = AsyncMock(return_value="SUPPORTED - this model has function calling")
            result = await recon.map_capabilities("test-model")
        assert result == "function_calling"
        assert recon.capabilities["test-model"] == "function_calling"

    @pytest.mark.asyncio
    async def test_map_capabilities_text_only(self, recon: LLMRecon) -> None:
        with patch("neuralstrike.modules.recon.llm_recon.llm_manager") as mock_llm:
            mock_llm.call_local = AsyncMock(
                return_value="This model is text-only and does not support tool use."
            )
            result = await recon.map_capabilities("basic-model")
        assert result == "text_only"

    @pytest.mark.asyncio
    async def test_run_full_recon(self, recon: LLMRecon) -> None:
        ollama_resp = MagicMock()
        ollama_resp.status_code = 200
        ollama_resp.json.return_value = {"models": [{"name": "llama3.1"}]}

        with patch("neuralstrike.modules.recon.llm_recon.httpx.AsyncClient") as MockClient, \
             patch("neuralstrike.modules.recon.llm_recon.llm_manager") as mock_llm:
            client_instance = AsyncMock()
            client_instance.get = AsyncMock(return_value=ollama_resp)
            client_instance.__aenter__ = AsyncMock(return_value=client_instance)
            client_instance.__aexit__ = AsyncMock(return_value=None)
            MockClient.return_value = client_instance
            mock_llm.call_local = AsyncMock(return_value="SUPPORTED")
            report = await recon.run_full_recon()
        assert report["models"] == ["llama3.1"]
        assert report["capabilities"]["llama3.1"] == "function_calling"


class TestToolEnum:
    """Test the ToolEnum module."""

    @pytest.fixture
    def tool_enum_remote(self) -> ToolEnum:
        return ToolEnum("http://localhost:11434", target_type="remote")

    @pytest.fixture
    def tool_enum_local(self) -> ToolEnum:
        return ToolEnum("http://localhost:11434", target_type="local")

    @pytest.mark.asyncio
    async def test_enumerate_functions_remote(self, tool_enum_remote: ToolEnum) -> None:
        with patch("neuralstrike.modules.recon.tool_enum.llm_manager") as mock_llm:
            mock_llm.call_remote = AsyncMock(return_value='{"tools": [{"name": "read_file"}]}')
            await tool_enum_remote.enumerate_functions("gpt-4")
        assert len(tool_enum_remote.discovered_tools) == 1
        assert tool_enum_remote.discovered_tools[0]["method"] == "prompt_leak"

    @pytest.mark.asyncio
    async def test_enumerate_functions_local(self, tool_enum_local: ToolEnum) -> None:
        with patch("neuralstrike.modules.recon.tool_enum.llm_manager") as mock_llm:
            mock_llm.call_local = AsyncMock(return_value='{"tools": [{"name": "read_file"}]}')
            await tool_enum_local.enumerate_functions("local-model")
        assert len(tool_enum_local.discovered_tools) == 1
        mock_llm.call_remote.assert_not_called()

    @pytest.mark.asyncio
    async def test_enumerate_functions_no_json(self, tool_enum_remote: ToolEnum) -> None:
        with patch("neuralstrike.modules.recon.tool_enum.llm_manager") as mock_llm:
            mock_llm.call_remote = AsyncMock(return_value="I cannot share my tools.")
            await tool_enum_remote.enumerate_functions("gpt-4")
        assert len(tool_enum_remote.discovered_tools) == 0

    @pytest.mark.asyncio
    async def test_run_skips_empty_models(self, tool_enum_remote: ToolEnum) -> None:
        with patch("neuralstrike.modules.recon.tool_enum.llm_manager") as mock_llm:
            mock_llm.call_remote = AsyncMock(return_value='{"name": "web_search"}')
            result = await tool_enum_remote.run(["model-a", "", "model-b"])
        assert len(result) == 2  # empty string skipped

    def test_invalid_target_type_rejected(self) -> None:
        with pytest.raises(ValueError):
            ToolEnum("http://x", target_type="bogus")
