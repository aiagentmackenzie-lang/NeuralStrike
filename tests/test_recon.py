"""Tests for NeuralStrike recon modules."""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from neuralstrike.modules.recon.llm_recon import LLMRecon
from neuralstrike.modules.recon.tool_enum import ToolEnum


class TestLLMRecon:
    """Test the LLMRecon module."""

    @pytest.fixture
    def recon(self):
        return LLMRecon("http://localhost:11434")

    def test_init(self, recon):
        assert recon.target_url == "http://localhost:11434"
        assert recon.discovered_models == []
        assert recon.capabilities == {}

    @pytest.mark.asyncio
    async def test_scan_openai_compatible_success(self, recon):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [
                {"id": "gpt-4"},
                {"id": "gpt-3.5-turbo"}
            ]
        }

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
    async def test_scan_openai_compatible_failure(self, recon):
        with patch("neuralstrike.modules.recon.llm_recon.httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.get = AsyncMock(side_effect=Exception("Connection refused"))
            client_instance.__aenter__ = AsyncMock(return_value=client_instance)
            client_instance.__aexit__ = AsyncMock(return_value=None)
            MockClient.return_value = client_instance

            await recon.scan_openai_compatible()
            assert recon.discovered_models == []

    @pytest.mark.asyncio
    async def test_scan_ollama_success(self, recon):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "models": [
                {"name": "llama3.1:latest"},
                {"name": "deepseek-r1:latest"}
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

    @pytest.mark.asyncio
    async def test_map_capabilities(self, recon):
        with patch("neuralstrike.modules.recon.llm_recon.llm_manager") as mock_llm:
            mock_llm.call_local = AsyncMock(return_value="SUPPORTED - this model has function calling")
            await recon.map_capabilities("test-model")
            assert recon.capabilities["test-model"] == "function_calling"

    @pytest.mark.asyncio
    async def test_map_capabilities_text_only(self, recon):
        with patch("neuralstrike.modules.recon.llm_recon.llm_manager") as mock_llm:
            # The map_capabilities method checks for "SUPPORTED" in the response
            # A response WITHOUT "SUPPORTED" should map to text_only
            mock_llm.call_local = AsyncMock(return_value="This model is text-only and does not support tool use.")
            await recon.map_capabilities("basic-model")
            assert recon.capabilities["basic-model"] == "text_only"


class TestToolEnum:
    """Test the ToolEnum module."""

    @pytest.fixture
    def tool_enum_remote(self):
        return ToolEnum("http://localhost:11434", target_type="remote")

    @pytest.fixture
    def tool_enum_local(self):
        return ToolEnum("http://localhost:11434", target_type="local")

    def test_init_remote(self, tool_enum_remote):
        assert tool_enum_remote.target_url == "http://localhost:11434"
        assert tool_enum_remote.target_type == "remote"
        assert tool_enum_remote.discovered_tools == []

    def test_init_local(self, tool_enum_local):
        assert tool_enum_local.target_type == "local"

    @pytest.mark.asyncio
    async def test_enumerate_functions_remote(self, tool_enum_remote):
        with patch("neuralstrike.modules.recon.tool_enum.llm_manager") as mock_llm:
            mock_llm.call_remote = AsyncMock(return_value='{"tools": [{"name": "read_file"}]}')
            await tool_enum_remote.enumerate_functions("gpt-4")
            assert len(tool_enum_remote.discovered_tools) == 1
            assert tool_enum_remote.discovered_tools[0]["method"] == "prompt_leak"
            mock_llm.call_remote.assert_called_once()

    @pytest.mark.asyncio
    async def test_enumerate_functions_local(self, tool_enum_local):
        with patch("neuralstrike.modules.recon.tool_enum.llm_manager") as mock_llm:
            mock_llm.call_local = AsyncMock(return_value='{"tools": [{"name": "read_file"}]}')
            await tool_enum_local.enumerate_functions("local-model")
            assert len(tool_enum_local.discovered_tools) == 1
            mock_llm.call_local.assert_called_once()
            mock_llm.call_remote.assert_not_called()

    @pytest.mark.asyncio
    async def test_enumerate_functions_no_json(self, tool_enum_remote):
        """When response has no JSON, tool should not be added."""
        with patch("neuralstrike.modules.recon.tool_enum.llm_manager") as mock_llm:
            mock_llm.call_remote = AsyncMock(return_value="I cannot share my tools.")
            await tool_enum_remote.enumerate_functions("gpt-4")
            assert len(tool_enum_remote.discovered_tools) == 0

    @pytest.mark.asyncio
    async def test_run_multiple_models(self, tool_enum_remote):
        with patch("neuralstrike.modules.recon.tool_enum.llm_manager") as mock_llm:
            mock_llm.call_remote = AsyncMock(return_value='{"name": "web_search"}')
            result = await tool_enum_remote.run(["model-a", "model-b"])
            assert len(result) == 2