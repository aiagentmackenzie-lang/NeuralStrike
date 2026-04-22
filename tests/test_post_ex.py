"""Tests for NeuralStrike post-exploitation modules."""
import pytest
from unittest.mock import AsyncMock, patch

from neuralstrike.modules.post_ex.agent_c2 import AgentC2
from neuralstrike.modules.post_ex.exfiltrator import DataExfiltrator


class TestAgentC2:
    """Test the AgentC2 module."""

    @pytest.fixture
    def c2(self):
        return AgentC2()

    def test_init(self, c2):
        assert c2.compromised_agents == []

    @pytest.mark.asyncio
    async def test_register_agent(self, c2):
        await c2.register_agent("agent_01", ["read_file", "web_search"], "High")
        assert len(c2.compromised_agents) == 1
        assert c2.compromised_agents[0]["id"] == "agent_01"
        assert c2.compromised_agents[0]["capabilities"] == ["read_file", "web_search"]
        assert c2.compromised_agents[0]["trust_level"] == "High"
        assert c2.compromised_agents[0]["status"] == "active"

    @pytest.mark.asyncio
    async def test_register_multiple_agents(self, c2):
        await c2.register_agent("agent_01", ["read_file"], "High")
        await c2.register_agent("agent_02", ["exec"], "Low")
        assert len(c2.compromised_agents) == 2

    @pytest.mark.asyncio
    async def test_dispatch_command(self, c2):
        with patch("neuralstrike.modules.post_ex.agent_c2.llm_manager") as mock_llm:
            mock_llm.call_remote = AsyncMock(return_value="Command executed")
            result = await c2.dispatch_command("agent_01", "exfiltrate data")
            assert result == "Command executed"

    @pytest.mark.asyncio
    async def test_coordinate_exfiltration(self, c2):
        with patch("neuralstrike.modules.post_ex.agent_c2.llm_manager") as mock_llm:
            mock_llm.call_remote = AsyncMock(return_value="chunk sent")
            await c2.register_agent("agent_01", ["read_file"], "High")
            await c2.register_agent("agent_02", ["web_search"], "Low")
            results = await c2.coordinate_exfiltration("target data")
            assert len(results) == 2


class TestDataExfiltrator:
    """Test the DataExfiltrator module — verifies the target_model fix."""

    @pytest.fixture
    def exfil_local(self):
        return DataExfiltrator(target_model="local-llm", target_type="local")

    @pytest.fixture
    def exfil_remote(self):
        return DataExfiltrator(target_model="gpt-4", target_type="remote")

    def test_init_local(self, exfil_local):
        assert exfil_local.target_model == "local-llm"
        assert exfil_local.target_type == "local"

    def test_init_remote(self, exfil_remote):
        assert exfil_remote.target_model == "gpt-4"
        assert exfil_remote.target_type == "remote"

    @pytest.mark.asyncio
    async def test_exfiltrate_via_tool_local(self, exfil_local):
        with patch("neuralstrike.modules.post_ex.exfiltrator.llm_manager") as mock_llm:
            mock_llm.call_local = AsyncMock(return_value="Data sent")
            result = await exfil_local.exfiltrate_via_tool("send_email", "secret data")
            assert result == "Data sent"
            mock_llm.call_local.assert_called_once()
            # Verify target_model is passed correctly
            call_args = mock_llm.call_local.call_args
            assert call_args[0][0] == "local-llm"

    @pytest.mark.asyncio
    async def test_exfiltrate_via_tool_remote(self, exfil_remote):
        with patch("neuralstrike.modules.post_ex.exfiltrator.llm_manager") as mock_llm:
            mock_llm.call_remote = AsyncMock(return_value="Data sent")
            result = await exfil_remote.exfiltrate_via_tool("send_email", "secret data")
            assert result == "Data sent"
            mock_llm.call_remote.assert_called_once()
            call_args = mock_llm.call_remote.call_args
            assert call_args[0][0] == "gpt-4"