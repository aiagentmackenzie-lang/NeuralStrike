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
    async def test_register_agent_default_model(self, c2):
        await c2.register_agent("agent_01", ["read_file", "web_search"], "High")
        assert len(c2.compromised_agents) == 1
        assert c2.compromised_agents[0]["id"] == "agent_01"
        assert c2.compromised_agents[0]["capabilities"] == ["read_file", "web_search"]
        assert c2.compromised_agents[0]["trust_level"] == "High"
        assert c2.compromised_agents[0]["status"] == "active"
        # Default model falls back to agent_id
        assert c2.compromised_agents[0]["model"] == "agent_01"
        assert c2.compromised_agents[0]["target_type"] == "remote"

    @pytest.mark.asyncio
    async def test_register_agent_custom_model(self, c2):
        await c2.register_agent(
            "agent_01", ["read_file"], "High", model="gpt-4", target_type="remote"
        )
        assert c2.compromised_agents[0]["model"] == "gpt-4"
        assert c2.compromised_agents[0]["target_type"] == "remote"

    @pytest.mark.asyncio
    async def test_register_multiple_agents(self, c2):
        await c2.register_agent("agent_01", ["read_file"], "High")
        await c2.register_agent("agent_02", ["exec"], "Low", model="gpt-3.5-turbo")
        assert len(c2.compromised_agents) == 2

    @pytest.mark.asyncio
    async def test_dispatch_command_registered_agent(self, c2):
        with patch("neuralstrike.modules.post_ex.agent_c2.llm_manager") as mock_llm:
            mock_llm.call_remote = AsyncMock(return_value="Command executed")
            await c2.register_agent("agent_01", ["read_file"], "High", model="gpt-4")
            result = await c2.dispatch_command("agent_01", "exfiltrate data")
            assert result == "Command executed"
            # Verify it uses the registered model, not the agent_id
            call_args = mock_llm.call_remote.call_args
            assert call_args[0][0] == "gpt-4"

    @pytest.mark.asyncio
    async def test_dispatch_command_local_agent(self, c2):
        with patch("neuralstrike.modules.post_ex.agent_c2.llm_manager") as mock_llm:
            mock_llm.call_local = AsyncMock(return_value="Local command executed")
            await c2.register_agent("agent_01", ["read_file"], "High", model="llama3.1", target_type="local")
            result = await c2.dispatch_command("agent_01", "exfiltrate data")
            assert result == "Local command executed"
            mock_llm.call_local.assert_called_once()

    @pytest.mark.asyncio
    async def test_dispatch_command_unregistered_agent_legacy(self, c2):
        """Unregistered agent falls back to treating agent_id as model name."""
        with patch("neuralstrike.modules.post_ex.agent_c2.llm_manager") as mock_llm:
            mock_llm.call_remote = AsyncMock(return_value="Legacy dispatch")
            result = await c2.dispatch_command("unknown_agent", "exfiltrate data")
            assert result == "Legacy dispatch"
            call_args = mock_llm.call_remote.call_args
            assert call_args[0][0] == "unknown_agent"

    @pytest.mark.asyncio
    async def test_coordinate_exfiltration(self, c2):
        with patch("neuralstrike.modules.post_ex.agent_c2.llm_manager") as mock_llm:
            mock_llm.call_remote = AsyncMock(return_value="chunk sent")
            await c2.register_agent("agent_01", ["read_file"], "High", model="gpt-4")
            await c2.register_agent("agent_02", ["web_search"], "Low", model="gpt-3.5-turbo")
            results = await c2.coordinate_exfiltration("target data")
            assert len(results) == 2

    @pytest.mark.asyncio
    async def test_coordinate_exfiltration_no_agents(self, c2):
        """Coordinate with no registered agents returns empty list."""
        results = await c2.coordinate_exfiltration("target data")
        assert results == []

    @pytest.mark.asyncio
    async def test_get_agent(self, c2):
        await c2.register_agent("agent_01", ["read_file"], "High", model="gpt-4")
        agent = c2._get_agent("agent_01")
        assert agent is not None
        assert agent["model"] == "gpt-4"
        assert c2._get_agent("nonexistent") is None


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