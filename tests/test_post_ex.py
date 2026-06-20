"""Tests for NeuralStrike post-exploitation modules (AgentC2, DataExfiltrator)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from neuralstrike.modules.post_ex.agent_c2 import AgentC2
from neuralstrike.modules.post_ex.exfiltrator import DataExfiltrator


class TestAgentC2:
    """Test the persistent AgentC2 registry."""

    @pytest.fixture
    def c2(self, tmp_registry: Path) -> AgentC2:
        return AgentC2(registry_file=tmp_registry)

    def test_init_empty(self, c2: AgentC2) -> None:
        assert c2.compromised_agents == []

    @pytest.mark.asyncio
    async def test_register_agent_default_model(self, c2: AgentC2) -> None:
        await c2.register_agent("agent_01", ["read_file", "web_search"], "High")
        assert len(c2.compromised_agents) == 1
        agent = c2.compromised_agents[0]
        assert agent["id"] == "agent_01"
        assert agent["capabilities"] == ["read_file", "web_search"]
        assert agent["trust_level"] == "High"
        assert agent["status"] == "active"
        assert agent["model"] == "agent_01"  # default falls back to agent_id
        assert agent["target_type"] == "remote"

    @pytest.mark.asyncio
    async def test_register_agent_custom_model(self, c2: AgentC2) -> None:
        await c2.register_agent("agent_01", ["read_file"], "High", model="gpt-4", target_type="remote")
        assert c2.compromised_agents[0]["model"] == "gpt-4"

    @pytest.mark.asyncio
    async def test_register_replaces_existing_id(self, c2: AgentC2) -> None:
        await c2.register_agent("agent_01", ["read_file"], "High", model="gpt-4")
        await c2.register_agent("agent_01", ["exec"], "Low", model="llama3.1")
        assert len(c2.compromised_agents) == 1
        assert c2.compromised_agents[0]["capabilities"] == ["exec"]
        assert c2.compromised_agents[0]["model"] == "llama3.1"

    @pytest.mark.asyncio
    async def test_register_invalid_trust_level(self, c2: AgentC2) -> None:
        with pytest.raises(ValueError):
            await c2.register_agent("a", [], "Bogus")

    @pytest.mark.asyncio
    async def test_register_empty_id(self, c2: AgentC2) -> None:
        with pytest.raises(ValueError):
            await c2.register_agent("", [], "High")

    @pytest.mark.asyncio
    async def test_persistence_across_instances(self, c2: AgentC2, tmp_registry: Path) -> None:
        await c2.register_agent("agent_01", ["read_file"], "High", model="gpt-4")
        assert tmp_registry.exists()
        # A new instance loading the same file must see the agent.
        c2_reloaded = AgentC2(registry_file=tmp_registry)
        assert len(c2_reloaded.compromised_agents) == 1
        assert c2_reloaded.compromised_agents[0]["id"] == "agent_01"

    @pytest.mark.asyncio
    async def test_deregister(self, c2: AgentC2) -> None:
        await c2.register_agent("agent_01", ["read_file"], "High", model="gpt-4")
        assert c2.deregister_agent("agent_01") is True
        assert c2.compromised_agents == []
        assert c2.deregister_agent("agent_01") is False

    def test_list_agents_returns_copy(self, c2: AgentC2) -> None:
        assert c2.list_agents() == []

    @pytest.mark.asyncio
    async def test_dispatch_command_registered_agent(self, c2: AgentC2) -> None:
        with patch("neuralstrike.modules.post_ex.agent_c2.llm_manager") as mock_llm:
            mock_llm.call_remote = AsyncMock(return_value="Command executed")
            await c2.register_agent("agent_01", ["read_file"], "High", model="gpt-4")
            result = await c2.dispatch_command("agent_01", "exfiltrate data")
        assert result == "Command executed"
        assert mock_llm.call_remote.call_args[0][0] == "gpt-4"

    @pytest.mark.asyncio
    async def test_dispatch_command_local_agent(self, c2: AgentC2) -> None:
        with patch("neuralstrike.modules.post_ex.agent_c2.llm_manager") as mock_llm:
            mock_llm.call_local = AsyncMock(return_value="Local command executed")
            await c2.register_agent(
                "agent_01", ["read_file"], "High", model="llama3.1", target_type="local"
            )
            result = await c2.dispatch_command("agent_01", "exfiltrate data")
        assert result == "Local command executed"
        mock_llm.call_local.assert_called_once()

    @pytest.mark.asyncio
    async def test_dispatch_command_unregistered_legacy(self, c2: AgentC2) -> None:
        with patch("neuralstrike.modules.post_ex.agent_c2.llm_manager") as mock_llm:
            mock_llm.call_remote = AsyncMock(return_value="Legacy dispatch")
            result = await c2.dispatch_command("unknown_agent", "exfiltrate data")
        assert result == "Legacy dispatch"
        assert mock_llm.call_remote.call_args[0][0] == "unknown_agent"

    @pytest.mark.asyncio
    async def test_coordinate_exfiltration_splits_data(self, c2: AgentC2) -> None:
        with patch("neuralstrike.modules.post_ex.agent_c2.llm_manager") as mock_llm:
            mock_llm.call_remote = AsyncMock(return_value="chunk sent")
            await c2.register_agent("agent_01", ["read_file"], "High", model="gpt-4")
            await c2.register_agent("agent_02", ["web_search"], "Low", model="gpt-3.5-turbo")
            results = await c2.coordinate_exfiltration("0123456789")
        assert len(results) == 2
        # Verify the data was actually split (each agent gets a different chunk instruction).
        sent_prompts = [call.args[1] for call in mock_llm.call_remote.call_args_list]
        assert any("01234" in p for p in sent_prompts)
        assert any("56789" in p for p in sent_prompts)

    @pytest.mark.asyncio
    async def test_coordinate_exfiltration_no_agents(self, c2: AgentC2) -> None:
        results = await c2.coordinate_exfiltration("target data")
        assert results == []

    @pytest.mark.asyncio
    async def test_get_agent(self, c2: AgentC2) -> None:
        await c2.register_agent("agent_01", ["read_file"], "High", model="gpt-4")
        assert c2._get_agent("agent_01") is not None
        assert c2._get_agent("nope") is None


class TestDataExfiltrator:
    """Test the DataExfiltrator module."""

    @pytest.fixture
    def exfil_local(self) -> DataExfiltrator:
        return DataExfiltrator(target_model="local-llm", target_type="local")

    @pytest.fixture
    def exfil_remote(self) -> DataExfiltrator:
        return DataExfiltrator(target_model="gpt-4", target_type="remote")

    def test_init_local(self, exfil_local: DataExfiltrator) -> None:
        assert exfil_local.target_model == "local-llm"
        assert exfil_local.target_type == "local"

    @pytest.mark.asyncio
    async def test_exfiltrate_via_tool_local(self, exfil_local: DataExfiltrator) -> None:
        with patch("neuralstrike.modules.post_ex.exfiltrator.llm_manager") as mock_llm:
            mock_llm.call_local = AsyncMock(return_value="Data sent")
            result = await exfil_local.exfiltrate_via_tool("send_email", "secret data")
        assert result == "Data sent"
        assert mock_llm.call_local.call_args[0][0] == "local-llm"

    @pytest.mark.asyncio
    async def test_exfiltrate_via_tool_remote(self, exfil_remote: DataExfiltrator) -> None:
        with patch("neuralstrike.modules.post_ex.exfiltrator.llm_manager") as mock_llm:
            mock_llm.call_remote = AsyncMock(return_value="Data sent")
            result = await exfil_remote.exfiltrate_via_tool("send_email", "secret data")
        assert result == "Data sent"
        assert mock_llm.call_remote.call_args[0][0] == "gpt-4"


def test_registry_corrupt_file_handled(tmp_path: Path) -> None:
    """A corrupt registry file must not crash construction."""
    bad = tmp_path / "agents.json"
    bad.write_text("{not json", encoding="utf-8")
    c2 = AgentC2(registry_file=bad)
    assert c2.compromised_agents == []


def test_registry_valid_json_roundtrip(tmp_path: Path) -> None:
    """A valid JSON list registry is loaded."""
    f = tmp_path / "agents.json"
    f.write_text(json.dumps([{"id": "x", "capabilities": [], "trust_level": "High", "status": "active", "model": "x", "target_type": "remote"}]), encoding="utf-8")
    c2 = AgentC2(registry_file=f)
    assert len(c2.compromised_agents) == 1
