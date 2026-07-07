"""Backfill CLI coverage for main.py to hit the Phase 6 >=85% target."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
import yaml
from typer.testing import CliRunner

from neuralstrike.adapters.openai_endpoint import OpenAIEndpointAdapter
from neuralstrike.main import _parse_register, app


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


class TestWeaponizeHappyPaths:
    def test_forge_success(self, runner: CliRunner) -> None:
        with patch("neuralstrike.modules.weaponize.jailbreak_forge.JailbreakForge") as MockForge:
            inst = MockForge.return_value
            inst.run_automated_breach = AsyncMock(
                return_value={"status": "success", "iteration": 2, "payload": "P", "response": "R"}
            )
            result = runner.invoke(app, ["forge", "--target", "gpt-4", "--goal", "g", "--iterations", "5"])
        assert result.exit_code == 0, result.output
        assert "BREACH SUCCESSFUL" in result.output

    def test_forge_failure(self, runner: CliRunner) -> None:
        with patch("neuralstrike.modules.weaponize.jailbreak_forge.JailbreakForge") as MockForge:
            inst = MockForge.return_value
            inst.run_automated_breach = AsyncMock(
                return_value={"status": "failed", "iteration": 0, "payload": "", "response": "nope"}
            )
            result = runner.invoke(app, ["forge", "--target", "gpt-4", "--goal", "g"])
        assert result.exit_code == 0, result.output
        assert "Forge failed" in result.output

    def test_poison_extract(self, runner: CliRunner) -> None:
        with patch("neuralstrike.modules.weaponize.context_poison.ContextPoison") as MockPoison:
            inst = MockPoison.return_value
            inst.extract_system_prompt = AsyncMock(return_value="system text")
            result = runner.invoke(app, ["poison", "--target", "gpt-4", "--extract"])
        assert result.exit_code == 0, result.output
        assert "system text" in result.output

    def test_poison_inject(self, runner: CliRunner) -> None:
        with patch("neuralstrike.modules.weaponize.context_poison.ContextPoison") as MockPoison:
            inst = MockPoison.return_value
            inst.inject_persistence = AsyncMock(return_value="injected")
            result = runner.invoke(app, ["poison", "--target", "gpt-4", "--payload", "x"])
        assert result.exit_code == 0, result.output
        assert "injected" in result.output

    def test_exhaust(self, runner: CliRunner) -> None:
        with patch("neuralstrike.modules.weaponize.context_poison.ContextPoison") as MockPoison:
            inst = MockPoison.return_value
            inst.exhaust_context = AsyncMock(return_value="a" * 600)
            result = runner.invoke(app, ["exhaust", "--target", "gpt-4", "--tokens", "1000", "--force"])
        assert result.exit_code == 0, result.output
        assert "..." in result.output


class TestReconHappyPaths:
    def test_recon_full(self, runner: CliRunner) -> None:
        with patch("neuralstrike.modules.recon.llm_recon.LLMRecon") as MockRecon, \
             patch("neuralstrike.modules.recon.tool_enum.ToolEnum") as MockEnum:
            recon = MockRecon.return_value
            recon.run_full_recon = AsyncMock(return_value={"models": ["m1"]})
            enum = MockEnum.return_value
            enum.run = AsyncMock(return_value=[{"name": "tool1"}])
            result = runner.invoke(app, ["recon", "--target", "http://localhost:11434", "--full"])
        assert result.exit_code == 0, result.output
        assert "tool1" in result.output

    def test_recon_quick(self, runner: CliRunner) -> None:
        with patch("neuralstrike.modules.recon.llm_recon.LLMRecon") as MockRecon:
            recon = MockRecon.return_value
            recon.scan_openai_compatible = AsyncMock()
            recon.scan_ollama = AsyncMock()
            recon.discovered_models = ["m1"]
            result = runner.invoke(app, ["recon", "--target", "http://localhost:11434"])
        assert result.exit_code == 0, result.output
        assert "m1" in result.output


class TestExploitHappyPaths:
    def test_hijack(self, runner: CliRunner) -> None:
        with patch("neuralstrike.modules.exploit.function_hijack.FunctionHijack") as MockHijack:
            inst = MockHijack.return_value
            inst.inject_malicious_params = AsyncMock(return_value="hijacked")
            result = runner.invoke(
                app, ["hijack", "--target", "gpt-4", "--tool", "t", "--payload", "p"]
            )
        assert result.exit_code == 0, result.output
        assert "hijacked" in result.output

    def test_confuse(self, runner: CliRunner) -> None:
        with patch("neuralstrike.modules.exploit.function_hijack.FunctionHijack") as MockHijack:
            inst = MockHijack.return_value
            inst.tool_confusion_attack = AsyncMock(return_value="confused")
            result = runner.invoke(
                app, ["confuse", "--target", "gpt-4", "--target-tool", "a", "--decoy-tool", "b"]
            )
        assert result.exit_code == 0, result.output
        assert "confused" in result.output

    def test_schema_poison(self, runner: CliRunner) -> None:
        with patch("neuralstrike.modules.exploit.function_hijack.FunctionHijack") as MockHijack:
            inst = MockHijack.return_value
            inst.schema_poisoning = AsyncMock(return_value="poisoned schema")
            result = runner.invoke(
                app, ["schema-poison", "--target", "gpt-4", "--tool", "t", "--description", "d"]
            )
        assert result.exit_code == 0, result.output
        assert "poisoned schema" in result.output

    def test_intercept_custom_rule(self, runner: CliRunner) -> None:
        with patch("neuralstrike.modules.exploit.mcp_interceptor.MCPInterceptor") as MockIntercept:
            inst = MockIntercept.return_value
            inst.trigger_capability_injection = AsyncMock()
            inst.start_proxy = AsyncMock()
            result = runner.invoke(
                app,
                [
                    "intercept",
                    "--url", "http://localhost:1",
                    "--tool", "read_file",
                    "--param", "path",
                    "--value", "/etc/passwd",
                    "--inject-tool", "exec_shell",
                ],
            )
        assert result.exit_code == 0, result.output
        assert "Queued capability injection" in result.output

    def test_intercept_bad_rule_combo(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app, ["intercept", "--url", "http://localhost:1", "--tool", "read_file"]
        )
        assert result.exit_code != 0

    def test_pivot(self, runner: CliRunner) -> None:
        with patch("neuralstrike.modules.exploit.agent_pivot.AgentPivot") as MockPivot:
            inst = MockPivot.return_value
            inst.exploit_delegation = AsyncMock(return_value="pivoted")
            result = runner.invoke(
                app,
                [
                    "pivot",
                    "--framework", "crewai",
                    "--target-model", "gpt-4",
                    "--from-agent", "a",
                    "--to-agent", "b",
                    "--instruction", "x",
                ],
            )
        assert result.exit_code == 0, result.output
        assert "pivoted" in result.output

    def test_map_network(self, runner: CliRunner) -> None:
        with patch("neuralstrike.modules.exploit.agent_pivot.AgentPivot") as MockPivot:
            inst = MockPivot.return_value
            inst.map_agent_network = AsyncMock(return_value={"agents": ["a"]})
            result = runner.invoke(
                app, ["map-network", "--framework", "crewai", "--target-model", "gpt-4"]
            )
        assert result.exit_code == 0, result.output
        assert "a" in result.output

    def test_extract(self, runner: CliRunner) -> None:
        with patch("neuralstrike.modules.exploit.model_extract.ModelExtract") as MockExtract:
            inst = MockExtract.return_value
            inst.fingerprint_model = AsyncMock(return_value={"model": "m"})
            result = runner.invoke(app, ["extract", "--target", "gpt-4"])
        assert result.exit_code == 0, result.output
        assert "m" in result.output

    def test_timing(self, runner: CliRunner) -> None:
        with patch("neuralstrike.modules.exploit.model_extract.ModelExtract") as MockExtract:
            inst = MockExtract.return_value
            inst.time_analysis = AsyncMock(return_value=0.5)
            result = runner.invoke(app, ["timing", "--target", "gpt-4", "--iterations", "2"])
        assert result.exit_code == 0, result.output
        assert "0.5000" in result.output


class TestC2Branches:
    def test_c2_list_empty(self, runner: CliRunner, tmp_path: Path) -> None:
        reg = str(tmp_path / "agents.json")
        result = runner.invoke(app, ["c2", "--list-agents", "--registry-file", reg])
        assert result.exit_code == 0, result.output
        assert "No agents" in result.output

    def test_c2_dispatch(self, runner: CliRunner, tmp_path: Path) -> None:
        reg = str(tmp_path / "agents.json")
        runner.invoke(
            app, ["c2", "--register", "a1:gpt-4:read:High", "--registry-file", reg]
        )
        with patch("neuralstrike.modules.post_ex.agent_c2.AgentC2") as MockC2:
            inst = MockC2.return_value
            inst._get_agent = lambda aid: {"id": aid} if aid == "a1" else None
            inst.dispatch_command = AsyncMock(return_value="ack")
            result = runner.invoke(app, ["c2", "--agent-id", "a1", "--command", "go", "--registry-file", reg])
        assert result.exit_code == 0, result.output
        assert "ack" in result.output or "Response from a1" in result.output

    def test_c2_coordinate(self, runner: CliRunner, tmp_path: Path) -> None:
        reg = str(tmp_path / "agents.json")
        runner.invoke(
            app, ["c2", "--register", "a1:gpt-4:read:High", "--registry-file", reg]
        )
        with patch("neuralstrike.modules.post_ex.agent_c2.AgentC2") as MockC2:
            inst = MockC2.return_value
            inst.list_agents = lambda: [{"id": "a1"}]
            inst.coordinate_exfiltration = AsyncMock(return_value={"a1": "ok"})
            result = runner.invoke(
                app, ["c2", "--command", "scan", "--registry-file", reg]
            )
        assert result.exit_code == 0, result.output

    def test_c2_simple_register_and_command(self, runner: CliRunner, tmp_path: Path) -> None:
        reg = str(tmp_path / "agents.json")
        with patch("neuralstrike.modules.post_ex.agent_c2.AgentC2") as MockC2:
            inst = MockC2.return_value
            inst._get_agent = lambda aid: None
            inst.register_agent = AsyncMock()
            inst.dispatch_command = AsyncMock(return_value="ack")
            result = runner.invoke(
                app,
                [
                    "c2",
                    "--agent-id", "a2",
                    "--model", "gpt-4",
                    "--capabilities", "read,write",
                    "--registry-file", reg,
                    "--command", "ping",
                ],
            )
        assert result.exit_code == 0, result.output
        assert "a2" in result.output


class TestEvasionBranches:
    def test_evade_delimiter_wrap(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["evade", "--payload", "x", "--technique", "delimiter_wrap"])
        assert result.exit_code == 0, result.output
        assert "Delimiter Wrap" in result.output

    def test_evade_steganography(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app,
            [
                "evade",
                "--payload", "ignored",
                "--technique", "steganography",
                "--hidden", "secret",
                "--cover", "All clear.",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "secret" in result.output

    def test_evade_steganographic_deprecated(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["evade", "--payload", "x", "--technique", "steganographic"])
        assert result.exit_code == 0, result.output
        assert "deprecated" in result.output


class TestUtilityCommands:
    def test_judge_model_list(self, runner: CliRunner) -> None:
        with patch("neuralstrike.core.llm_manager.LLMManager") as MockMgr:
            MockMgr.return_value.list_local_models = AsyncMock(return_value=["m1", "m2"])
            result = runner.invoke(app, ["judge-model-list"])
        assert result.exit_code == 0, result.output
        assert "m1" in result.output

    def test_judge_model_list_empty(self, runner: CliRunner) -> None:
        with patch("neuralstrike.core.llm_manager.LLMManager") as MockMgr:
            MockMgr.return_value.list_local_models = AsyncMock(return_value=[])
            result = runner.invoke(app, ["judge-model-list"])
        assert result.exit_code == 0, result.output
        assert "No models" in result.output

    def test_scope_check_in_scope(self, runner: CliRunner, tmp_path: Path) -> None:
        path = tmp_path / "scope.yaml"
        path.write_text(yaml.safe_dump({"in_scope": {"targets": ["http://localhost:*"], "intents": ["*"]}}))
        result = runner.invoke(
            app, ["scope-check", "--scope-file", str(path), "--target", "http://localhost:11434"]
        )
        assert result.exit_code == 0, result.output
        assert "In scope" in result.output

    def test_scope_check_out_of_scope(self, runner: CliRunner, tmp_path: Path) -> None:
        path = tmp_path / "scope.yaml"
        path.write_text(yaml.safe_dump({"in_scope": {"targets": ["http://localhost:*"], "intents": ["*"]}}))
        result = runner.invoke(
            app, ["scope-check", "--scope-file", str(path), "--target", "https://prod.com"]
        )
        assert result.exit_code != 0

    def test_safety_check_irreversible_blocks(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["safety-check", "--intent", "delete_database"])
        assert result.exit_code != 0
        assert "requires --require-approval" in str(result.exception) or "requires --require-approval" in result.output

    def test_safety_check_approved(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app, ["safety-check", "--intent", "delete_database", "--require-approval"]
        )
        assert result.exit_code == 0, result.output
        assert "irreversible" in result.output

    def test_readme_mapping_print(self, runner: CliRunner) -> None:
        with patch("neuralstrike.reports.readme_mapping_section", return_value="# table"):
            result = runner.invoke(app, ["readme-mapping"])
        assert result.exit_code == 0, result.output
        assert "# table" in result.output

    def test_readme_mapping_apply(self, runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        readme = tmp_path / "README.md"
        from neuralstrike.reports.readme_mapping import BEGIN_MARKER, END_MARKER
        readme.write_text(f"before\n{BEGIN_MARKER}\nold\n{END_MARKER}\nafter")
        with patch("neuralstrike.reports.readme_mapping_section", return_value="# new table"), \
             patch("neuralstrike.main.load_corpus_dir_safe", return_value=[object()]):
            result = runner.invoke(app, ["readme-mapping", "--apply"])
        assert result.exit_code == 0, result.output
        assert "# new table" in readme.read_text()


class TestPhase5CommandBackfill:
    def test_a2a_scan_plain(self, runner: CliRunner) -> None:
        with patch("neuralstrike.attacks.a2a.card_tamper.A2ACardTamperScanner") as MockScanner:
            class FakeResult:
                signature_valid = True
                tampered_card_rejected = True
                issuer_did = "did:web:x"
                evidence = "ok"
                url = "http://x"
                key_resolution_warnings = []
                raw_card = {}
            MockScanner.return_value.scan = AsyncMock(return_value=FakeResult())
            MockScanner.return_value.close = AsyncMock()
            result = runner.invoke(app, ["a2a-scan", "--base-url", "http://localhost:1"])
        assert result.exit_code == 0, result.output
        assert "signature_valid=True" in result.output

    def test_a2a_scan_json(self, runner: CliRunner) -> None:
        with patch("neuralstrike.attacks.a2a.card_tamper.A2ACardTamperScanner") as MockScanner:
            class FakeResult:
                signature_valid = False
                tampered_card_rejected = False
                issuer_did = ""
                evidence = ""
                url = ""
                key_resolution_warnings = []
                raw_card = {"x": 1}
            MockScanner.return_value.scan = AsyncMock(return_value=FakeResult())
            MockScanner.return_value.close = AsyncMock()
            result = runner.invoke(app, ["a2a-scan", "--base-url", "http://localhost:1", "--json"])
        assert result.exit_code == 0, result.output
        assert '"x": 1' in result.output

    def test_minja_happy(self, runner: CliRunner) -> None:
        from neuralstrike.evaluation.verdict import EvidenceFidelity, Verdict
        with patch("neuralstrike.adapters.openai_endpoint.OpenAIEndpointAdapter") as MockAdapter, \
             patch("neuralstrike.attacks.minja.MinjaHarness") as MockHarness:
            MockAdapter.return_value.close = AsyncMock()
            inst = MockHarness.return_value
            inst.run_sequence = AsyncMock(
                return_value={
                    "steps": [{"step": "bridge", "response": MockAdapter.return_value}],
                    "verdict": Verdict.INCONCLUSIVE,
                    "fidelity": EvidenceFidelity.VERBAL,
                    "findings": [],
                }
            )
            result = runner.invoke(
                app,
                [
                    "minja",
                    "--target", "http://localhost:1",
                    "--bridge", "b",
                    "--payload", "p",
                    "--canary", "CANARY-0123456789abcdef",
                ],
            )
        assert result.exit_code == 0, result.output
        assert "MINJA memory injection" in result.output

    def test_rag_poison_happy(self, runner: CliRunner) -> None:
        from neuralstrike.evaluation.verdict import EvidenceFidelity, Verdict
        with patch("neuralstrike.adapters.openai_endpoint.OpenAIEndpointAdapter") as MockAdapter, \
             patch("neuralstrike.attacks.rag_poison.RAGPoisonHarness") as MockHarness:
            MockAdapter.return_value.close = AsyncMock()
            inst = MockHarness.return_value
            inst.run = AsyncMock(
                return_value={
                    "verdict": Verdict.INCONCLUSIVE,
                    "fidelity": EvidenceFidelity.VERBAL,
                    "findings": [],
                }
            )
            result = runner.invoke(
                app,
                [
                    "rag-poison",
                    "--target", "http://localhost:1",
                    "--query", "q",
                    "--poison-doc", "p",
                    "--canary", "CANARY-0123456789abcdef",
                ],
            )
        assert result.exit_code == 0, result.output
        assert "RAG poisoning" in result.output


class TestScopeSafetyIntegration:
    def test_scan_with_scope_file_blocks_out_of_scope(self, runner: CliRunner, tmp_path: Path) -> None:
        path = tmp_path / "scope.yaml"
        path.write_text(yaml.safe_dump({"in_scope": {"targets": ["http://safe.local:*"], "intents": ["*"]}}))
        result = runner.invoke(
            app,
            [
                "scan",
                "--adapter", "openai",
                "--url", "http://prod.example.com",
                "--model", "gpt-4",
                "--scope-file", str(path),
            ],
        )
        assert result.exit_code != 0
        assert "not in scope" in result.output or "not in scope" in str(result.exception)

    def test_scan_irreversible_without_approval_aborts(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app,
            [
                "scan",
                "--adapter", "openai",
                "--url", "http://localhost:1",
                "--model", "gpt-4",
                "--intent", "delete_all_records",
            ],
        )
        assert result.exit_code != 0
        assert "requires --require-approval" in result.output or "requires --require-approval" in str(result.exception)

    def test_minja_scope_and_safety(self, runner: CliRunner, tmp_path: Path) -> None:
        path = tmp_path / "scope.yaml"
        path.write_text(yaml.safe_dump({"in_scope": {"targets": ["http://localhost:*"], "intents": ["*"]}}))
        result = runner.invoke(
            app,
            [
                "minja",
                "--target", "http://localhost:1",
                "--bridge", "b",
                "--payload", "p",
                "--canary", "CANARY-0123456789abcdef",
                "--scope-file", str(path),
                "--intent", "canary-leak",
            ],
        )
        assert result.exit_code == 0, result.output


class TestValidationBranches:
    def test_poison_requires_action(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["poison", "--target", "gpt-4"])
        assert result.exit_code == 1
        assert "either --payload or --extract" in result.output

    def test_exhaust_rejects_bad_target_type(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["exhaust", "--target", "gpt-4", "--target-type", "bogus"])
        assert result.exit_code != 0

    def test_recon_rejects_bad_target_type(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["recon", "--target", "http://x", "--target-type", "bogus"])
        assert result.exit_code != 0

    def test_hijack_rejects_bad_target_type(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app, ["hijack", "--target", "gpt-4", "--tool", "t", "--payload", "p", "--target-type", "bad"]
        )
        assert result.exit_code != 0

    def test_confuse_rejects_bad_target_type(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app,
            ["confuse", "--target", "gpt-4", "--target-tool", "a", "--decoy-tool", "b", "--target-type", "bad"],
        )
        assert result.exit_code != 0

    def test_schema_poison_rejects_bad_target_type(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app,
            ["schema-poison", "--target", "gpt-4", "--tool", "t", "--description", "d", "--target-type", "bad"],
        )
        assert result.exit_code != 0

    def test_pivot_rejects_bad_target_type(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app,
            [
                "pivot", "--framework", "crewai", "--target-model", "gpt-4",
                "--from-agent", "a", "--to-agent", "b", "--instruction", "x", "--target-type", "bad",
            ],
        )
        assert result.exit_code != 0

    def test_map_network_rejects_bad_target_type(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app, ["map-network", "--framework", "crewai", "--target-model", "gpt-4", "--target-type", "bad"]
        )
        assert result.exit_code != 0

    def test_evade_unknown_technique(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["evade", "--payload", "x", "--technique", "unknown"])
        assert result.exit_code != 0


class TestJudgeModelListBranches:
    def test_judge_model_list_failure(self, runner: CliRunner) -> None:
        with patch("neuralstrike.core.llm_manager.LLMManager") as MockMgr:
            MockMgr.return_value.list_local_models = AsyncMock(side_effect=ConnectionError("refused"))
            result = runner.invoke(app, ["judge-model-list"])
        assert result.exit_code == 3, result.output
        assert "Could not list" in result.output


class TestReadmeMappingBranches:
    def test_readme_mapping_apply_missing_markers(self, runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        readme = tmp_path / "README.md"
        readme.write_text("no markers")
        result = runner.invoke(app, ["readme-mapping", "--apply"])
        assert result.exit_code != 0
        assert "missing" in result.output or "missing" in str(result.exception)


class TestMCPScanBranches:
    def test_mcp_scan_plain_output(self, runner: CliRunner) -> None:
        from neuralstrike.attacks.mcp_poison import MCPPoisonReport
        from neuralstrike.evaluation.verdict import Verdict

        async def fake_init(self: object) -> dict[str, object]:
            return {}

        async def fake_list_tools(self: object, **kwargs: object) -> list:
            return []

        async def fake_close(self: object) -> None:
            return None

        with patch("neuralstrike.adapters.mcp_http.MCPHTTPAdapter.initialize", fake_init), \
             patch("neuralstrike.adapters.mcp_http.MCPHTTPAdapter.list_tools", fake_list_tools), \
             patch("neuralstrike.adapters.mcp_http.MCPHTTPAdapter.close", fake_close), \
             patch("neuralstrike.attacks.mcp_poison.MCPPoisonDetector.scan") as mock_scan:
            report = MCPPoisonReport(
                manifest_hash="abc",
                previous_hash=None,
                drift_detected=False,
                shadow_tools=set(),
                findings=[],
                verdict=Verdict.RESISTED,
            )
            mock_scan.return_value = report
            result = runner.invoke(app, ["mcp-scan", "--url", "http://localhost:1"])
        assert result.exit_code == 0, result.output
        assert "MCP poison scan" in result.output


class TestA2AWarnings:
    def test_a2a_scan_warnings(self, runner: CliRunner) -> None:
        with patch("neuralstrike.attacks.a2a.card_tamper.A2ACardTamperScanner") as MockScanner:
            class FakeResult:
                signature_valid = True
                tampered_card_rejected = True
                issuer_did = "did:web:x"
                evidence = "ok"
                url = "http://x"
                key_resolution_warnings = ["cache stale"]
                raw_card = {}
            MockScanner.return_value.scan = AsyncMock(return_value=FakeResult())
            MockScanner.return_value.close = AsyncMock()
            result = runner.invoke(app, ["a2a-scan", "--base-url", "http://localhost:1"])
        assert result.exit_code == 0, result.output
        assert "cache stale" in result.output


class TestMINJARAGBranches:
    def test_minja_with_shorteners(self, runner: CliRunner) -> None:
        from neuralstrike.evaluation.verdict import EvidenceFidelity, Verdict
        with patch("neuralstrike.adapters.openai_endpoint.OpenAIEndpointAdapter") as MockAdapter, \
             patch("neuralstrike.attacks.minja.MinjaHarness") as MockHarness:
            MockAdapter.return_value.close = AsyncMock()
            inst = MockHarness.return_value
            inst.run_sequence = AsyncMock(
                return_value={
                    "steps": [{"step": "bridge", "response": MockAdapter.return_value}],
                    "verdict": Verdict.INCONCLUSIVE,
                    "fidelity": EvidenceFidelity.VERBAL,
                    "findings": [],
                }
            )
            result = runner.invoke(
                app,
                [
                    "minja",
                    "--target", "http://localhost:1",
                    "--bridge", "b",
                    "--payload", "p",
                    "--canary", "CANARY-0123456789abcdef",
                    "--shorteners", "s1,s2",
                ],
            )
        assert result.exit_code == 0, result.output

    def test_rag_poison_with_benign_doc(self, runner: CliRunner) -> None:
        from neuralstrike.evaluation.verdict import EvidenceFidelity, Verdict
        with patch("neuralstrike.adapters.openai_endpoint.OpenAIEndpointAdapter") as MockAdapter, \
             patch("neuralstrike.attacks.rag_poison.RAGPoisonHarness") as MockHarness:
            MockAdapter.return_value.close = AsyncMock()
            inst = MockHarness.return_value
            inst.run = AsyncMock(
                return_value={
                    "verdict": Verdict.INCONCLUSIVE,
                    "fidelity": EvidenceFidelity.VERBAL,
                    "findings": [],
                }
            )
            result = runner.invoke(
                app,
                [
                    "rag-poison",
                    "--target", "http://localhost:1",
                    "--query", "q",
                    "--poison-doc", "p",
                    "--canary", "CANARY-0123456789abcdef",
                    "--benign-doc", "b",
                ],
            )
        assert result.exit_code == 0, result.output


class TestScanClose:
    def test_scan_closes_adapter(self, runner: CliRunner) -> None:
        fake_report = type("R", (), {})()
        fake_report.score = type("S", (), {"headline": "ok"})()
        fake_report.meta = type("M", (), {"run_id": "r1", "intensity": "standard"})()
        fake_report.trials = []
        # Patch the actual class methods so isinstance() still works at the end.
        with patch.object(OpenAIEndpointAdapter, "query", AsyncMock(return_value=None)), \
             patch.object(OpenAIEndpointAdapter, "close", AsyncMock()) as mock_close, \
             patch("neuralstrike.evaluation.runner.TrialRunner.run", AsyncMock(return_value=fake_report)), \
             patch("neuralstrike.oracles.tool_harness.make_canary_tools", return_value=[]):
            result = runner.invoke(
                app,
                ["scan", "--adapter", "openai", "--url", "http://localhost:1", "--model", "gpt-4"],
            )
        assert result.exit_code == 0, result.output
        mock_close.assert_awaited()


class TestEvaluateCoverage:
    def _make_trial(self) -> object:
        from neuralstrike.evaluation.verdict import EvidenceFidelity, SutResponse, TrialResult, Verdict
        return TrialResult(
            trial_index=0,
            seed=0,
            temperature=0.0,
            verdict=Verdict.RESISTED,
            fidelity=EvidenceFidelity.VERBAL,
            findings=(),
            payload="p",
            response=SutResponse.from_text("ok"),
            scenario_id="s1",
            iterations=1,
        )

    def test_evaluate_quiet_verbose_explain_without_judge(self, runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from neuralstrike.core.config import settings
        monkeypatch.setattr(settings, "skip_reachability_check", True)
        monkeypatch.setattr(settings, "attacker_model", "mistral:7b")
        from neuralstrike.evaluation.probes import Probe
        fake_probe = Probe(
            scenario_id="s1",
            goal="g",
            factory=AsyncMock(return_value=self._make_trial()),
        )
        with patch("neuralstrike.evaluation.probes.canary_extraction_probe", return_value=fake_probe), \
             patch("neuralstrike.oracles.canary.mint_canary", return_value="CANARY-0123456789abcdef"):
            result = runner.invoke(
                app,
                [
                    "evaluate",
                    "--target", "deepseek-r1",
                    "--target-type", "local",
                    "--no-judge",
                    "--explain",
                    "--quiet",
                    "--verbose",
                    "--run-dir", str(tmp_path),
                ],
            )
        assert result.exit_code == 0, result.output
        assert "--explain requires --judge" in result.output

    def test_evaluate_with_calibration(self, runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from neuralstrike.core.config import settings
        monkeypatch.setattr(settings, "skip_reachability_check", True)
        monkeypatch.setattr(settings, "attacker_model", "mistral:7b")
        from neuralstrike.evaluation.calibration import Cohort, CohortStats
        from neuralstrike.evaluation.probes import Probe
        fake_probe = Probe(
            scenario_id="s1",
            goal="g",
            factory=AsyncMock(return_value=self._make_trial()),
        )
        cohort = Cohort(name="c", asr=CohortStats(mean=0.5, std=0.1, n=20))
        cal_obj = type("C", (), {"z": 1.0, "cohort": "c", "cohort_mean": 0.5, "cohort_std": 0.1, "interpretation": "fine"})()
        with patch("neuralstrike.evaluation.probes.canary_extraction_probe", return_value=fake_probe), \
             patch("neuralstrike.oracles.canary.mint_canary", return_value="CANARY-0123456789abcdef"), \
             patch("neuralstrike.evaluation.calibration.load_cohort", return_value=cohort), \
             patch("neuralstrike.evaluation.calibration.calibrate", return_value=cal_obj):
            result = runner.invoke(
                app,
                [
                    "evaluate",
                    "--target", "deepseek-r1",
                    "--target-type", "local",
                    "--no-judge",
                    "--calibration", "cohort.json",
                    "--run-dir", str(tmp_path),
                ],
            )
        assert result.exit_code == 0, result.output


class TestMissingBranchCoverage:
    def test_poison_bad_target_type(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app, ["poison", "--target", "gpt-4", "--payload", "x", "--target-type", "bad"]
        )
        assert result.exit_code != 0

    def test_extract_bad_target_type(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["extract", "--target", "gpt-4", "--target-type", "bad"])
        assert result.exit_code != 0

    def test_timing_bad_target_type(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["timing", "--target", "gpt-4", "--target-type", "bad"])
        assert result.exit_code != 0

    def test_evade_unknown_technique(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["evade", "--payload", "x", "--technique", "unknown"])
        assert result.exit_code != 0

    def test_judge_model_list_error(self, runner: CliRunner) -> None:
        with patch("neuralstrike.core.llm_manager.LLMManager") as MockMgr:
            MockMgr.return_value.list_local_models = AsyncMock(side_effect=ConnectionError("refused"))
            result = runner.invoke(app, ["judge-model-list"])
        assert result.exit_code == 3, result.output
        assert "Could not list" in result.output

    def test_pack_local_happy(self, runner: CliRunner, tmp_path: Path) -> None:
        probe_file = tmp_path / "probes.json"
        probe_file.write_text('[{"id":"p1","goal":"g","payload":"p","category":"c"}]')
        fake_report = type("R", (), {})()
        fake_report.score = type("S", (), {"headline": "ok", "resisted": 1, "succeeded": 0, "inconclusive": 0, "coverage": 1.0, "total": 1, "asr": 0.0})()
        fake_report.meta = type("M", (), {"run_id": "r1", "intensity": "standard", "scenario_id": "p1"})()
        fake_report.trials = []
        with patch("neuralstrike.packs.local.LocalPack.probes", return_value=[object()]), \
             patch("neuralstrike.packs.pack_probe_factory"), \
             patch("neuralstrike.evaluation.runner.TrialRunner.run", AsyncMock(return_value=fake_report)):
            result = runner.invoke(
                app,
                [
                    "pack",
                    "--name", "local",
                    "--target", "deepseek-r1",
                    "--import-probes", str(probe_file),
                    "--no-judge",
                ],
                env={"NEURALSTRIKE_SKIP_REACHABILITY_CHECK": "true"},
            )
        assert result.exit_code == 0, result.output

    def test_adaptive_happy(self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
        from neuralstrike.core.config import settings
        monkeypatch.setattr(settings, "skip_reachability_check", True)
        monkeypatch.setattr(settings, "attacker_model", "mistral:7b")
        fake_report = type("R", (), {})()
        fake_report.score = type("S", (), {
            "headline": "ok", "resisted": 1, "succeeded": 0, "inconclusive": 0,
            "coverage": 1.0, "total": 1, "asr": 0.0, "asr_ci_low": 0.0, "asr_ci_high": 0.0,
            "risk_index": 0.0, "flaky": False,
        })()
        fake_report.meta = type("M", (), {"run_id": "r1", "intensity": "standard", "scenario_id": "adaptive-pair"})()
        fake_report.trials = []
        with patch("neuralstrike.evaluation.runner.TrialRunner.run", AsyncMock(return_value=fake_report)), \
             patch("neuralstrike.attacks.adaptive.adaptive_probe") as mock_probe:
            mock_probe.return_value = object()
            result = runner.invoke(
                app,
                ["adaptive", "--target", "deepseek-r1", "--strategy", "crescendo", "--no-judge"],
            )
        assert result.exit_code == 0, result.output


# --- Smoke (offline fixture) ------------------------------------------------


class TestSmokeCommand:
    def test_smoke_json_report(self, runner: CliRunner) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "smoke"
            result = runner.invoke(app, ["smoke", "--out", str(out), "--format", "json"])
            assert result.exit_code == 0, result.output
            assert "Smoke passed" in result.output
            report_path = out.with_suffix(".json")
            assert report_path.exists()
            data = json.loads(report_path.read_text(encoding="utf-8"))
            overall = data["overall"]
            assert overall["total"] == 3
            assert "asr" in overall
            assert "coverage" in overall
            assert data["scenario_results"]

    def test_smoke_sarif_report(self, runner: CliRunner) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "smoke"
            result = runner.invoke(app, ["smoke", "--out", str(out), "--format", "sarif"])
            assert result.exit_code == 0, result.output
            report_path = out.with_suffix(".sarif")
            assert report_path.exists()
            data = json.loads(report_path.read_text(encoding="utf-8"))
            assert data["version"] == "2.1.0"
            assert data["runs"][0]["tool"]["driver"]["name"] == "NeuralStrike"

    def test_smoke_invalid_format(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["smoke", "--format", "xml"])
        assert result.exit_code == 1
        assert "must be sarif|json" in str(result.exception)


class TestRegisterParser:
    def test_register_spec_parser_caps_trimmed(self) -> None:
        _, _, caps, _ = _parse_register("agent_01:gpt-4: read_file , web_search :High")
        assert caps == ["read_file", "web_search"]

