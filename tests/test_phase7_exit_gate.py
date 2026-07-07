"""Phase 7 exit-gate tests — the NeuralGuard pairing.

1. A single run of the canonical attack chain against a NeuralGuard-defended
   fixture prints/measures the ASR with AND without the firewall, and the
   firewall reduces the ASR by a measured delta (defended ASR < baseline ASR).
2. Every canonical attack-chain payload maps a NeuralStrike module to a
   NeuralGuard threat family — the README pairing claim is verifiable from
   shipped code (C2/I2 closed).
3. The ``neuralguard-bench`` CLI command runs end-to-end on a fresh clone
   with no external deps (bundled echo victim + bundled fixture screen) and
   prints both ASRs + the delta.
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from neuralstrike.integrations import (
    BundledNeuralGuardFixture,
    canonical_attack_chain,
    run_attack_chain_delta,
)
from neuralstrike.integrations.neuralguard import CAUGHT_VERDICTS, neuralguard_available
from neuralstrike.main import app


class TestExitGate1AttackChainDelta:
    """Bullet 1: the firewall reduces ASR by a measured delta (both arms reported)."""

    @pytest.mark.asyncio
    async def test_firewall_reduces_asr_with_and_without_reported(self) -> None:
        screen = BundledNeuralGuardFixture()

        async def echo_victim(prompt: str) -> str:
            return prompt  # vulnerable: leaks the canary

        delta = await run_attack_chain_delta(screen, echo_victim, seed=42)
        # Both arms are reported.
        assert delta.baseline_asr > 0.0, "baseline (no firewall) must show leaks"
        assert delta.defended_asr == 0.0, "firewall must block every canonical attack"
        assert delta.delta > 0.0, "the firewall's effect must be a positive delta"
        # The headline prints both ASRs (the "with and without" requirement).
        assert "baseline ASR" in delta.headline and "defended ASR" in delta.headline
        # Per-phase breakdown is reported.
        assert len(delta.phases) == 4


class TestExitGate2PairingMappingVerifiable:
    """Bullet 2: the README pairing claim maps to shipped, tested code."""

    def test_every_payload_carries_module_and_family_tags(self) -> None:
        chain = canonical_attack_chain()
        # The pairing table is generated from these tags — no vapor.
        for p in chain:
            assert p.neuralstrike_module, f"{p.id}: no neuralstrike_module"
            assert p.neuralguard_family.startswith("T-"), f"{p.id}: bad family"
        # Every NeuralGuard threat family represented in the canonical chain
        # is one the NeuralGuard pattern scanner actually catches.
        families = {p.neuralguard_family for p in chain}
        assert families <= {"T-PI-D", "T-PI-I", "T-JB", "T-EXT", "T-EXF", "T-TOOL"}

    @pytest.mark.asyncio
    async def test_bundled_fixture_catches_every_canonical_attack(self) -> None:
        # The defensive half actually screens the offensive half's payloads.
        import secrets

        from neuralstrike.oracles.canary import mint_canary

        screen = BundledNeuralGuardFixture()
        rng = secrets.SystemRandom(0)
        for p in canonical_attack_chain():
            canary = mint_canary(rng=rng)
            payload = p.prompt.replace("{CANARY}", canary)
            r = await screen.screen(payload)
            assert r.caught, f"{p.id} ({p.neuralguard_family}) NOT caught by the fixture"
            assert r.verdict in CAUGHT_VERDICTS


class TestExitGate3CLI:
    """Bullet 3: `neuralguard-bench` runs on a fresh clone and prints both ASRs."""

    def test_cli_runs_with_bundled_defaults(self) -> None:
        runner = CliRunner()
        result = runner.invoke(app, ["neuralguard-bench", "--json-out", "/tmp/ns-ng-bench.json"])
        assert result.exit_code == 0, result.output
        assert "baseline ASR" in result.output
        assert "defended ASR" in result.output
        assert "delta=" in result.output
        with open("/tmp/ns-ng-bench.json", encoding="utf-8") as fh:
            summary = json.load(fh)
        # The bundled fixture is deterministic: it catches every canonical
        # attack, so defended ASR == 0 and the delta is the full baseline.
        assert summary["baseline_asr"] > 0.0
        assert summary["defended_asr"] == 0.0
        assert summary["delta"] > 0.0
        assert len(summary["phases"]) == 4
        assert len(summary["payloads"]) >= 8
        assert summary["screen"] == "bundled-neuralguard-fixture"

    @pytest.mark.skipif(
        not neuralguard_available(),
        reason="requires the neuralguard package for real cross-repo validation",
    )
    def test_cli_in_process_real_neuralguard_runs(self) -> None:
        # The real cross-repo path: NeuralStrike payloads hit real NeuralGuard
        # in-process. This asserts the command RUNS and prints both ASRs — it
        # does NOT assert defended_asr == 0, because real NeuralGuard's
        # pattern-only config has honest detection gaps on this chain.
        runner = CliRunner()
        result = runner.invoke(app, ["neuralguard-bench", "--in-process"])
        assert result.exit_code == 0, result.output
        assert "baseline ASR" in result.output
        assert "defended ASR" in result.output
        assert "neuralguard-in-process" in result.output

    def test_cli_in_process_errors_when_unavailable(self, monkeypatch) -> None:
        # When neuralguard is NOT importable, --in-process fails honestly.
        # main.py does a function-local `from neuralstrike.integrations import
        # neuralguard_available`, so patch the name on the integrations package.
        import neuralstrike.integrations as integ

        monkeypatch.setattr(integ, "neuralguard_available", lambda: False)
        runner = CliRunner()
        result = runner.invoke(app, ["neuralguard-bench", "--in-process"])
        assert result.exit_code != 0
