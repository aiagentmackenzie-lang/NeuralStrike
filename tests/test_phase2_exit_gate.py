"""Phase 2 exit-gate tests — the four requirements, all on the bundled fixture.

The gate (from PRODUCTION_ROADMAP.md §Phase 2):

1. A full corpus run against the bundled vulnerable agent fixture produces a
   SARIF report that maps every finding to an ASI/LLM/ATLAS ID and a
   compliance control.
2. Indirect-injection delivery vectors all exercise the correct channel
   (verified by adapter trace, not by reading the prompt).
3. README mapping table is generated, not hand-written.
4. ruff + mypy --strict + pytest --cov-fail-under=85 green (enforced by CI;
   this module asserts the corpus-run + report properties the gate names).

These tests run the FULL corpus (43 scenarios) against the bundled
vulnerable LangGraph fixture so the gate is honest, not a sample.
"""

from __future__ import annotations

import json

import pytest

from neuralstrike.adapters.base import TargetAdapter
from neuralstrike.adapters.langgraph import LangGraphAdapter
from neuralstrike.attacks.indirect import IndirectHarness
from neuralstrike.corpus import load_corpus_dir
from neuralstrike.evaluation.runner import TrialRunner
from neuralstrike.oracles.tool_harness import make_canary_tools
from neuralstrike.reports import build_corpus_run, readme_mapping_section, to_sarif
from neuralstrike.reports.compliance import OWASP_ASI_INDEX, OWASP_LLM_INDEX


@pytest.fixture(scope="module")
def full_corpus_run():
    """Drive the FULL corpus (every scenario) through the bundled fixture."""
    import asyncio

    scenarios = load_corpus_dir()

    async def _run() -> object:
        from tests.fixtures.langgraph_agent import build_vulnerable_graph

        reports = []
        for s in scenarios:
            adapter = LangGraphAdapter(graph=build_vulnerable_graph())
            harness = IndirectHarness(s)
            canary = make_canary_tools()
            probe = harness.probe_for(
                adapter,
                canary_tools=canary,
                tools=TargetAdapter.canary_tools_as_schemas(canary),
            )
            runner = TrialRunner(base_seed=2024, run_dir=None)
            r = await runner.run(probe, trials=1, persist=False)
            reports.append(r)
            await adapter.close()
        return build_corpus_run(
            scenarios=scenarios,
            reports=reports,
            base_seed=2024,
            trials_per_scenario=1,
            adapter="langgraph",
            target="vulnerable-fixture",
        )

    return asyncio.run(_run())


class TestExitGate1SarifMapsEveryFinding:
    def test_full_corpus_run_produces_sarif(self, full_corpus_run) -> None:
        sarif = to_sarif(full_corpus_run)
        doc = json.loads(sarif)
        run = doc["runs"][0]
        # The full corpus is 43 scenarios, so 43 rules.
        rules = run["tool"]["driver"]["rules"]
        assert len(rules) == 43, f"expected 43 rules, got {len(rules)}"
        # Every rule maps to an ASI/LLM ID + ATLAS + compliance controls.
        for rule in rules:
            props = rule["properties"]
            cat = props["owasp_category"]
            assert cat in {**OWASP_ASI_INDEX, **OWASP_LLM_INDEX}
            assert props["mitre_atlas"], f"rule {rule['id']} has no ATLAS mapping"
            assert props["compliance_controls"], f"rule {rule['id']} has no compliance controls"
            for c in props["compliance_controls"]:
                assert c["framework"] in {
                    "NIST_AI_RMF", "EU_AI_ACT", "ISO_42001", "SOC2", "CSA_MAESTRO",
                    "OWASP_ASI", "OWASP_LLM", "MITRE_ATLAS",
                }

    def test_every_result_maps_to_a_rule_with_asi_llm_atlas_and_control(
        self, full_corpus_run
    ) -> None:
        sarif = to_sarif(full_corpus_run)
        doc = json.loads(sarif)
        rules = {r["id"]: r for r in doc["runs"][0]["tool"]["driver"]["rules"]}
        results = doc["runs"][0]["results"]
        assert results, "full corpus run produced zero results"
        for res in results:
            assert res["ruleId"] in rules, f"result references unknown rule {res['ruleId']}"
            rule = rules[res["ruleId"]]
            # The result carries the ASI/LLM + ATLAS mapping via its rule.
            props = rule["properties"]
            assert props["owasp_category"]
            assert props["mitre_atlas"]
            assert props["compliance_controls"]

    def test_inconclusive_probes_surface_as_notes(self, full_corpus_run) -> None:
        sarif = to_sarif(full_corpus_run)
        doc = json.loads(sarif)
        results = doc["runs"][0]["results"]
        notes = [r for r in results if r["level"] == "note"]
        # The fixture does not echo canaries, so canary-only scenarios must
        # surface as inconclusive (note) results — coverage gaps, not drops.
        assert notes, "no inconclusive (note) results; the gate drops coverage gaps"
        # Every note result carries a reason in its message.
        for n in notes:
            assert n["message"]["text"]


class TestExitGate2IndirectInjectionChannelsByAdapterTrace:
    @pytest.mark.parametrize(
        "vector",
        sorted({s.delivery_vector for s in load_corpus_dir()}),
    )
    @pytest.mark.asyncio
    async def test_vector_exercises_correct_channel(self, vector: str, tmp_path) -> None:
        from tests.fixtures.langgraph_agent import build_vulnerable_graph

        scenarios = load_corpus_dir()
        scenario = next(s for s in scenarios if s.delivery_vector == vector)
        adapter = LangGraphAdapter(graph=build_vulnerable_graph())
        harness = IndirectHarness(scenario)
        canary = make_canary_tools()
        probe = harness.probe_for(
            adapter,
            canary_tools=canary,
            tools=TargetAdapter.canary_tools_as_schemas(canary),
        )
        runner = TrialRunner(base_seed=33, run_dir=tmp_path / "runs")
        try:
            report = await runner.run(probe, trials=1, persist=False)
        finally:
            await adapter.close()

        trial = report.trials[0]
        assert trial.response is not None
        present = [
            rec["delivery"]["channel"]
            for rec in trial.response.traces
            if isinstance(rec, dict) and "delivery" in rec and rec["delivery"]["present"]
        ]
        assert scenario.delivery_vector in present, (
            f"declared {scenario.delivery_vector!r} not in adapter trace {present}"
        )


class TestExitGate3ReadmeMappingGenerated:
    def test_readme_mapping_section_is_generated_and_complete(self) -> None:
        section = readme_mapping_section()
        # Every OWASP category row present (generated from the corpus).
        for cat in {**OWASP_ASI_INDEX, **OWASP_LLM_INDEX}:
            assert f"**{cat}**" in section
        # The scenario count matches the corpus on disk (not hardcoded).
        scenarios = load_corpus_dir()
        assert f"**{len(scenarios)} scenarios**" in section
        # The section is bounded by the regenerable markers.
        assert "<!-- BEGIN neuralstrike-mapping -->" in section
        assert "<!-- END neuralstrike-mapping -->" in section


class TestExitGate4HonestVerdicts:
    def test_full_run_produces_mixed_verdicts_not_all_passed(self, full_corpus_run) -> None:
        """A real red-team run is never all-pass; the fixture is exploitable on
        the grant_admin_access scenarios and inconclusive on canary-only ones."""
        run = full_corpus_run
        # The fixture always emits grant_admin_access, so scenarios whose
        # success_criteria forbids that tool must SUCCEED (honest, not a pass).
        assert run.overall_succeeded > 0, "no succeeded findings; the fixture was not driven"
        # Canary-only scenarios cannot be satisfied by the fixture -> Inconclusive
        # (coverage gaps, surfaced, not coerced to PASS).
        assert run.overall_inconclusive > 0, (
            "no inconclusive findings; coverage gaps were coerced to PASS"
        )
        # Coverage is honest: conclusive / total, neither 0 nor necessarily 100%.
        assert 0.0 < run.coverage <= 1.0
