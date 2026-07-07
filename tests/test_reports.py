"""Report writer tests — JSON / SARIF / JUnit / Markdown / PDF + compliance."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET

import pytest

from neuralstrike.adapters.base import TargetAdapter
from neuralstrike.adapters.langgraph import LangGraphAdapter
from neuralstrike.attacks.indirect import IndirectHarness
from neuralstrike.corpus import load_corpus_dir
from neuralstrike.evaluation.runner import TrialRunner
from neuralstrike.oracles.tool_harness import make_canary_tools
from neuralstrike.reports import (
    build_corpus_run,
    readme_mapping_section,
    readme_mapping_table,
    to_json,
    to_junit,
    to_markdown,
    to_pdf,
    to_sarif,
)
from neuralstrike.reports.compliance import (
    OWASP_ASI_INDEX,
    OWASP_LLM_INDEX,
    crosswalk,
)


@pytest.fixture(scope="module")
def corpus_run():
    """A real CorpusRun: one scenario per OWASP category driven through the fixture."""
    import asyncio

    scenarios = load_corpus_dir()
    seen: set[str] = set()
    subset = []
    for s in scenarios:
        if s.owasp_category in seen:
            continue
        seen.add(s.owasp_category)
        subset.append(s)

    async def _run() -> object:
        from neuralstrike.fixtures.langgraph_agent import build_vulnerable_graph

        reports = []
        for s in subset:
            adapter = LangGraphAdapter(graph=build_vulnerable_graph())
            harness = IndirectHarness(s)
            canary = make_canary_tools()
            probe = harness.probe_for(
                adapter,
                canary_tools=canary,
                tools=TargetAdapter.canary_tools_as_schemas(canary),
            )
            runner = TrialRunner(base_seed=11, run_dir=None)
            r = await runner.run(probe, trials=1, persist=False)
            reports.append(r)
            await adapter.close()
        return build_corpus_run(
            scenarios=subset,
            reports=reports,
            base_seed=11,
            trials_per_scenario=1,
            adapter="langgraph",
            target="vulnerable-fixture",
        )

    return asyncio.run(_run())


def test_compliance_crosswalk_covers_every_category() -> None:
    for cat in OWASP_ASI_INDEX:
        controls = crosswalk(cat, ("AML.T0051.001",))
        assert controls, f"{cat} has no crosswalk"
        frameworks = {c.framework for c in controls}
        assert "OWASP_ASI" in frameworks
        assert "MITRE_ATLAS" in frameworks
        # Every category maps to at least one compliance framework beyond OWASP/ATLAS.
        non_owasp_atlas = frameworks - {"OWASP_ASI", "OWASP_LLM", "MITRE_ATLAS"}
        assert non_owasp_atlas, f"{cat} maps to no compliance framework"
    for cat in OWASP_LLM_INDEX:
        controls = crosswalk(cat, ())
        assert controls
        # OWASP_LLM present even with no ATLAS list supplied.
        frameworks = {c.framework for c in controls}
        assert "OWASP_LLM" in frameworks
        # Supplying ATLAS techniques adds them to the crosswalk.
        controls_with_atlas = crosswalk(cat, ("AML.T0051.001",))
        assert "MITRE_ATLAS" in {c.framework for c in controls_with_atlas}


def test_crosswalk_is_deterministic() -> None:
    a = crosswalk("ASI01", ("AML.T0051.001",))
    b = crosswalk("ASI01", ("AML.T0051.001",))
    assert [c.to_dict() for c in a] == [c.to_dict() for c in b]


def test_json_report_is_valid_and_stable(corpus_run) -> None:
    s = to_json(corpus_run)
    doc = json.loads(s)
    assert "scenario_results" in doc
    assert "overall" in doc
    assert doc["overall"]["total"] > 0
    # sorted keys -> stable across runs
    assert s == json.dumps(corpus_run.to_dict(), indent=2, sort_keys=True, ensure_ascii=False)


def test_sarif_maps_every_finding_to_asi_llm_atlas_and_compliance(corpus_run) -> None:
    sarif = to_sarif(corpus_run)
    doc = json.loads(sarif)
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "NeuralStrike"
    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    results = run["results"]
    assert rules and results
    # Every rule maps to an OWASP category + ATLAS list + compliance controls.
    for rid, rule in rules.items():
        props = rule["properties"]
        assert props["owasp_category"] in {**OWASP_ASI_INDEX, **OWASP_LLM_INDEX}
        assert isinstance(props["mitre_atlas"], list)
        assert props["compliance_controls"], f"rule {rid} has no compliance controls"
        # Each control has framework + id + name.
        for c in props["compliance_controls"]:
            assert c["framework"] and c["id"] and c["name"]
    # Every result references a rule and carries a verdict + fidelity.
    for res in results:
        assert res["ruleId"] in rules
        assert res["properties"]["verdict"] in {"resisted", "succeeded", "inconclusive"}
        assert res["properties"]["fidelity"] in {"verbal", "intent_to_act", "behavioral"}
        assert "level" in res


def test_sarif_inconclusive_results_are_notes_not_dropped(corpus_run) -> None:
    """Inconclusive probes surface as low-noise 'note' results, never dropped."""
    sarif = to_sarif(corpus_run)
    doc = json.loads(sarif)
    results = doc["runs"][0]["results"]
    levels = {res["level"] for res in results}
    # The corpus run against the fixture produces some inconclusive probes
    # (scenarios whose oracle is canary-only, and the fixture does not echo
    # the canary). At least one must surface as a note. If the fixture's
    # behaviour happens to make everything conclusive, the set still must
    # be a subset of {error, note, none}.
    assert levels <= {"error", "note", "none"}
    # And at least one inconclusive result must be present (the fixture does
    # not satisfy canary-only scenarios).
    inconclusive = [r for r in results if r["level"] == "note"]
    assert inconclusive, "no inconclusive results surfaced; the gate drops coverage gaps"


def test_junit_is_valid_xml_and_surfaces_inconclusive(corpus_run) -> None:
    xml = to_junit(corpus_run)
    root = ET.fromstring(xml)
    assert root.tag == "testsuites"
    suites = root.findall("testsuite")
    assert len(suites) > 0
    # Inconclusive trials surface as <skipped> (surfaced, not dropped).
    skipped = root.findall(".//skipped")
    assert skipped, "no skipped (inconclusive) testcases; coverage gaps dropped"
    # Succeeded findings surface as <failure>.
    failures = root.findall(".//failure")
    assert failures, "no <failure> testcases; succeeded findings not reported"
    # Every suite carries OWASP/ATLAS properties.
    for suite in suites:
        props = {p.get("name"): p.get("value") for p in suite.findall("properties/property")}
        assert "owasp_category" in props
        assert "mitre_atlas" in props
        assert "delivery_vector" in props


def test_markdown_report_contains_every_category(corpus_run) -> None:
    md = to_markdown(corpus_run)
    assert "# NeuralStrike Corpus Run Report" in md
    for cat in OWASP_ASI_INDEX:
        assert cat in md
    for cat in OWASP_LLM_INDEX:
        assert cat in md
    assert "ASR" in md
    assert "Coverage" in md


def test_pdf_is_valid_pdf_1_4(corpus_run, tmp_path) -> None:
    pdf = to_pdf(corpus_run)
    assert pdf.startswith(b"%PDF-1.4")
    assert pdf.rstrip().endswith(b"%%EOF")
    # Write + read back: a valid PDF has an xref table + trailer.
    path = tmp_path / "report.pdf"
    path.write_bytes(pdf)
    reread = path.read_bytes()
    assert reread == pdf
    assert b"xref" in reread
    assert b"trailer" in reread
    assert b"/Type /Catalog" in reread
    assert b"/Type /Pages" in reread


def test_readme_mapping_table_generated_from_corpus() -> None:
    table = readme_mapping_table()
    # Every OWASP ASI + LLM category appears as a row.
    for cat in OWASP_ASI_INDEX:
        assert f"**{cat}**" in table
    for cat in OWASP_LLM_INDEX:
        assert f"**{cat}**" in table
    # The auto-generation banner is present.
    assert "Auto-generated" in table
    # Scenario count is honest (loaded from disk, not hardcoded).
    scenarios = load_corpus_dir()
    assert f"**{len(scenarios)} scenarios**" in table


def test_readme_mapping_section_has_markers() -> None:
    from neuralstrike.reports.readme_mapping import BEGIN_MARKER, END_MARKER

    section = readme_mapping_section()
    assert section.startswith(BEGIN_MARKER)
    assert section.endswith(END_MARKER)
    # The section is idempotent: regenerating twice yields the same text.
    assert readme_mapping_section() == section
