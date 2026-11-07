"""Report views preserve portable source identity and exact observation links."""

import hashlib
import json
from dataclasses import replace

import pytest
from tests.test_report_contract import make_run, trial

from neuralstrike.corpus import corpus_path, load_corpus
from neuralstrike.evaluation.verdict import Verdict
from neuralstrike.reports import to_json, to_junit, to_markdown, to_sarif
from neuralstrike.reports.pdf import _lines_for_run


@pytest.mark.parametrize("filename", ["phase5_real_incidents.yaml", "phase10_execution_context.yaml"])
def test_sarif_source_is_recorded_file_not_id_prefix(filename):
    from neuralstrike.evaluation.runner import RunMeta, RunReport
    from neuralstrike.reports import build_corpus_run

    scenario = load_corpus(corpus_path() / filename)[0]
    observation = replace(trial(0, Verdict.INCONCLUSIVE), scenario_id=scenario.id)
    report = RunReport(
        RunMeta("fixture", scenario.id, 0, 1, 0, 0.7, "2026-11-06T00:00:00Z"), trials=(observation,)
    )
    run = build_corpus_run(
        scenarios=[scenario],
        reports=[report],
        base_seed=0,
        trials_per_scenario=1,
        adapter="synthetic",
        target="local",
    )
    result = json.loads(to_sarif(run))["runs"][0]["results"][0]
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == f"corpus/{filename}"
    assert scenario.source_sha256 == hashlib.sha256((corpus_path() / filename).read_bytes()).hexdigest()
    assert result["partialFingerprints"]["scenario"] == scenario.fingerprint
    assert result["partialFingerprints"]["evidence"].startswith("sha256:")


def test_all_report_formats_include_evidence_links_origin_scope_and_limits():
    run = make_run([trial(0, Verdict.INCONCLUSIVE)])
    document = json.loads(to_json(run))
    record = document["scenario_results"][0]["trials"][0]
    evidence_id = record["evidence_id"]
    assert evidence_id.startswith("sha256:")
    assert record["evidence_origin"] == "unverified-observation"
    assert document["assessment_scope"]["selected_scenarios"] == [record["scenario_id"]]
    assert document["limitations"]
    sarif = json.loads(to_sarif(run))["runs"][0]
    assert sarif["results"][0]["properties"]["evidence_id"] == evidence_id
    assert sarif["invocations"][0]["properties"]["limitations"] == document["limitations"]
    for text in [to_markdown(run), to_junit(run), "\n".join(_lines_for_run(run, 95))]:
        assert evidence_id in text
        assert "unverified-observation" in text
        assert "Scope" in text or "scope" in text
        assert "limitations" in text.lower()


def mixed_run():
    from tests.test_report_contract import finding

    return make_run(
        [
            trial(
                0,
                Verdict.INCONCLUSIVE,
                [
                    finding("one", Verdict.RESISTED, "insufficient observation"),
                    finding("judge", Verdict.SUCCEEDED, "advisory", True),
                ],
            ),
            trial(
                1,
                Verdict.SUCCEEDED,
                [
                    finding("one", Verdict.RESISTED, "other condition"),
                    finding("two", Verdict.SUCCEEDED, "actual violation"),
                ],
                error="late outage",
            ),
            trial(2, Verdict.RESISTED, [finding("one", Verdict.RESISTED, "complete resistance")]),
            trial(3, Verdict.INCONCLUSIVE, error="unsupported delivery channel: memory"),
        ]
    )


def test_mixed_oracles_errors_and_unsupported_channel_agree_across_exports():
    import xml.etree.ElementTree as ET
    from io import BytesIO

    from pypdf import PdfReader

    from neuralstrike.reports import to_pdf

    run = mixed_run()
    json_report = json.loads(to_json(run))
    assert json_report["overall"] == {
        "total": 4,
        "succeeded": 1,
        "resisted": 1,
        "inconclusive": 2,
        "asr": 0.5,
        "coverage": 0.5,
    }
    sarif = json.loads(to_sarif(run))["runs"][0]
    assert sarif["invocations"][0]["properties"]["overall"] == json_report["overall"]
    assert sarif["invocations"][0]["executionSuccessful"] is False
    assert len(sarif["results"]) == 4
    junit = ET.fromstring(to_junit(run))
    assert [junit.get(key) for key in ["tests", "failures", "errors", "skipped"]] == ["4", "1", "1", "1"]
    assert len(junit.findall(".//testcase")) == 4
    text = to_markdown(run)
    pdf_text = "\n".join(page.extract_text() for page in PdfReader(BytesIO(to_pdf(run)), strict=True).pages)
    for rendered in [text, pdf_text]:
        assert "unsupported delivery channel: memory" in rendered
        assert "late outage" in rendered
        assert "incomplete" in rendered
    records = json_report["scenario_results"][0]["trials"]
    for record in records:
        assert record["evidence_id"] in text
        # PDF wraps long identifiers, so remove text-extraction whitespace.
        assert record["evidence_id"] in "".join(pdf_text.split())
