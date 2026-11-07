"""Independent parser coverage for the PDF writer's actual page tree and streams."""

from io import BytesIO

import pytest
from pypdf import PdfReader
from tests.test_report_contract import finding, make_run, trial

from neuralstrike.evaluation.verdict import Verdict
from neuralstrike.reports import to_pdf
from neuralstrike.reports.pdf import _wrap_line


@pytest.mark.parametrize("count", [1, 80])
def test_pdf_pages_resolve_to_real_pages_and_extract_all_trials(count):
    run = make_run(
        [
            trial(i, Verdict.RESISTED, [finding("fixture", Verdict.RESISTED, f"UNIQUE-RECEIPT-{i}")])
            for i in range(count)
        ]
    )
    reader = PdfReader(BytesIO(to_pdf(run)), strict=True)
    assert reader.pages
    if count > 1:
        assert len(reader.pages) > 1
    for page in reader.pages:
        assert page["/Type"] == "/Page"
        assert float(page.mediabox.width) == 612
        assert float(page.mediabox.height) == 792
        font = page["/Resources"]["/Font"]["/F1"]
        assert font["/Type"] == "/Font"
        assert page.get_contents() is not None
    text = "\n".join(page.extract_text() for page in reader.pages)
    assert "NeuralStrike Corpus Run Report" in text
    assert "Assessment health: complete" in text
    for index in range(count):
        assert f"UNIQUE-RECEIPT-{index}" in text


def test_long_unbroken_evidence_wraps_within_page_columns():
    lines = _wrap_line("W" * 240, 80)
    assert all(len(line) <= 80 for line in lines)
    assert "".join(lines) == "W" * 240


def test_pdf_keeps_trial_identity_with_its_execution_error():
    from tests.test_report_provenance import mixed_run

    pages = PdfReader(BytesIO(to_pdf(mixed_run())), strict=True).pages
    error_page = next(
        page.extract_text()
        for page in pages
        if "Execution error: unsupported delivery channel: memory" in page.extract_text()
    )
    assert "trial 3 " in error_page
    assert "Evidence: sha256:" in error_page
