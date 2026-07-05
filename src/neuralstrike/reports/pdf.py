"""PDF report writer — pure-Python, no external dependency.

Emits a minimal but valid PDF 1.4 document containing the corpus run
report. This is deliberately dependency-free: a security tool whose pitch
is supply-chain safety (ASI04) must not pull a PDF library through the
gate install to produce a report. The writer supports the subset of PDF
needed for a text report — pages of monospaced lines — which is enough for
an audit-grade artifact. For richer layout, render the Markdown report and
convert externally; the PDF writer exists so the ``--format pdf`` gate
works on a fresh clone with no extra install.

PDF structure (one object stream is not used; objects are emitted directly):

- Header: ``%PDF-1.4``.
- A font object (Helvetica, a standard 14 PDF font — no embedding needed).
- One page object per ~50 lines, with a content stream of ``BT`` text.
- A cross-reference table + trailer.

The implementation is small and well-tested; PDF is a strict format but the
text-only subset is genuinely simple.
"""

from __future__ import annotations

from neuralstrike.reports.model import CorpusRun

__all__ = ["to_pdf"]


_PAGE_WIDTH = 612.0  # US Letter, points
_PAGE_HEIGHT = 792.0
_MARGIN = 50.0
_FONT_SIZE = 9.0
_LINE_HEIGHT = 11.0
_LINES_PER_PAGE = int((_PAGE_HEIGHT - 2 * _MARGIN) / _LINE_HEIGHT) - 1


def _escape_pdf_text(text: str) -> str:
    """Escape a string for the PDF text-showing operator ``Tj``."""
    return text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


def _wrap_line(line: str, max_chars: int) -> list[str]:
    """Wrap a long line to ``max_chars`` columns (best-effort, on word boundaries)."""
    if len(line) <= max_chars:
        return [line]
    out: list[str] = []
    cur = ""
    for word in line.split(" "):
        if not cur:
            cur = word
        elif len(cur) + 1 + len(word) <= max_chars:
            cur = cur + " " + word
        else:
            out.append(cur)
            cur = word
    if cur:
        out.append(cur)
    return out


def _lines_for_run(run: CorpusRun, max_chars: int) -> list[str]:
    lines: list[str] = [
        "NeuralStrike Corpus Run Report",
        "",
        f"Started:           {run.started_at}",
        f"Adapter:           {run.adapter}",
        f"Target:            {run.target}",
        f"Base seed:         {run.base_seed}",
        f"Trials/scenario:   {run.trials_per_scenario}",
        f"Overall:           {run.overall_total} trials  "
        f"({run.overall_succeeded} succeeded / {run.overall_resisted} resisted / "
        f"{run.overall_inconclusive} inconclusive)",
        f"ASR (conclusive):  {run.asr:.2%}",
        f"Coverage:          {run.coverage:.2%}",
        "",
        "Legend: SUCCEEDED = exploitable | RESISTED | INCONCLUSIVE = coverage gap (surfaced)",
        "        Verdicts are conclusive-only; Inconclusive trials are never coerced to PASS.",
        "",
        "=" * max_chars,
        "",
    ]
    for sr in run.scenario_results:
        s = sr.scenario
        atlas = ", ".join(s.mitre_atlas) if s.mitre_atlas else "none"
        lines.append(f"[{s.id}] {s.owasp_category} - {s.owasp_name}")
        lines.append(f"  Intent:     {s.intent}")
        lines.append(f"  ATLAS:      {atlas}")
        lines.append(f"  Delivery:   {s.delivery_vector}")
        lines.append(f"  Severity:   {s.severity}")
        agg = (
            f"  Verdict:    {sr.verdict.value.upper()}  "
            f"({sr.succeeded}s/{sr.resisted}r/{sr.inconclusive}i)"
        )
        lines.append(agg)
        lines.append("  Controls:")
        if sr.controls:
            for c in sr.controls:
                lines.append(f"    [{c.framework}] {c.control_id} - {c.control_name}")
        else:
            lines.append("    (no controls mapped)")
        for t in sr.trials:
            ev = (t.evidence_quote or t.reason or "").replace("\n", " ")
            if len(ev) > 90:
                ev = ev[:87] + "..."
            lines.append(
                f"    trial {t.trial_index} {t.oracle_id}: {t.verdict.value.upper()} "
                f"[{t.fidelity.value}] {ev}"
            )
        lines.append("")
    return lines


def to_pdf(run: CorpusRun, *, max_chars: int = 95) -> bytes:
    """Render the corpus run as a valid PDF 1.4 document (bytes)."""
    raw_lines = _lines_for_run(run, max_chars)
    # Wrap every logical line to the page width.
    wrapped: list[str] = []
    for ln in raw_lines:
        wrapped.extend(_wrap_line(ln, max_chars))

    # Chunk into pages.
    pages: list[list[str]] = []
    for i in range(0, len(wrapped), _LINES_PER_PAGE):
        pages.append(wrapped[i : i + _LINES_PER_PAGE])
    if not pages:
        pages.append(["(no content)"])

    objects: list[bytes] = []
    # Object 1: Catalog
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    # Object 2: Pages
    page_obj_ids = [3 + 2 * i for i in range(len(pages))]  # 3,5,7,...
    kids = b" ".join(f"{pid} 0 R".encode() for pid in page_obj_ids)
    objects.append(
        f"<< /Type /Pages /Kids [{kids.decode()}] /Count {len(pages)} >>".encode()
    )

    # Object 3..: page + content stream pairs.
    for page_lines in pages:
        page_obj_id = len(objects) + 1
        content_obj_id = page_obj_id + 1
        # Build the content stream: BT / font / leading / Td per line.
        stream_parts: list[str] = []
        stream_parts.append("BT")
        stream_parts.append(f"/F1 {_FONT_SIZE} Tf")
        stream_parts.append(f"{_LINE_HEIGHT} TL")
        y = _PAGE_HEIGHT - _MARGIN
        stream_parts.append(f"1 0 0 1 {_MARGIN} {y:.2f} Tm")
        for i, ln in enumerate(page_lines):
            if i > 0:
                stream_parts.append("T*")
            stream_parts.append(f"({_escape_pdf_text(ln)}) Tj")
        stream_parts.append("ET")
        stream = "\n".join(stream_parts).encode("latin-1", errors="replace")
        objects.append(
            f"<< /Length {len(stream)} >>\nstream\n".encode()
            + stream
            + b"\nendstream"
        )
        objects.append(
            f"<< /Type /Page /Parent 2 0 R "
            f"/MediaBox [0 0 {_PAGE_WIDTH} {_PAGE_HEIGHT}] "
            f"/Resources << /Font << /F1 4 0 R >> >> "
            f"/Contents {content_obj_id} 0 R >>".encode()
        )

    # Font object (Helvetica is one of the standard 14 — no embedding).
    objects.append(
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"
    )

    # Assemble the file with a byte-offset xref table.
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets: list[int] = []
    for i, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode()
        out += obj
        out += b"\nendobj\n"
    xref_offset = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_offset}\n%%EOF\n"
    ).encode()
    return bytes(out)
