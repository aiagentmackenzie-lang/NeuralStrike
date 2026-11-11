"""Contract: no document may point a reviewer at `/tmp` and call it evidence.

ENGINEERING_BACKLOG.md E-9. `/tmp` evaporates, and this repository has already lost evidence
twice: the AgentDojo exploratory packet and the whole Phase 0 acceptance directory. Both were
cited as preserved locations; both are gone, and one document still claimed the packet was
available.

The rule, from `docs/implementation/EVIDENCE.md` §Where evidence lives:

* `/tmp` is allowed inside a **fenced code block** — that is an instruction you run now, a scratch
  location by design;
* `/tmp` is allowed in `PROGRESS.md`, which is a dated history of what ran and where, and
  rewriting it would falsify the log;
* anywhere else, a line naming `/tmp` must say that the data is **gone**. A citation and a
  tombstone look similar in a grep; only one of them is honest.

The durable root is the declared alternative and is asserted here, so it cannot drift from the
backlog that names it.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOCS = [*sorted((ROOT / "docs").rglob("*.md")), ROOT / "README.md", ROOT / "USAGE.md"]
EVIDENCE = ROOT / "docs/implementation/EVIDENCE.md"
BACKLOG = ROOT / "docs/implementation/ENGINEERING_BACKLOG.md"

DURABLE_ROOT = "~/Documents/Codex/2026-11-08/neuralstrike-phase3"
TMP = "/tmp/"

#: A line may name /tmp outside a fence only when it says the data is not there.
GONE_MARKERS = (
    "no longer",
    "gone",
    "lost",
    "absent",
    "was never",
    "scratch",
    "removed",
)

#: Dated history, not citation. Exempt by name and by nothing else.
HISTORY_DOCS = frozenset({"PROGRESS.md"})

FENCE = re.compile(r"```.*?```", re.DOTALL)


def documents() -> list[Path]:
    return [path for path in DOCS if path.is_file()]


def prose_without_fences(text: str) -> str:
    """Blank out fenced code so line numbers survive and instructions are not citations."""
    return FENCE.sub(lambda match: "\n" * match.group(0).count("\n"), text)


def test_the_durable_root_is_declared_in_the_evidence_contract_and_the_backlog() -> None:
    assert DURABLE_ROOT in EVIDENCE.read_text(), "EVIDENCE.md must name the durable root"
    assert DURABLE_ROOT in BACKLOG.read_text(), "the backlog names the same root"


def test_the_durable_root_exists_on_this_machine() -> None:
    """A declared root that is not there is the same failure one level up."""
    root = Path(DURABLE_ROOT).expanduser()
    assert root.is_dir(), f"{root} does not exist; the declared durable root must be real"
    assert any(root.iterdir()), f"{root} is empty"


def offenders() -> list[str]:
    found: list[str] = []
    for path in documents():
        if path.name in HISTORY_DOCS:
            continue
        prose = prose_without_fences(path.read_text())
        original = path.read_text().splitlines()
        for index, line in enumerate(prose.splitlines(), start=1):
            if TMP not in line:
                continue
            lowered = line.lower()
            if any(marker in lowered for marker in GONE_MARKERS):
                continue
            found.append(f"{path.relative_to(ROOT)}:{index}: {original[index - 1].strip()}")
    return found


def test_no_document_cites_tmp_as_where_evidence_lives() -> None:
    found = offenders()
    assert not found, (
        "these lines point a reviewer at /tmp without saying the data is gone; move the artefact "
        "under the durable root or record the loss (EVIDENCE.md §Evidence that is gone):\n"
        + "\n".join(found)
    )


def test_the_gone_marker_allowance_is_actually_used() -> None:
    """If nothing needs the tombstone allowance, the rule above is untested by the corpus."""
    tombstones = [
        line
        for path in documents()
        if path.name not in HISTORY_DOCS
        for line in prose_without_fences(path.read_text()).splitlines()
        if TMP in line and any(marker in line.lower() for marker in GONE_MARKERS)
    ]
    assert tombstones, "no document records a lost /tmp artefact; the inventory has no entries"


def test_the_fence_stripper_keeps_line_numbers() -> None:
    text = "before\n```bash\nrun --out /tmp/x\nmore\n```\nafter\n"
    stripped = prose_without_fences(text)
    assert stripped.count("\n") == text.count("\n")
    assert TMP not in stripped


@pytest.mark.parametrize("path", [EVIDENCE])
def test_the_evidence_contract_states_the_rule_and_the_losses(path: Path) -> None:
    body = path.read_text()
    assert "## Where evidence lives" in body
    assert "Evidence that is gone" in body
    assert "agentdojo-observations" in body
    assert "phase0-acceptance" in body


# --- The durable root is only durable if a reviewer can open what it is told to open ---------

CITATION = re.compile(
    r"(?:/Users/agentmackenzie/Documents/Codex/2026-11-08/neuralstrike-phase3"
    r"|~/Documents/Codex/2026-11-08/neuralstrike-phase3)[^\s`)\"'\]>]*"
)


def citations() -> dict[str, str]:
    """Every durable-root path a document tells a reviewer to open, with its document."""
    found: dict[str, str] = {}
    for path in documents():
        for match in CITATION.finditer(path.read_text()):
            cited = match.group(0).rstrip(".,;:")
            if "*" in cited:
                continue  # a glob describes a directory, not a file to open
            found.setdefault(cited, path.name)
    return found


def test_every_cited_durable_path_exists() -> None:
    """A declared durable root with dead citations is `/tmp` with a longer path."""
    missing = {
        cited: document
        for cited, document in citations().items()
        if not Path(cited.replace("~", str(Path.home()))).exists()
    }
    assert not missing, "documents cite evidence that is not on disk:\n" + "\n".join(
        f"  {document}: {cited}" for cited, document in sorted(missing.items())
    )


def test_the_citation_scan_is_not_vacuous() -> None:
    found = citations()
    assert len(found) >= 5, f"only {len(found)} durable paths are cited; the scan may be blind"
    assert any("review.zip" in cited for cited in found), "no packet is cited"
