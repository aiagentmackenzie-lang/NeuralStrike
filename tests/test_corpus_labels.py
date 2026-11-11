"""Contract: a scenario's OWASP name must be the canonical name for its OWASP category.

Found while auditing the README against the tree: **10 of 60 scenarios** carried an `owasp_name`
that the compliance index disagrees with. Some were synonyms ("Supply Chain Vulnerabilities in AI
Components" for "Agentic Supply Chain Vulnerabilities"), but two were a different framework's name
entirely — `ASI06` labelled "Insecure Output Handling / Agent Tool Abuse" (that is LLM05's name) and
`ASI02` labelled "Sensitive Information Disclosure" (that is LLM02's). A report prints this string,
so a customer reading a finding would see a category that does not exist.

The taxonomy itself (which category a scenario belongs to) is not asserted here: moving a scenario
between categories changes coverage counts and is a decision, not a typo fix. This contract only
holds the labels to the index.
"""

from __future__ import annotations

import pytest

from neuralstrike.corpus.loader import load_corpus_dir
from neuralstrike.reports.compliance import OWASP_ASI_INDEX, OWASP_LLM_INDEX

SCENARIOS = load_corpus_dir()


def canonical(category: str) -> str:
    index = OWASP_ASI_INDEX if category.startswith("ASI") else OWASP_LLM_INDEX
    assert category in index, f"undeclared OWASP category: {category}"
    return index[category]


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.id)
def test_owasp_name_matches_the_canonical_index(scenario: object) -> None:
    category = scenario.owasp_category  # type: ignore[attr-defined]
    name = scenario.owasp_name  # type: ignore[attr-defined]
    assert name == canonical(category), (
        f"{scenario.id} is {category} but its owasp_name is {name!r}; "
        f"the canonical name is {canonical(category)!r}"
    )


def test_the_indices_cover_both_top_ten_lists() -> None:
    assert len(OWASP_ASI_INDEX) == 10
    assert len(OWASP_LLM_INDEX) == 10
    assert not (set(OWASP_ASI_INDEX) & set(OWASP_LLM_INDEX))


def test_the_repository_copies_and_the_shipped_package_data_are_identical() -> None:
    """There are two copies of the corpus: `corpus/` for readers, package data for wheels.

    Found while fixing the labels above — the two trees were byte-identical by luck, not by
    contract, and only the package copy is loaded at runtime. A reviewer reading `corpus/` and a
    wheel running its own copy must not be looking at different scenarios.
    """
    from neuralstrike.corpus import corpus_path

    shipped = corpus_path()
    reader = corpus_path().parents[3] / "corpus"
    assert reader.is_dir(), reader
    reader_files = sorted(reader.glob("*.yaml"))
    shipped_files = sorted(shipped.glob("*.yaml"))
    reader_names = {path.name for path in reader_files}
    shipped_names = {path.name for path in shipped_files}
    # Exact set equality: `corpus/` is what a reader browses and the package data is what a wheel
    # loads, and they must be the same four files. `phase10_execution_context.yaml` used to exist
    # only in the package, so a reader counting the corpus saw 53 scenarios where the README said 60.
    assert reader_names == shipped_names, sorted(reader_names ^ shipped_names)
    for name in sorted(reader_names):
        assert (reader / name).read_bytes() == (shipped / name).read_bytes(), (
            f"corpus/{name} and the shipped package copy have diverged"
        )
