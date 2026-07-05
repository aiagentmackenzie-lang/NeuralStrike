"""Corpus package — OWASP ASI/LLM scenario loader and oracle builder.

Phase 2 deliverable: the scenario corpus is the foundation of the audit-grade
report. Reports and the README mapping table are generated from the loaded
corpus, never hand-written.
"""

from __future__ import annotations

from neuralstrike.corpus.loader import (
    CANARY_PLACEHOLDER,
    DeliveryVector,
    Scenario,
    SuccessCriterion,
    build_oracles,
    corpus_path,
    iter_corpus_files,
    load_corpus,
    load_corpus_dir,
)

__all__ = [
    "CANARY_PLACEHOLDER",
    "DeliveryVector",
    "Scenario",
    "SuccessCriterion",
    "build_oracles",
    "corpus_path",
    "iter_corpus_files",
    "load_corpus",
    "load_corpus_dir",
]
