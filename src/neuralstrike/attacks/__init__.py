"""Attack harnesses — delivery-vector injection (Phase 2) and beyond.

Phase 2 ships :mod:`neuralstrike.attacks.indirect`, the indirect-injection
delivery-vector harness. Future phases add adaptive attacks (Phase 4) and
MCP/A2A/RAG deep coverage (Phase 5).
"""

from __future__ import annotations

from neuralstrike.attacks.indirect import (
    INJECTION_MARKER_PREFIX,
    IndirectHarness,
    InjectionInputs,
    mint_injection_marker,
)

__all__ = [
    "INJECTION_MARKER_PREFIX",
    "IndirectHarness",
    "InjectionInputs",
    "mint_injection_marker",
]
