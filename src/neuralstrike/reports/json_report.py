"""JSON report writer.

Serializes a :class:`~neuralstrike.reports.model.CorpusRun` to a stable JSON
document (sorted keys) so two runs over the same corpus + seed produce
byte-identical reports.
"""

from __future__ import annotations

import json

from neuralstrike.reports.model import CorpusRun

__all__ = ["to_json"]


def to_json(run: CorpusRun) -> str:
    """Render the corpus run as a pretty JSON string (sorted keys)."""
    return json.dumps(run.to_dict(), indent=2, sort_keys=True, ensure_ascii=False)
