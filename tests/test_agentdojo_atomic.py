"""A failed journal encoding must preserve the previous record and allow recovery."""

import json

import pytest
from examples.agentdojo_banking.collect import atomic


def test_encoding_failure_preserves_journal_and_allows_error_receipt(tmp_path):
    path = tmp_path / "observation.json"
    atomic(path, {"state": "running"})
    before = path.read_bytes()
    with pytest.raises(TypeError):
        atomic(path, {"not_json": object()})
    assert path.read_bytes() == before
    atomic(path, {"state": "running", "error": "controlled encoding failure"})
    assert json.loads(path.read_text())["error"] == "controlled encoding failure"
    assert path.stat().st_mode & 0o777 == 0o600
