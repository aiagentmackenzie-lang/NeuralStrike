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


def test_failed_atomic_replace_does_not_block_error_journal_or_touch_existing_temp(tmp_path, monkeypatch):
    from pathlib import Path

    path = tmp_path / "observation.json"
    atomic(path, {"state": "running"})
    before = path.read_bytes()
    original = Path.replace

    def fail(source, target):
        raise OSError("controlled replace failure")

    with monkeypatch.context() as patch:
        patch.setattr(Path, "replace", fail)
        with pytest.raises(OSError, match="controlled replace failure"):
            atomic(path, {"state": "complete"})
    assert path.read_bytes() == before
    atomic(path, {"state": "running", "error": "replace failed"})
    assert json.loads(path.read_text())["error"] == "replace failed"
    # A historical/foreign .tmp is not ours to overwrite or remove.
    foreign = path.with_suffix(".tmp")
    foreign.write_text("historical partial evidence")
    atomic(path, {"state": "running", "error": "preserved foreign evidence"})
    assert foreign.read_text() == "historical partial evidence"
    assert not list(tmp_path.glob(".*.tmp"))
    assert original is Path.replace
