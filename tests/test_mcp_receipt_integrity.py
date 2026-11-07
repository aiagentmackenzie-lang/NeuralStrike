"""MCP capability files remain portable data, never instructions or assessment passes."""

import hashlib
import json

import pytest

from neuralstrike.evaluation.mcp_receipt import MCPReceiptError, load_mcp_inspection
from neuralstrike.utils.json import StrictJSONError, strict_json


def test_strict_json_rejects_numeric_overflow_and_ambiguous_keys():
    for encoded in (b'{"x":1e999}', b'{"x":NaN}', b'{"x":1,"x":2}'):
        with pytest.raises(StrictJSONError):
            strict_json(encoded)


def test_incompatible_and_running_receipts_cannot_be_verified(tmp_path):
    (tmp_path / "plan.json").write_text("{}")
    (tmp_path / "receipt.json").write_text("{}")
    (tmp_path / "transcript.json").write_text("[]")
    files = {
        name: hashlib.sha256((tmp_path / name).read_bytes()).hexdigest()
        for name in ("plan.json", "receipt.json", "transcript.json")
    }
    for version, state in ((2, "committed"), (True, "committed"), (1, "running")):
        (tmp_path / "manifest.json").write_text(
            json.dumps(
                {
                    "kind": "neuralstrike-mcp-inspection",
                    "schema_version": version,
                    "state": state,
                    "files": files,
                }
            )
        )
        with pytest.raises(MCPReceiptError):
            load_mcp_inspection(tmp_path)
