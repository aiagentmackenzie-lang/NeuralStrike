"""Offline native recomputation rejects unreviewed/incomplete inputs before dispatch."""

import pytest
from examples.agentdojo_banking.collect import REVISION
from examples.agentdojo_workspace.recompute import recompute


@pytest.mark.parametrize(
    "field,value",
    [
        ("state", "running"),
        ("error", "timeout"),
        ("schema_version", True),
        ("schema_version", 2),
        ("source_revision", "unreviewed"),
        ("kind", "other"),
        ("case", "other"),
        ("policy", "other"),
        ("tool_schema_profile", "other"),
    ],
)
def test_native_recomputation_cannot_run_unreviewed_or_incomplete_inputs(field, value):
    d = {
        "kind": "agentdojo-workspace-local-observation",
        "schema_version": 1,
        "source_revision": REVISION,
        "state": "complete",
        "error": None,
        "case": "delete_protected",
        "policy": "unfiltered",
        "tool_schema_profile": "internal_id_v2",
    }
    d[field] = value
    with pytest.raises(ValueError, match="complete reviewed"):
        recompute(d, None, None)  # No native suite/runtime can be touched.
