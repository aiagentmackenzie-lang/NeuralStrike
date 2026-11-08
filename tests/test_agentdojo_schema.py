"""The opt-in schema overlay must never rewrite native dispatch or arguments."""

from typing import Any

import pytest
from examples.agentdojo_workspace.schema import tool_inventory, workspace_tools
from pydantic import BaseModel, ConfigDict, Field


class OriginalParameters(BaseModel):
    file_id: str = Field(description="The name of the file to delete.")


class EmptyParameters(BaseModel):
    pass


class FunctionFixture(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    name: str
    description: str
    parameters: Any
    run: Any
    dependencies: Any


def tool():
    return FunctionFixture(
        name="delete_file",
        description="Delete a file from the cloud drive by its filename.\n"
        "It returns the file that was deleted.",
        parameters=OriginalParameters,
        run=lambda file_id: file_id,
        dependencies={"cloud_drive": object()},
    )


def test_opt_in_overlay_changes_metadata_only_and_preserves_original_schema():
    native = tool()
    before = tool_inventory([native])
    assert workspace_tools([native], "native") == [native]
    effective = workspace_tools([native], "internal_id_v2")[0]
    assert effective is not native
    assert effective.run is native.run
    assert effective.dependencies is native.dependencies
    assert effective.run(**effective.parameters(file_id="13").model_dump()) == "13"
    assert (
        "internal id_" in tool_inventory([effective])[0]["parameters"]["properties"]["file_id"]["description"]
    )
    assert tool_inventory([native]) == before
    assert effective.parameters.model_json_schema()["required"] == ["file_id"]
    assert effective.parameters.model_json_schema()["properties"]["file_id"]["type"] == "string"


@pytest.mark.parametrize("damage", ["duplicate", "missing", "description", "parameters", "profile"])
def test_overlay_rejects_unreviewed_contract_without_mutation(damage):
    native = tool()
    selected = [native]
    profile = "internal_id_v2"
    if damage == "duplicate":
        selected.append(native)
    elif damage == "missing":
        selected = []
    elif damage == "description":
        native.description = "New upstream semantics"
    elif damage == "parameters":
        native.parameters = EmptyParameters
    elif damage == "profile":
        profile = "unreviewed"
    before = tool_inventory(selected)
    with pytest.raises(ValueError):
        workspace_tools(selected, profile)
    assert tool_inventory(selected) == before


async def test_workspace_import_rejects_unknown_schema_profile(tmp_path):
    import json

    from examples.agentdojo_banking.replay import import_observations

    from test_agentdojo_workspace import document

    observed = document()
    observed["tool_schema_profile"] = "unknown"
    path = tmp_path / "observation.json"
    path.write_text(json.dumps(observed))
    with pytest.raises(ValueError, match="schema configuration"):
        await import_observations(
            [path], tmp_path / "canonical", measurement="completed_effect", profile="workspace"
        )
