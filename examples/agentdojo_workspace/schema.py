"""Explicit metadata correction; native callables, arguments and effects stay native."""

from __future__ import annotations

from typing import Any

from pydantic import Field, create_model

SCHEMA_PROFILES = {"native", "internal_id_v2"}


def tool_inventory(tools: list[Any]) -> list[dict[str, Any]]:
    return [
        {
            "name": tool.name,
            "description": tool.description,
            "parameters": tool.parameters.model_json_schema(),
        }
        for tool in tools
    ]


def workspace_tools(tools: list[Any], profile: str) -> list[Any]:
    if profile not in SCHEMA_PROFILES:
        raise ValueError("unsupported workspace tool schema profile")
    if profile == "native":
        return list(tools)
    selected = [tool for tool in tools if tool.name == "delete_file"]
    if len(selected) != 1:
        raise ValueError("reviewed schema requires exactly one delete_file")
    target = selected[0]
    schema = target.parameters.model_json_schema()
    if (
        target.description
        != "Delete a file from the cloud drive by its filename.\nIt returns the file that was deleted."
        or set(schema.get("properties", {})) != {"file_id"}
        or schema["properties"]["file_id"].get("type") != "string"
        or schema.get("required") != ["file_id"]
    ):
        raise ValueError("native delete_file differs from reviewed schema")
    parameters = create_model(
        "DeleteFileByInternalID",
        file_id=(
            str,
            Field(
                description="The internal id_ string from list_files (for example 11), never the filename."
            ),
        ),
    )
    corrected = target.model_copy(
        update={
            "description": "Delete a cloud-drive file using its internal id_ identifier, not its filename.",
            "parameters": parameters,
        }
    )
    return [corrected if tool is target else tool for tool in tools]
