"""Offline MCP capability-receipt integrity, without importing protocol SDKs.

Hashes establish internal consistency, not authorship or a security verdict.
These receipts are not assessment replay/rescore bundles.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from neuralstrike.utils.json import strict_json

KIND = "neuralstrike-mcp-inspection"
_FILES = {"plan.json", "receipt.json", "transcript.json"}
MAX_RECEIPT_BYTES = 64 * 1024 * 1024


class MCPReceiptError(ValueError):
    """An MCP receipt cannot be safely interpreted as a committed observation."""


def _read(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_RECEIPT_BYTES:
        raise MCPReceiptError("invalid or oversized MCP receipt file")
    raw = path.read_bytes()
    if len(raw) > MAX_RECEIPT_BYTES:
        raise MCPReceiptError("oversized MCP receipt file")
    return raw


def load_mcp_inspection(directory: str | Path) -> dict[str, Any]:
    """Verify exact inventory, hashes and complete-status invariants offline."""
    root = Path(directory)
    try:
        if (
            root.is_symlink()
            or not root.is_dir()
            or {p.name for p in root.iterdir()} != _FILES | {"manifest.json"}
        ):
            raise MCPReceiptError("unexpected MCP receipt inventory")
        manifest = strict_json(_read(root / "manifest.json"))
        if (
            not isinstance(manifest, dict)
            or manifest.get("kind") != KIND
            or type(manifest.get("schema_version")) is not int
            or manifest["schema_version"] != 1
            or manifest.get("state") != "committed"
            or set(manifest.get("files", {})) != _FILES
        ):
            raise MCPReceiptError("unsupported or uncommitted MCP receipt")
        documents = {}
        for name in _FILES:
            raw = _read(root / name)
            if hashlib.sha256(raw).hexdigest() != manifest["files"][name]:
                raise MCPReceiptError("MCP receipt hash mismatch")
            documents[name] = strict_json(raw)
        receipt = documents["receipt.json"]
        plan = documents["plan.json"]
        if (
            not isinstance(receipt, dict)
            or receipt.get("kind") != KIND
            or type(receipt.get("schema_version")) is not int
            or receipt["schema_version"] != 1
            or receipt.get("security_assessment") is not False
            or receipt.get("status") not in {"complete", "incomplete"}
            or not isinstance(documents["transcript.json"], list)
        ):
            raise MCPReceiptError("invalid MCP receipt shape")
        if receipt["status"] == "complete":
            calls = receipt["tool_calls"]
            execution_plan = plan["execution_plan"]
            if (
                receipt["raw_tool_names"] != receipt["tool_names"]
                or receipt["tool_names"] != [tool["name"] for tool in receipt["tools"]]
                or len(set(receipt["tool_names"])) != len(receipt["tool_names"])
                or receipt["protocol_version"] != "2026-07-28"
                or receipt["stage"] != "complete"
                or receipt["error"] is not None
                or receipt["cleanup"].get("clean") is not True
                or len(calls) != len(execution_plan)
                or [call["tool"] for call in calls] != plan["execution_order"]
                or set(plan["execution_order"]) != set(execution_plan)
                or any(
                    call["status"] != "complete" or call["arguments"] != execution_plan[call["tool"]]
                    for call in calls
                )
            ):
                raise MCPReceiptError("complete MCP receipt contradicts execution evidence")
        return dict(receipt)
    except MCPReceiptError:
        raise
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        raise MCPReceiptError("invalid MCP receipt data") from exc
