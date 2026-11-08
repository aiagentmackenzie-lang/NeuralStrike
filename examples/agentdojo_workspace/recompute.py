"""Recompute the narrow native list/delete profile without model or oracle calls.

This executes explicitly pinned, trusted native in-memory operations, not arbitrary
recorded tool names. It is separate from NeuralStrike's original-oracle replay.
"""

from __future__ import annotations

# ruff: noqa: PLC0415 -- native dependencies live only in the isolated candidate environment
import argparse
import hashlib
import json
import socket
import sys
import uuid
from pathlib import Path
from typing import Any

from examples.agentdojo_banking.collect import REVISION, atomic, source_receipt
from examples.agentdojo_workspace.profile import CASES, POLICIES, approved_file, permitted
from examples.agentdojo_workspace.schema import SCHEMA_PROFILES


def recompute(document: dict[str, Any], suite: Any, runtime: Any) -> dict[str, Any]:
    if (
        document.get("kind") != "agentdojo-workspace-local-observation"
        or (type(document.get("schema_version")) is not int or document["schema_version"] != 1)
        or document.get("source_revision") != REVISION
        or document.get("state") != "complete"
        or document.get("error")
        or document.get("case") not in CASES
        or document.get("policy") not in POLICIES
        or document.get("tool_schema_profile", "native") not in SCHEMA_PROFILES
    ):
        raise ValueError("only complete reviewed workspace observations can be recomputed")
    environment = suite.load_and_inject_default_environment(document["injections"])
    pre = environment.model_copy(deep=True)
    if pre.model_dump(mode="json") != document["pre_environment"]:
        raise ValueError("recorded pre-state differs from native fixture/injections")
    approved = approved_file(suite.load_and_inject_default_environment({}))
    for action in document["actions"]:
        function, args, status = action["function"], action["arguments"], action["status"]
        # Never dispatch arbitrary tool names from evidence, even in this native suite.
        if function not in {"list_files", "delete_file"} or not isinstance(args, dict):
            raise ValueError("unsupported recomputation operation")
        if (
            (function == "list_files" and args)
            or (function == "delete_file" and (set(args) != {"file_id"} or type(args["file_id"]) is not str))
            or "effective_arguments" in action
        ):
            raise ValueError("unsupported recomputation arguments")
        allowed = document["policy"] == "unfiltered" or permitted(function, args, approved)
        if status == "blocked" and not allowed:
            continue
        if status != "completed" or not allowed or action.get("error"):
            raise ValueError("incomplete/invalid dispatch or inconsistent authorization receipt")
        _, error = runtime.run_function(environment, function, dict(args))
        if error:
            raise ValueError("recorded completed dispatch failed native recomputation")
    if environment.model_dump(mode="json") != document["post_environment"]:
        raise ValueError("recorded post-state differs from recomputed native effects")
    violation = suite.injection_tasks["injection_task_1"].security("", pre, environment)
    utility = suite.user_tasks["user_task_35"].utility("", pre, environment)
    if violation is not document.get("upstream_violation") or utility is not document.get("upstream_utility"):
        raise ValueError("recorded labels differ from recomputed native predicates")
    return {
        "state_match": True,
        "upstream_predicates_match": True,
        "violation": violation,
        "utility": utility,
        "model_or_oracle_calls": 0,
    }


def verify(source: Path, paths: list[Path], output: Path) -> Path:
    hashes = source_receipt(source)
    root = output / f"recompute-{uuid.uuid4().hex}"
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    receipt: dict[str, Any] = {
        "kind": "native-workspace-effect-recomputation",
        "state": "running",
        "independent_human_validation": False,
        "observations": [],
    }
    atomic(root / "receipt.json", receipt)
    sys.path.insert(0, str(source / "src"))
    connect, connect_ex = socket.socket.connect, socket.socket.connect_ex

    def reject_network(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("network prohibited during native effect recomputation")

    socket.socket.connect = reject_network
    socket.socket.connect_ex = reject_network
    try:
        from agentdojo.functions_runtime import FunctionsRuntime
        from agentdojo.task_suite import get_suite

        suite = get_suite("v1", "workspace")
        for path in paths:
            row: dict[str, Any] = {"path": str(path), "verified": False}
            receipt["observations"].append(row)
            try:
                raw = path.read_bytes()
                row["sha256"] = hashlib.sha256(raw).hexdigest()
                document = json.loads(raw)
                if document["source_hashes"] != hashes:
                    raise ValueError("native source receipt differs from selected checkout")
                row.update(recompute(document, suite, FunctionsRuntime(suite.tools)), verified=True)
            except (OSError, ValueError, KeyError, TypeError) as exc:
                row["error"] = f"{type(exc).__name__}: {exc}"
            atomic(root / "receipt.json", receipt)
        receipt["state"] = (
            "verified_native_effects"
            if paths and all(row["verified"] for row in receipt["observations"])
            else "incomplete"
        )
    except BaseException as exc:
        receipt.update(state="incomplete", error=f"{type(exc).__name__}: {exc}")
        raise
    finally:
        socket.socket.connect, socket.socket.connect_ex = connect, connect_ex
        atomic(root / "receipt.json", receipt)
    return root


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--observation", type=Path, action="append", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    root = verify(args.source.resolve(), args.observation, args.out.resolve())
    print(root)
    if json.loads((root / "receipt.json").read_text())["state"] != "verified_native_effects":
        raise SystemExit(3)


if __name__ == "__main__":
    main()
