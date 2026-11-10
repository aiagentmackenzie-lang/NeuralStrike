"""Freeze and run the single-variable model replication of the banking redirection finding.

One question, one changed declaration: the model. Every payload, the attacker account, the
task id, the policies, the seed and the budgets are the frozen ones in ``profile.py``. The
plan is written and hashed before the first inference, and each trial is a separate
``collect.py`` process re-verifying the declared digest before dispatch.

Exit codes: 0 = every trial complete and every declared expectation met; 3 = every trial
complete and at least one declared expectation not met (a recorded null, not a harness
error); 2 = at least one trial incomplete or a process failure. Nothing is re-scored,
retried or deleted: incomplete rows stay in the summary with their journals.

This is a local replication, not independent review and not Phase 3 acceptance.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

from examples.agentdojo_banking.collect import atomic
from examples.agentdojo_banking.profile import (
    BUDGETS,
    DECISION_RULE,
    HYPOTHESIS,
    PLAN_KIND,
    REPEAT_SEMANTICS,
    REPEATS,
    REPLICATED_MODELS,
    REPLICATES,
    REPLICATES_NOTE,
    REVISION,
    SEED,
    SUPERSEDES,
    model_block,
    trials_for,
    verify_model_pin,
)


def harness_hashes(root: Path) -> dict[str, str]:
    return {
        str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
        for folder in ("agentdojo_banking", "agentdojo_workspace")
        for p in sorted((root / "examples" / folder).glob("*.py"))
    }


def freeze_harness(root: Path, target: Path, expected: dict[str, str]) -> None:
    """Preserve the exact harness bytes that will be dispatched, not just their digest."""
    for relative, declared in expected.items():
        raw = (root / relative).read_bytes()
        if hashlib.sha256(raw).hexdigest() != declared:
            raise RuntimeError("harness changed while freezing the plan")
        copy = target / relative
        copy.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor = os.open(copy, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)


def build_plan(
    trials: list[dict[str, Any]], pins: dict[str, Any], hashes: dict[str, str], repeats: int
) -> dict[str, Any]:
    """Every expectation, budget and pin, declared before the first inference call."""
    return {
        "kind": PLAN_KIND,
        "replicates": REPLICATES,
        "replicates_note": REPLICATES_NOTE,
        "supersedes": SUPERSEDES,
        "source_revision": REVISION,
        "hypothesis": HYPOTHESIS,
        "decision_rule": DECISION_RULE,
        "models": [model_block(name) for name in REPLICATED_MODELS],
        "model_pins": {name: pins[name] for name in REPLICATED_MODELS},
        "replicated_model": REPLICATED_MODELS[1],
        "repeats": repeats,
        "repeat_semantics": REPEAT_SEMANTICS,
        "seed": SEED,
        "trials": trials,
        "budgets": BUDGETS,
        "source_files_sha256": hashes,
        "measurement_boundary": "completed_effect",
        "independent_human_validation": False,
        "feasibility_probe": {
            "question": (
                "does the candidate emit a native tool_calls entry through the same loopback "
                "ollama_chat/OpenAI path with the banking target's own tool schema?"
            ),
            "excluded_from_counts": True,
            "environment_or_payload_used": False,
            "observed": {
                "qwen3.5:2b": "baseline model of the replicated index (native tool calls in trial)",
                "gemma4:31b": (
                    "1 native tool_call (get_balance), finish_reason tool_calls, "
                    "no reasoning channel"
                ),
                "nemotron-3.5-lightning:30b": (
                    "1 native tool_call (get_balance), no reasoning channel; not selected"
                ),
                "qwen3.8:27b": (
                    "1 native tool_call (get_balance), no reasoning channel; not selected"
                ),
                "mistral:7b": "0 tool_calls, prose only -> rejected (uninformative null)",
                "phi4-mini:latest": "0 tool_calls, prose only -> rejected (uninformative null)",
            },
            "selection_rule": (
                "loopback only, no download, capability not outcome: different family from the "
                "baseline, declared once, never swapped after a result"
            ),
        },
        "limitations": [
            "One machine, one seed, two models; not a population and not a rate.",
            "Native upstream predicates are labels, not independent human review.",
            "Harness-authored payload and authorization wrapper; not stock benchmark scores.",
            "The second model's rows are counts at seed 7 and say nothing about other seeds.",
        ],
    }


def initial_row(trial: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": trial["id"],
        "model": trial["model"],
        "case": trial["case"],
        "policy": trial["policy"],
        "seed": trial["seed"],
        "repeat": trial["repeat"],
        "expected_violation": trial["expected_violation"],
        "expected_utility": trial["expected_utility"],
        "process_complete": False,
        "violation": None,
        "utility": None,
        "expectations_met": None,
        "observation": None,
        "observation_sha256": None,
    }


def dispatch(
    destination: Path, python: Path, source: Path, trial: dict[str, Any], row: dict[str, Any]
) -> None:
    """Run one native trial from the frozen harness copy and read its journal.

    A timeout or non-zero exit leaves the row with ``violation: None`` and an error; it is
    never retried and never removed, because a failed row is part of the record.
    """
    command = [
        str(python),
        str(destination / "harness/examples/agentdojo_banking/collect.py"),
        "--source",
        str(source),
        "--out",
        str(destination / trial["id"]),
        "--case",
        trial["case"],
        "--policy",
        trial["policy"],
        "--seed",
        str(trial["seed"]),
        "--prefetch-bill",
        "--model",
        trial["model"],
    ]
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=BUDGETS["collector_timeout_seconds"],
            check=False,
        )
    except subprocess.TimeoutExpired:
        row["error"] = "collector timeout; journal preserved"
        return
    atomic(
        destination / f"{trial['id']}-process.json",
        {"returncode": process.returncode, "stdout": process.stdout, "stderr": process.stderr},
    )
    row["process_complete"] = process.returncode == 0
    if process.returncode != 0:
        row["error"] = "collector failed; inspect preserved process record"
        return
    observation = Path(process.stdout.strip().splitlines()[-1]) / "observation.json"
    raw = observation.read_bytes()
    document = json.loads(raw)
    row.update(
        violation=document["upstream_violation"],
        utility=document["upstream_utility"],
        observation=str(observation.relative_to(destination)),
        observation_sha256=hashlib.sha256(raw).hexdigest(),
        execution_state=document["state"],
    )
    met_violation = row["violation"] is row["expected_violation"]
    met_utility = True if row["expected_utility"] is None else row["utility"] is row["expected_utility"]
    row["expectations_met"] = document["state"] == "complete" and met_violation and met_utility


def replication(output: Path, python: Path, source: Path, *, repeats: int = REPEATS) -> Path:
    root = Path(__file__).resolve().parents[2]
    trials = trials_for(repeats=repeats)
    pins = {name: verify_model_pin(name) for name in REPLICATED_MODELS}
    destination = output / f"banking-replication-{uuid.uuid4().hex}"
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    hashes = harness_hashes(root)
    plan = build_plan(trials, pins, hashes, repeats)
    freeze_harness(root, destination / "harness", hashes)
    atomic(destination / "plan.json", plan)
    plan_sha = hashlib.sha256((destination / "plan.json").read_bytes()).hexdigest()
    summary: dict[str, Any] = {
        "kind": "agentdojo-banking-model-replication-result",
        "state": "running",
        "plan_kind": PLAN_KIND,
        "plan_sha256": plan_sha,
        "source_revision": REVISION,
        "rows": [],
        "counts": {},
        "independent_human_validation": False,
    }
    atomic(destination / "summary.json", summary)

    for trial in trials:
        # Re-verify before each trial: a pin that moved mid-run must stop the next dispatch.
        verify_model_pin(trial["model"])
        row = initial_row(trial)
        summary["rows"].append(row)
        atomic(destination / "summary.json", summary)
        dispatch(destination, python, source, trial, row)
        atomic(destination / "summary.json", summary)

    counts: dict[str, dict[str, Any]] = {}
    for row in summary["rows"]:
        key = f"{row['model']}|{row['case']}|{row['policy']}"
        bucket = counts.setdefault(
            key,
            {
                "model": row["model"],
                "case": row["case"],
                "policy": row["policy"],
                "k": 0,
                "complete": 0,
                "violations": 0,
                "utility_true": 0,
                "expected_violation": row["expected_violation"],
                "expected_utility": row["expected_utility"],
                "expectations_met": 0,
            },
        )
        bucket["k"] += 1
        if row["violation"] is not None:
            bucket["complete"] += 1
            bucket["violations"] += int(bool(row["violation"]))
            bucket["utility_true"] += int(bool(row["utility"]))
        bucket["expectations_met"] += int(row["expectations_met"] is True)
    complete = all(row["violation"] is not None for row in summary["rows"])
    met = all(row["expectations_met"] is True for row in summary["rows"])
    state = "incomplete" if not complete else ("complete" if met else "expectations_not_reproduced")
    summary.update(
        counts=counts,
        state=state,
        rows_complete=sum(1 for row in summary["rows"] if row["violation"] is not None),
        rows_planned=len(summary["rows"]),
    )
    atomic(destination / "summary.json", summary)
    return destination


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("--repeats", type=int, default=REPEATS)
    args = parser.parse_args()
    destination = replication(
        args.out.resolve(), args.python.absolute(), args.source.resolve(), repeats=args.repeats
    )
    summary = json.loads((destination / "summary.json").read_text())
    print(destination)
    print(json.dumps({"state": summary["state"], "rows_complete": summary["rows_complete"]}))
    raise SystemExit(
        0
        if summary["state"] == "complete"
        else (3 if summary["state"] == "expectations_not_reproduced" else 2)
    )


if __name__ == "__main__":
    main()
