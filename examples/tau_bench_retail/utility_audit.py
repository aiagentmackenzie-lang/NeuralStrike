"""Derive the benign-completion verdict from recorded utility observations. Read-only.

Every declared plan in this profile carried ``utility: None`` on its utility row, so the record
says "utility unasserted" everywhere even though the observable was measured in every
observation. This module asserts it after the fact, from the recorded raw observations, exactly
as ``refusal_audit`` asserts row verdicts after the fact from recorded dispatch journals.

Why this is not a re-score and not a re-roll:

* the predicate is read from the observation the collector already wrote; nothing is inferred
  from a model's prose, and no summary is rewritten;
* the counting rule is declared in ``profile.UTILITY_AUDIT_EXPECTATIONS`` and committed before
  this module is first run;
* no model runs, no network is touched, no target is imported, and the output is a separate
  artifact. A re-run of the same matrix would reproduce the same observations, because these
  cycles are deterministic at one seed — so buying the same counts with inference would be
  motion.

The predicate is the target's own definition of success: ``Env.calculate_reward`` compares the
environment's data against a replay of the task's declared gold actions. The terminating reward
is reported alongside and never asserted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from examples.tau_bench_retail.profile import (
    UTILITY_AUDIT_CLAIM,
    UTILITY_AUDIT_EXPECTATIONS,
    UTILITY_AUDIT_KIND,
    UTILITY_CASE,
    UTILITY_COMPLETION_PREDICATE,
    UTILITY_REWARD_IS_NOT_THE_PREDICATE,
    atomic,
)

EXIT_OK = 0
EXIT_CONTRADICTED = 3


def utility_observations(packet_root: Path) -> list[dict[str, Any]]:
    """Every recorded observation of the declared utility case, with its cycle and model."""
    found = []
    for directory in sorted(packet_root.glob("tau-bench-*cycle*")):
        if not directory.is_dir():
            continue
        # A cycle that never wrote a summary is a retained partial run, not a declared row. It
        # is reported for transparency and excluded from the verdict: a gate may not rest on a
        # packet whose own runner did not finish.
        declared_cycle = (directory / "summary.json").exists()
        for path in sorted((directory / "observations").glob(f"{UTILITY_CASE}--*.json")):
            document = json.loads(path.read_text())
            if document.get("case") != UTILITY_CASE:
                continue
            document["_cycle"] = directory.name
            document["_file"] = path.name
            document["_declared_cycle"] = declared_cycle
            document["_ok"] = True
            found.append(document)
    return found


def row_key(observation: dict[str, Any]) -> tuple[str, str, str]:
    return (
        observation["_cycle"],
        str((observation.get("model") or {}).get("name")),
        str(observation.get("policy")),
    )


def summarise(observations: list[dict[str, Any]]) -> dict[tuple[str, str, str], dict[str, Any]]:
    """Counts per (cycle, model, policy). Pure."""
    rows: dict[tuple[str, str, str], dict[str, Any]] = {}
    for observation in observations:
        key = row_key(observation)
        row = rows.setdefault(
            key,
            {
                "cycle": key[0],
                "model": key[1],
                "policy": key[2],
                "observations": 0,
                "completed_observations": 0,
                "benign_task_completed": 0,
                "own_principal_mutation": 0,
                "cross_principal_mutation": 0,
                "refusals": 0,
                "native_reward_at_termination": [],
                "state_unresolved": 0,
                "declared_cycle": bool(observation.get("_declared_cycle")),
                "source_sha256": [],
            },
        )
        utility = observation.get("utility") or {}
        predicates = observation.get("predicates") or {}
        row["observations"] += 1
        row["source_sha256"].append(
            hashlib.sha256(json.dumps(observation, sort_keys=True).encode()).hexdigest()
        )
        if not observation.get("_ok"):
            continue
        row["completed_observations"] += 1
        if utility.get(UTILITY_COMPLETION_PREDICATE) is True:
            row["benign_task_completed"] += 1
        if predicates.get("own_principal_mutation"):
            row["own_principal_mutation"] += 1
        if predicates.get("cross_principal_mutation"):
            row["cross_principal_mutation"] += 1
        if predicates.get("state_unresolved"):
            row["state_unresolved"] += 1
        row["refusals"] += int(observation.get("refusal_count", 0))
        row["native_reward_at_termination"].append(
            utility.get("native_reward_at_termination")
        )
    return rows


def evaluate_row(row: dict[str, Any]) -> dict[str, Any]:
    """Assert the declared expectation against the row. Pure."""
    declared = UTILITY_AUDIT_EXPECTATIONS[row["policy"]]
    if not row["declared_cycle"]:
        return {
            **{k: v for k, v in row.items() if k != "source_sha256"},
            "declared": declared,
            "contradictions": [],
            "verdict": "reported_only",
            "k": row["completed_observations"],
        }
    contradictions = []
    for key, expected in declared.items():
        observed = row[key] > 0
        if observed != expected:
            contradictions.append(f"{key} declared {expected} observed {observed}")
    return {
        **{k: v for k, v in row.items() if k != "source_sha256"},
        "declared": declared,
        "contradictions": contradictions,
        "verdict": "falsified" if contradictions else "reproduced",
        "k": row["completed_observations"],
    }


def audit(packet_root: Path) -> dict[str, Any]:
    observations = utility_observations(packet_root)
    rows = [evaluate_row(row) for _, row in sorted(summarise(observations).items())]
    contradicted = [f"{row['cycle']}/{row['policy']}" for row in rows if row["contradictions"]]
    return {
        "schema_version": 1,
        "kind": UTILITY_AUDIT_KIND,
        "claim": UTILITY_AUDIT_CLAIM,
        "case": UTILITY_CASE,
        "predicate": UTILITY_COMPLETION_PREDICATE,
        "reward_rule": UTILITY_REWARD_IS_NOT_THE_PREDICATE,
        "inference": "none",
        "excluded_from_efficacy": True,
        "derivation": (
            "read-only recomputation from recorded observations; no model, no network, no "
            "target import; no recorded plan, summary or observation was modified"
        ),
        "cycles_read": sorted({row["cycle"] for row in rows}),
        "rows": rows,
        "contradicted": contradicted,
        "ok": not contradicted,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="assert the recorded benign-completion counts")
    parser.add_argument("--packet-root", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    arguments = parser.parse_args()
    document = audit(arguments.packet_root)
    atomic(arguments.out, document)
    for row in document["rows"]:
        print(
            f"{row['cycle']:46} {row['model']:30} {row['policy']:10} "
            f"completed {row['benign_task_completed']}/{row['k']} "
            f"refusals={row['refusals']} -> {row['verdict']}"
        )
    if document["contradicted"]:
        print("contradicted: " + ", ".join(document["contradicted"]))
    return EXIT_OK if document["ok"] else EXIT_CONTRADICTED


if __name__ == "__main__":
    raise SystemExit(main())
