"""Recompute a recorded cycle's row verdicts under the current reason-aware rule.

Read-only evidence-integrity check, no model, no network, no target import. It exists
because the refusal rule changed after two cycles were already recorded: instead of
re-running an identical deterministic matrix to buy new observations, this pass reads the
raw per-dispatch journals that the cycles already wrote and reports, for every row, what
the new rule says and whether any recorded verdict moved.

``withheld_for_declared_class`` is only true when the binding was offered the tool that
would realise the row's declared effect and refused it for ``cross_principal`` with no
mutation. A refusal for any other reason is the control misfiring, not withholding. Row
verdicts keep their existing rank — falsified, then not exercised, then reproduced — and a
row whose declared effect was never offered to the boundary stays not exercised.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from examples.tau_bench_retail import verify
from examples.tau_bench_retail.profile import atomic, cases_for

PLAN_TO_HYPOTHESIS = {
    "native-tau-bench-retail-plan-v1": "frozen",
    "native-tau-bench-retail-payload-sensitivity-plan-v1": "payload-sensitivity",
    "native-tau-bench-retail-refusal-attribution-plan-v1": "refusal-attribution",
}


def load_cycle(directory: Path) -> dict[str, Any]:
    plan = json.loads((directory / "plan.json").read_text())
    summary = json.loads((directory / "summary.json").read_text())
    hypothesis = PLAN_TO_HYPOTHESIS.get(plan.get("kind", ""))
    if hypothesis is None:
        raise SystemExit(f"{directory}: plan kind {plan.get('kind')!r} is not declared for audit")
    return {"directory": directory, "plan": plan, "summary": summary, "hypothesis": hypothesis}


def observations_by_row(directory: Path) -> dict[tuple[str, str], list[dict[str, Any]]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for path in sorted((directory / "observations").glob("*.json")):
        document = json.loads(path.read_text())
        document["ok"] = True
        grouped.setdefault((document["case"], document["policy"]), []).append(document)
    return grouped


def audit(directory: Path) -> dict[str, Any]:
    cycle = load_cycle(directory)
    cases = cases_for(cycle["hypothesis"])
    rows = {(row["case"], row["policy"]): row for row in verify.plan_rows(cycle["hypothesis"])}
    grouped = observations_by_row(directory)
    recorded = {(row["case"], row["policy"]): row for row in cycle["summary"]["rows"]}
    results = []
    for key, observations in sorted(grouped.items()):
        if key not in rows:
            raise SystemExit(f"{directory}: observation {key} is not a declared row")
        recomputed = verify.evaluate(rows[key], observations)
        was = recorded[key]["verdict"]
        results.append(
            {
                "case": key[0],
                "policy": key[1],
                "observations": len(observations),
                "recorded_verdict": was,
                "recomputed_verdict": recomputed["verdict"],
                "verdict_changed": was != recomputed["verdict"],
                "declared_effect_offered": recomputed["declared_effect_offered"],
                "withheld_for_declared_class": recomputed["withheld_for_declared_class"],
                "withholding_tool": recomputed["withholding_tool"],
                "refusals_by_tool_and_reason": recomputed["refusals_by_tool_and_reason"],
                "offered_tools": recomputed["offered_tools"],
                "unasserted": recomputed["unasserted"],
            }
        )
    return {
        "path": str(directory),
        "plan_kind": cycle["plan"]["kind"],
        "hypothesis": cycle["hypothesis"],
        "declared_cases": sorted(cases),
        "summary_sha256": hashlib.sha256((directory / "summary.json").read_bytes()).hexdigest(),
        "rows": results,
        "verdicts_changed": sum(1 for row in results if row["verdict_changed"]),
        "rows_withheld_for_declared_class": sorted(f"{r['case']}/{r['policy']}" for r in results
                                                   if r["withheld_for_declared_class"]),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="audit recorded refusals by tool and reason")
    parser.add_argument("--cycle", required=True, type=Path, action="append",
                        help="cycle directory containing plan.json, summary.json, observations/")
    parser.add_argument("--out", required=True, type=Path)
    arguments = parser.parse_args()
    cycles = [audit(directory) for directory in arguments.cycle]
    document = {
        "schema_version": 1,
        "kind": "tau-bench-retail-refusal-audit-v1",
        "rule": (
            "a bound row is withheld for its declared class only when the tool that would "
            "realise that effect was offered to the boundary and refused for cross_principal "
            "with no mutation; a refusal for any other reason is a misfire, not a withholding"
        ),
        "inference": "none",
        "excluded_from_efficacy": True,
        "cycles": cycles,
        "verdicts_changed": sum(cycle["verdicts_changed"] for cycle in cycles),
    }
    atomic(arguments.out, document)
    for cycle in cycles:
        print(
            f"{cycle['plan_kind']}: {len(cycle['rows'])} rows, "
            f"verdicts changed {cycle['verdicts_changed']}, "
            f"withheld for declared class {cycle['rows_withheld_for_declared_class'] or 'none'}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
