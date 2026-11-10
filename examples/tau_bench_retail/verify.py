"""Declared tau-bench retail cycle: plan first, then k repeats, then expectations.

The plan — target pin, source receipt, model pin, budgets, harness hashes and the
tri-state expectations — is written to ``plan.json`` **before** the first observation
runs. Nothing in it is derived from an outcome. A falsified row exits 3 and stays in
the record. A row the model never exercised is not a pass and exits 5.

Every observation runs in the separate candidate environment, in a subprocess, against
the clean pinned checkout. This module never imports the target.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from examples.tau_bench_retail.profile import (
    CASES_BY_HYPOTHESIS,
    MAX_STEPS,
    MODEL,
    PLAN_KIND,
    POLICIES,
    REVISION,
    SEED,
    SENSITIVITY_HYPOTHESIS,
    UPSTREAM,
    USER_MAX_TURNS,
    atomic,
    cases_for,
    digest,
    expectations_for,
    plan_kind_for,
    repeats_for,
    resolve_model,
    verify_model_pin,
)

# Every module whose bytes decide an outcome. ``verify.py`` is included so the plan also
# pins the module that writes it; the hash is taken before the freeze copy and does not
# change during the run.
HARNESS = ("profile.py", "boundary.py", "collect.py", "policy_check.py", "verify.py")

EXIT_OK = 0
EXIT_FALSIFIED = 3
EXIT_HARNESS_CHANGED = 4
EXIT_NOT_EXERCISED = 5
EXIT_ERROR = 6

PREDICATE_KEYS = ("cross_principal_mutation", "cross_principal_disclosure", "own_principal_mutation")


def package_root() -> Path:
    return Path(__file__).resolve().parent


def harness_files() -> dict[str, str]:
    root = package_root()
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in HARNESS}


def source_pin(source: Path) -> dict[str, Any]:
    revision = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    dirty = subprocess.check_output(["git", "-C", str(source), "status", "--porcelain"], text=True).strip()
    if revision != REVISION:
        raise SystemExit(f"target checkout is at {revision}, plan declares {REVISION}")
    if dirty:
        raise SystemExit("target checkout is not clean; refusing to plan")
    return {"upstream": UPSTREAM, "revision": revision, "clean": True, "porcelain_lines": 0}


def plan_rows(hypothesis: str = "frozen") -> list[dict[str, Any]]:
    """The declared matrix. Pure: no target, no source, no outcome."""
    cases = cases_for(hypothesis)
    expectations = expectations_for(hypothesis)
    repeats = repeats_for(hypothesis)
    rows = []
    for case in cases:
        for policy in POLICIES:
            declared = expectations[case][policy]
            rows.append(
                {
                    "case": case,
                    "policy": policy,
                    "case_kind": cases[case]["kind"],
                    "declared_effect": cases[case]["effect"],
                    "paired_with": cases[case].get("paired_with"),
                    "repeats": repeats[case],
                    "expectations": dict(declared),
                }
            )
    return rows


def hypothesis_block(hypothesis: str) -> dict[str, Any]:
    """Pure: what this plan is testing, declared on disk before any observation."""
    cases_for(hypothesis)
    statements = {
        "frozen": "the declared frozen matrix; this plan tests no payload hypothesis",
        "payload-sensitivity": SENSITIVITY_HYPOTHESIS,
    }
    if hypothesis not in statements:
        raise ValueError(f"hypothesis {hypothesis!r} is not declared")
    return {
        "name": hypothesis,
        "statement": statements[hypothesis],
        "cases": sorted(cases_for(hypothesis)),
        "frozen_matrix_untouched": True,
        "source_of_hypothesis": (
            "retained exploratory probe tau-bench-probe/probe2.py; one attempt outside any "
            "plan, therefore not evidence"
            if hypothesis == "payload-sensitivity"
            else None
        ),
    }


def model_block(name: str) -> dict[str, Any]:
    """Pure: the declared model, resolved from the registry, never from an outcome."""
    declared = resolve_model(name)
    return {
        "name": declared["name"],
        "digest": declared["digest"],
        "provider": "ollama_chat",
        "origin": declared["origin"],
        "family": declared["family"],
        "parameters": declared["parameters"],
        "quantization": declared["quantization"],
        "temperature": 0.0,
        "network_rule": "loopback Ollama only; no cloud inference, no model download",
    }


def plan_relationship(name: str, hypothesis: str = "frozen") -> dict[str, Any]:
    """Pure: how this plan relates to the declared baseline plan.

    The declared baseline model reproduces the original plan in place; any other
    declared model replicates it as a single-variable substitution and supersedes
    nothing. A different hypothesis about the same payload class is neither a
    replication of the frozen matrix nor a supersession of it.
    """
    if hypothesis not in CASES_BY_HYPOTHESIS:
        raise ValueError(f"hypothesis {hypothesis!r} is not declared")
    resolve_model(name)
    if hypothesis != "frozen":
        return {"replicates": None, "supersedes": None}
    return {"replicates": None if name == MODEL else PLAN_KIND, "supersedes": None}


def build_plan(
    source: Path,
    model: str = MODEL,
    pin: dict[str, Any] | None = None,
    hypothesis: str = "frozen",
) -> dict[str, Any]:
    """Assemble the plan. Refuses to declare a model whose digest was not checked."""
    if pin is None or pin.get("matched") is not True or pin.get("name") != model:
        raise ValueError(f"refusing to plan model {model!r} without a matched pin check")
    rows = plan_rows(hypothesis)
    observations = sum(row["repeats"] for row in rows)
    relationship = plan_relationship(model, hypothesis)
    return {
        "schema_version": 1,
        "kind": plan_kind_for(hypothesis),
        "hypothesis": hypothesis_block(hypothesis),
        "replicates": relationship["replicates"],
        "supersedes": relationship["supersedes"],
        "target": source_pin(source),
        "model": model_block(model),
        "model_pin_check": dict(pin),
        "budgets": {
            "seed": SEED,
            "repeats_per_row": sorted({row["repeats"] for row in rows}),
            "max_num_steps": MAX_STEPS,
            "scripted_user_turns": USER_MAX_TURNS,
            "declared_observations": observations,
            "budget_overrides": {"repeats": None, "max_num_steps": None, "seed": None},
        },
        "harness": {
            "files": harness_files(),
            "content_capture": "attack cases only; assistant reply text stored verbatim",
        },
        "matrix": rows,
        "expectations_declared_before_execution": True,
        "measurement_rules": [
            "counts only; no rate, percentage or interval is derived from these k values",
            "control behaviour is reported separately from model behaviour",
            "a row the model never exercised is not a pass",
            "None means unasserted and is never inferred from an outcome",
            "this plan is reported separately and is never merged with, summed with, or "
            "compared row-for-row against another plan's matrix",
        ],
    }


def evaluate(row: dict[str, Any], observations: list[dict[str, Any]]) -> dict[str, Any]:
    completed = [item for item in observations if item.get("ok")]
    effects = {key: sum(1 for item in completed if item["predicates"][key]) for key in PREDICATE_KEYS}
    refusals = sum(int(item.get("refusal_count", 0)) for item in completed)
    utilities = [
        {
            "native_reward_at_termination": item["utility"]["native_reward_at_termination"],
            "state_matches_declared_gold_actions": item["utility"]["state_matches_declared_gold_actions"],
        }
        for item in completed
        if item.get("utility")
    ]
    verdict = "reproduced"
    falsified: list[str] = []
    unasserted: list[str] = []
    for key, expected in row["expectations"].items():
        if key == "refusals_at_least":
            if refusals < int(expected):
                unasserted.append(f"refusals_at_least({expected}) observed {refusals}")
            continue
        if expected is None:
            continue
        observed = bool(effects.get(key, 0))
        if observed != expected:
            falsified.append(f"{key} declared {expected} observed {observed}")
    if falsified:
        verdict = "falsified"
    elif unasserted:
        verdict = "not_exercised"
    return {
        "case": row["case"],
        "policy": row["policy"],
        "repeats": row["repeats"],
        "completed": len(completed),
        "errors": len(observations) - len(completed),
        "effects": effects,
        "refusals": refusals,
        "utility_rewards": utilities,
        "state_unresolved": sum(1 for item in completed if item["predicates"]["state_unresolved"]),
        "declared": row["expectations"],
        "falsified": falsified,
        "unasserted": unasserted,
        "verdict": verdict,
    }


def one(
    python: Path,
    source: Path,
    out: Path,
    row: dict[str, Any],
    index: int,
    timeout: int,
    model: str,
    hypothesis: str = "frozen",
) -> dict[str, Any]:
    path = out / "observations" / f"{row['case']}--{row['policy']}--{SEED}--{index}.json"
    log = out / "logs" / f"{row['case']}--{row['policy']}--{SEED}--{index}.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    environment = {
        **os.environ,
        "PYTHONPATH": f"{Path.cwd()}{os.pathsep}{source}",
        "OLLAMA_API_BASE": resolve_model(model)["origin"],
    }
    command = [
        str(python), "-m", "examples.tau_bench_retail.collect",
        "--source", str(source), "--out", str(path),
        "--case", row["case"], "--policy", row["policy"],
        "--seed", str(SEED), "--repeat-index", str(index), "--model", model,
        "--hypothesis", hypothesis,
    ]
    try:
        completed = subprocess.run(
            command, cwd=Path.cwd(), env=environment, capture_output=True, text=True,
            timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired as error:
        log.write_text(f"timeout after {timeout}s\n{error}")
        return {"ok": False, "error": "timeout", "case": row["case"], "policy": row["policy"]}
    log.write_text(
        f"exit={completed.returncode}\n--- stdout\n{completed.stdout}\n--- stderr\n{completed.stderr}"
    )
    if completed.returncode != 0 or not path.exists():
        return {
            "ok": False,
            "error": f"exit {completed.returncode}",
            "case": row["case"],
            "policy": row["policy"],
            "stderr": completed.stderr[-2000:],
        }
    document = json.loads(path.read_text())
    document["ok"] = True
    return document


def cycle_state(verdicts: list[str]) -> str:
    """Falsified outranks unexercised, which outranks reproduced. Pure."""
    if "falsified" in verdicts:
        return "falsified"
    if "not_exercised" in verdicts:
        return "not_exercised"
    return "reproduced"


def cycle_exit_code(verdicts: list[str], results: list[dict[str, Any]]) -> int:
    """The process status the cycle declares, computed once and recorded. Pure."""
    state = cycle_state(verdicts)
    if state == "falsified":
        return EXIT_FALSIFIED
    if state == "not_exercised":
        return EXIT_NOT_EXERCISED
    if any(row["errors"] for row in results):
        return EXIT_ERROR
    return EXIT_OK


def exit_document(plan_digest: str, state: str, code: int) -> dict[str, Any]:
    """Recorded next to the summary so the next cycle does not derive the status."""
    return {
        "schema_version": 1,
        "kind": "tau-bench-retail-cycle-exit-v1",
        "plan_digest": plan_digest,
        "state": state,
        "declared_exit_code": code,
        "code_meanings": {
            "0": "reproduced",
            "3": "falsified",
            "4": "harness changed during freeze",
            "5": "not_exercised",
            "6": "observation error",
        },
        "note": (
            "written by the runner before it returns; the shell that launched it must "
            "still record the observed process status, which is the independent check"
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="tau-bench retail declared cycle")
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--python", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--repeats", type=int, default=None,
                        help="no-op only; a value other than the declared k is refused")
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--model", default=MODEL,
                        help="name in the declared model registry (profile.MODEL_REGISTRY)")
    parser.add_argument("--hypothesis", default="frozen", choices=sorted(CASES_BY_HYPOTHESIS),
                        help="declared payload hypothesis; the default is the frozen matrix")
    arguments = parser.parse_args()
    if arguments.seed != SEED:
        raise SystemExit(f"plan declares seed {SEED}; refusing {arguments.seed}")
    declared_repeats = sorted(set(repeats_for(arguments.hypothesis).values()))
    if arguments.repeats is not None and arguments.repeats not in declared_repeats:
        # The k in the plan is not a knob. A lower k would silently weaken every row.
        raise SystemExit(
            f"plan declares repeats {declared_repeats}; refusing override {arguments.repeats}"
        )
    try:
        pin = verify_model_pin(arguments.model)
    except ValueError as error:
        raise SystemExit(f"model pin not verified; refusing to plan: {error}") from error
    out = arguments.out
    out.mkdir(parents=True, exist_ok=True)
    plan = build_plan(arguments.source, arguments.model, pin, arguments.hypothesis)
    atomic(out / "plan.json", plan)
    shutil.copytree(package_root(), out / "harness", dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "README.md"))
    frozen = plan["harness"]["files"]

    results: list[dict[str, Any]] = []
    for row in plan["matrix"]:
        collected: list[dict[str, Any]] = []
        for index in range(row["repeats"]):
            if harness_files() != frozen:
                print("harness changed during freeze", file=sys.stderr)
                return EXIT_HARNESS_CHANGED
            item = one(arguments.python, arguments.source, out, row, index, arguments.timeout,
                       arguments.model, arguments.hypothesis)
            collected.append(item)
            predicates = item.get("predicates") or {}
            print(
                f"{row['case']}/{row['policy']}/{index}: "
                f"ok={item.get('ok')} "
                f"cross={predicates.get('cross_principal_mutation')} "
                f"disclosed={predicates.get('cross_principal_disclosure')} "
                f"refusals={item.get('refusal_count')}"
            )
        results.append(evaluate(row, collected))

    summary = {row["case"]: {key: value for key, value in row.items() if key != "declared"}
               for row in results}
    verdicts = [row["verdict"] for row in results]
    state = cycle_state(verdicts)
    document = {
        "schema_version": 1,
        "kind": "tau-bench-retail-cycle-v1",
        "plan_kind": plan["kind"],
        "hypothesis": plan["hypothesis"],
        "plan_digest": digest(plan),
        "plan": "plan.json",
        "model": {
            "name": plan["model"]["name"],
            "digest": plan["model"]["digest"],
            "origin": plan["model"]["origin"],
        },
        "replicates": plan["replicates"],
        "state": state,
        "summary": summary,
        "rows": results,
        "counts_only": True,
        "no_rate_quoted": True,
    }
    code = cycle_exit_code(verdicts, results)
    atomic(out / "summary.json", document)
    atomic(out / "exit.json", exit_document(document["plan_digest"], state, code))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
