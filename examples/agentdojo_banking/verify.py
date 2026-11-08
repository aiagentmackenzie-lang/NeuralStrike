"""Rerun a real local-model redirection/fix/regression cycle; no cloud backend.

Requires the pinned AgentDojo checkout, isolated hashed environment and existing
pinned Ollama model. A run that does not reproduce the expectations fails openly.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import uuid
from pathlib import Path

from examples.agentdojo_banking.collect import atomic


def verify(source: Path, python: Path, output: Path) -> Path:
    root = output / f"remediation-{uuid.uuid4().hex}"
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    receipt = {
        "kind": "agentdojo-local-remediation",
        "state": "running",
        "stages": [],
        "independent_human_validation": False,
    }
    atomic(root / "cycle.json", receipt)
    for policy, expected_violation, expected_utility in [
        ("unfiltered", True, False),
        ("bound_bill_payment", False, True),
        ("unfiltered", True, False),
    ]:
        command = [
            str(python),
            str(Path(__file__).with_name("collect.py")),
            "--source",
            str(source),
            "--out",
            str(root),
            "--case",
            "recipient_field_redirection",
            "--policy",
            policy,
            "--prefetch-bill",
            "--seed",
            "7",
        ]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=150, check=False)
        except subprocess.TimeoutExpired:
            receipt["state"] = "incomplete"
            receipt["error"] = "collector timeout; inspect preserved observation journals"
            atomic(root / "cycle.json", receipt)
            raise
        atomic(
            root / f"process-{len(receipt['stages'])}.json",
            {
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            },
        )
        if result.returncode:
            receipt["state"] = "incomplete"
            receipt["error"] = "collector failed; inspect preserved observation journals"
            atomic(root / "cycle.json", receipt)
            raise RuntimeError(receipt["error"])
        observation = Path(result.stdout.strip().splitlines()[-1]) / "observation.json"
        document = json.loads(observation.read_text())
        stage = {
            "policy": policy,
            "observation": str(observation.relative_to(root)),
            "violation": document["upstream_violation"],
            "utility": document["upstream_utility"],
            "execution_state": document["state"],
        }
        receipt["stages"].append(stage)
        atomic(root / "cycle.json", receipt)
        if (
            document["state"] != "complete"
            or document.get("error")
            or (stage["violation"] is not expected_violation or stage["utility"] is not expected_utility)
        ):
            receipt["state"] = "expectations_not_reproduced"
            atomic(root / "cycle.json", receipt)
            raise RuntimeError("local remediation cycle expectations not reproduced")
    receipt["state"] = "verified_local_only"
    atomic(root / "cycle.json", receipt)
    return root


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    print(verify(args.source.resolve(), args.python.absolute(), args.out.resolve()))


if __name__ == "__main__":
    main()
