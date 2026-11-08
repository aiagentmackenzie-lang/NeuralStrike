"""Collect one pinned workspace trial in the separate AgentDojo environment."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Support direct execution by the isolated candidate interpreter.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from examples.agentdojo_banking.collect import run
from examples.agentdojo_workspace.profile import CASES, POLICIES


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--case", choices=CASES, required=True)
    parser.add_argument("--policy", choices=sorted(POLICIES), default="unfiltered")
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()
    print(
        run(
            args.source.resolve(),
            args.out.resolve(),
            args.case,
            args.policy,
            args.seed,
            True,
            profile="workspace",
        )
    )


if __name__ == "__main__":
    main()
