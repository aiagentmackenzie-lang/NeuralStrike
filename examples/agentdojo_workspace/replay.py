"""Import native workspace effects through the existing canonical assessment APIs."""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from examples.agentdojo_banking.replay import import_observations


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observation", type=Path, action="append", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    print(
        asyncio.run(
            import_observations(
                args.observation, args.out, measurement="completed_effect", profile="workspace"
            )
        )
    )


if __name__ == "__main__":
    main()
