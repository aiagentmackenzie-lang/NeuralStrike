"""JailbreakBench pack — on-demand import behind ``--accept-license``.

JailbreakBench (Chao et al., 2024) is the community benchmark for
jailbreak attacks and defenses. NeuralStrike imports its harmful-behaviors
dataset on demand; **no data is bundled** (licensing + supply-chain
hygiene).

The default dataset URL is the upstream harmful-behaviors CSV. The parser
handles the documented schema (``Goal, Target, Type``). If upstream
changes the schema, the parser raises a clear error rather than silently
producing wrong probes.

Verdicts: JailbreakBench probes have **no expected-token oracle** ->
``--judge`` decides, or every probe is honestly Inconclusive.
"""

from __future__ import annotations

import csv
import io
from collections.abc import Callable

from neuralstrike.packs.base import Pack, PackProbe, default_fetcher, register_pack

__all__ = ["JailbreakBenchPack"]


@register_pack
class JailbreakBenchPack(Pack):
    """JailbreakBench harmful-behaviors dataset, imported on demand."""

    name = "jailbreakbench"
    license_url = "https://github.com/JailbreakBench/jailbreakbench/blob/main/LICENSE"
    requires_accept_license = True

    dataset_url = (
        "https://raw.githubusercontent.com/JailbreakBench/jailbreakbench/"
        "main/data/harmful_behaviors.csv"
    )

    def probes(
        self,
        *,
        accept_license: bool = False,
        fetcher: Callable[[str], str] | None = None,
        limit: int | None = None,
    ) -> list[PackProbe]:
        if fetcher is None and not accept_license:
            raise PermissionError(
                f"pack {self.name!r} requires --accept-license before a network "
                f"fetch (license: {self.license_url})"
            )
        fetch = fetcher or default_fetcher
        raw = fetch(self.dataset_url)
        return self._parse(raw, limit=limit)

    def _parse(self, raw: str, *, limit: int | None = None) -> list[PackProbe]:
        reader = csv.DictReader(io.StringIO(raw))
        if not reader.fieldnames or "Goal" not in reader.fieldnames:
            raise ValueError(
                f"JailbreakBench CSV schema mismatch (expected a 'Goal' column); "
                f"got fieldnames={reader.fieldnames!r}. Upstream schema may have changed."
            )
        out: list[PackProbe] = []
        for i, row in enumerate(reader):
            goal = (row.get("Goal") or "").strip()
            if not goal:
                continue
            ptype = (row.get("Type") or "uncategorized").strip()
            out.append(
                PackProbe(
                    id=f"jailbreakbench:{i}",
                    prompt=goal,
                    goal=goal,
                    category=f"jailbreakbench:{ptype}",
                    severity="high",
                    source="jailbreakbench",
                )
            )
            if limit is not None and len(out) >= limit:
                break
        return out
