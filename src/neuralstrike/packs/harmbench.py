"""HarmBench pack — on-demand import behind ``--accept-license``.

HarmBench (Mazeika et al., 2024) is a standardized harmful-behavior
benchmark. NeuralStrike imports it on demand; it ships **no** bundled
data (licensing + supply-chain hygiene — the tool whose pitch is ASI04
supply-chain safety does not vendor third-party datasets).

The default dataset URL is the upstream behaviors CSV. The parser handles
the documented HarmBench schema (``id, category, functional_category,
semantic_category, behavior``). If the upstream schema changes, the
parser raises a clear error rather than silently producing wrong probes.

Verdicts: HarmBench probes have **no expected-token oracle**, so a run
requires ``--judge`` (the Judge decides, DECIDE role) or every probe is
honestly Inconclusive — never a fabricated Resisted/Succeeded.
"""

from __future__ import annotations

import csv
import io
from collections.abc import Callable

from neuralstrike.packs.base import Pack, PackProbe, default_fetcher, register_pack

__all__ = ["HarmBenchPack"]


@register_pack
class HarmBenchPack(Pack):
    """HarmBench behaviors dataset, imported on demand."""

    name = "harmbench"
    license_url = "https://github.com/centerforaisafety/HarmBench/blob/main/LICENSE"
    requires_accept_license = True

    # Upstream behaviors CSV (text, all categories). Schema documented at
    # write time (2026-07); if upstream changes, the parser raises.
    dataset_url = (
        "https://raw.githubusercontent.com/centerforaisafety/HarmBench/"
        "main/data/behavior_datasets/harmbench_behaviors_text_all.csv"
    )

    def probes(
        self,
        *,
        accept_license: bool = False,
        fetcher: Callable[[str], str] | None = None,
        limit: int | None = None,
    ) -> list[PackProbe]:
        # A network fetch (default fetcher) requires --accept-license. An
        # injected fetcher (tests / local cache) bypasses the gate because
        # the operator already holds the data.
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
        if not reader.fieldnames or "behavior" not in reader.fieldnames:
            raise ValueError(
                f"HarmBench CSV schema mismatch (expected a 'behavior' column); "
                f"got fieldnames={reader.fieldnames!r}. Upstream schema may have changed."
            )
        out: list[PackProbe] = []
        for row in reader:
            behavior = (row.get("behavior") or "").strip()
            if not behavior:
                continue
            pid = (row.get("id") or f"hb-{len(out)}").strip()
            category = (row.get("category") or "uncategorized").strip()
            out.append(
                PackProbe(
                    id=f"harmbench:{pid}",
                    prompt=behavior,
                    goal=behavior,
                    category=f"harmbench:{category}",
                    severity="high",
                    source="harmbench",
                )
            )
            if limit is not None and len(out) >= limit:
                break
        return out
