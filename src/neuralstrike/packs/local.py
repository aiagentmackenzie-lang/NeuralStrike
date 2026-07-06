"""Local probe dataset import — ``--import-probes <file.json>``.

A local pack is an operator-supplied JSON file of probes. It skips the
``--accept-license`` gate because the operator already holds the data
(and is responsible for its licensing). Like the network packs, a local
pack has **no expected-token oracle**: verdicts come from ``--judge``
(DECIDE) or are honestly Inconclusive — never fabricated.

Local pack JSON schema (one of)::

    [
      {"id": "p1", "prompt": "...", "goal": "...", "category": "x",
       "severity": "high"}
    ]

or a wrapper::

    {"probes": [ ... ], "name": "my-local-pack"}
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from neuralstrike.packs.base import Pack, PackProbe, register_pack

__all__ = ["LocalPack", "load_local_pack_file"]


@register_pack
class LocalPack(Pack):
    """A pack sourced from a local operator-supplied JSON file.

    Unlike the network packs, ``requires_accept_license`` is False: the
    operator already holds the data. Construct with ``path=`` before
    calling :meth:`probes`.
    """

    name = "local"
    license_url = ""
    requires_accept_license = False

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path is not None else None

    def probes(
        self,
        *,
        accept_license: bool = False,
        fetcher: Callable[[str], str] | None = None,
        limit: int | None = None,
    ) -> list[PackProbe]:
        if self.path is None:
            raise ValueError("LocalPack requires a path; construct with path=...")
        raw = self.path.read_text(encoding="utf-8")
        return self._parse(raw, limit=limit)

    def _parse(self, raw: str, *, limit: int | None = None) -> list[PackProbe]:
        data: Any = json.loads(raw)
        if isinstance(data, dict) and "probes" in data:
            entries = data["probes"]
        elif isinstance(data, list):
            entries = data
        else:
            raise ValueError(
                "local pack JSON must be a list of probes or an object with a "
                f"'probes' key; got top-level {type(data).__name__}"
            )
        out: list[PackProbe] = []
        for i, entry in enumerate(entries):
            if not isinstance(entry, dict):
                continue
            prompt = str(entry.get("prompt") or "").strip()
            if not prompt:
                continue
            out.append(
                PackProbe(
                    id=str(entry.get("id") or f"local-{i}"),
                    prompt=prompt,
                    goal=str(entry.get("goal") or prompt),
                    category=str(entry.get("category") or "uncategorized"),
                    severity=str(entry.get("severity") or "high"),
                    source="local",
                )
            )
            if limit is not None and len(out) >= limit:
                break
        return out


def load_local_pack_file(path: str | Path) -> tuple[LocalPack, list[PackProbe]]:
    """Convenience: build a LocalPack from ``path`` and return (pack, probes)."""
    pack = LocalPack(path=path)
    return pack, pack.probes()
