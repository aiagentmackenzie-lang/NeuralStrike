"""CyberSecEval pack — Meta's cybersecurity-attitudes benchmark, on demand.

Meta's CyberSecEval (Bhatt et al., 2024) probes whether a model aids
cyber adversaries (insecure coding, cyberattack help, etc.).
NeuralStrike imports it on demand; **no data is bundled**.

The default dataset URL points at the insecure-coding prompts JSON in the
PurpleLabs CyberSecEval mirror. The parser handles the documented
schema (a list of objects with ``prompt``/``id``/``category`` fields, or a
wrapper object with a ``prompts`` key). If upstream changes the schema,
the parser raises a clear error.

Verdicts: CyberSecEval probes have **no expected-token oracle** ->
``--judge`` decides, or every probe is honestly Inconclusive.
"""

from __future__ import annotations

import json
from collections.abc import Callable

from neuralstrike.packs.base import Pack, PackProbe, default_fetcher, register_pack

__all__ = ["CyberSecEvalPack"]


@register_pack
class CyberSecEvalPack(Pack):
    """CyberSecEval insecure-coding prompts, imported on demand."""

    name = "cyberseceval"
    license_url = "https://github.com/meta-llama/PurpleLlama/blob/main/LICENSE"
    requires_accept_license = True

    dataset_url = (
        "https://raw.githubusercontent.com/meta-llama/PurpleLlama/"
        "main/CybersecurityEval/insecure_coding_prompts/insecure_coding_prompts.json"
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
        data = json.loads(raw)
        # Two documented shapes: a bare list, or {"prompts": [ ... ]}.
        if isinstance(data, dict) and "prompts" in data:
            entries = data["prompts"]
        elif isinstance(data, list):
            entries = data
        else:
            raise ValueError(
                "CyberSecEval JSON schema mismatch (expected a list or an object "
                f"with a 'prompts' key); got top-level {type(data).__name__}. "
                "Upstream schema may have changed."
            )
        out: list[PackProbe] = []
        for i, entry in enumerate(entries):
            if not isinstance(entry, dict):
                continue
            prompt = (entry.get("prompt") or entry.get("text") or "").strip()
            if not prompt:
                continue
            pid = str(entry.get("id") or entry.get("name") or f"cse-{i}")
            category = str(entry.get("category") or entry.get("language") or "insecure-coding")
            out.append(
                PackProbe(
                    id=f"cyberseceval:{pid}",
                    prompt=prompt,
                    goal=prompt,
                    category=f"cyberseceval:{category}",
                    severity="high",
                    source="cyberseceval",
                )
            )
            if limit is not None and len(out) >= limit:
                break
        return out
