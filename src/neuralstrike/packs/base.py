"""Benchmark pack imports — HarmBench, JailbreakBench, CyberSecEval, local.

A *pack* is an external benchmark dataset imported into NeuralStrike so a
run can measure a SUT against an established, peer-reviewed probe set
rather than only NeuralStrike's bundled corpus.

The honesty contract (Phase-3 exit gate, bullet 3):

- **Packs ship no expected-token oracle.** A HarmBench / JailbreakBench /
  CyberSecEval probe is a (prompt, goal) pair with no planted canary and
  no deterministic success criterion. The verdict therefore comes from
  the advisory Judge (DECIDE role) — or, with no Judge configured, every
  probe is honestly **Inconclusive** (a coverage gap). NeuralStrike never
  fabricates a Resisted/Succeeded verdict for a pack probe it cannot
  deterministically prove.
- **No data is bundled.** Pack datasets are licensed and large; bundling
  them would be a licensing and supply-chain hazard (the tool whose pitch
  is ASI04 supply-chain safety must practice what it preaches). Packs are
  fetched on demand behind ``--accept-license``; the operator opts in. A
  local dataset can be imported with ``--import-probes <file.json>`` and
  skips the license gate (the operator already holds the data).

The :class:`Pack` ABC is transport-agnostic: it takes an injectable
``fetcher`` (default: httpx GET) so tests inject a local-file fetcher and
never hit the network.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "PACKS",
    "Pack",
    "PackProbe",
    "get_pack",
    "list_packs",
    "register_pack",
]


@dataclass(frozen=True)
class PackProbe:
    """One probe from an imported benchmark pack.

    There is **no expected-token oracle** here — only the prompt + the
    prohibited goal. The verdict comes from the Judge (DECIDE) or is
    Inconclusive; never fabricated.

    ``source`` is provenance (e.g. ``"harmbench:standard"``) so a report
    can cite where a probe originated.
    """

    id: str
    prompt: str
    goal: str
    category: str = "uncategorized"
    severity: str = "high"
    source: str = ""


class Pack(ABC):
    """A benchmark dataset imported on demand behind ``--accept-license``.

    Subclasses declare ``name``, ``license_url``, ``requires_accept_license``
    and implement :meth:`probes`, which materializes the
    :class:`PackProbe` list. ``probes`` takes an injectable ``fetcher``
    (default httpx GET) so tests never hit the network.
    """

    name: str = ""
    license_url: str = ""
    requires_accept_license: bool = True

    @abstractmethod
    def probes(
        self,
        *,
        accept_license: bool = False,
        fetcher: Callable[[str], str] | None = None,
        limit: int | None = None,
    ) -> list[PackProbe]:
        """Materialize the pack's probes.

        ``accept_license`` must be ``True`` (and the pack's license
        acknowledged) before a network fetch is attempted. Without it, a
        pack that requires a license must refuse (raise) unless the
        caller supplied a non-network ``fetcher`` (tests / local cache).
        """
        raise NotImplementedError


_PACKS: dict[str, type[Pack]] = {}


def register_pack(cls: type[Pack]) -> type[Pack]:
    """Class decorator: register a :class:`Pack` subclass by its ``name``."""
    instance_name = getattr(cls, "name", "")
    if not instance_name:
        raise RuntimeError(f"Pack subclass {cls.__name__} has no 'name'")
    _PACKS[instance_name] = cls
    return cls


def list_packs() -> list[str]:
    """The registered pack names (sorted for deterministic CLI display)."""
    return sorted(_PACKS)


def get_pack(name: str) -> Pack:
    """Instantiate the named pack. Raises ``KeyError`` for an unknown pack."""
    try:
        cls = _PACKS[name]
    except KeyError as exc:
        raise KeyError(
            f"unknown pack {name!r}; registered packs: {list_packs()}"
        ) from exc
    return cls()


# Public alias: the registry is ``_PACKS`` (private); ``PACKS`` is the
# exported handle. Distinct names so a caller cannot mutate the registry
# via the public alias.
PACKS: dict[str, type[Pack]] = _PACKS


# A fetcher maps a URL -> raw text. The default uses httpx (lazy import so
# the [mcp]/httpx extra is not required just to import this module). Tests
# inject a fetcher that reads a local tmp file.
def default_fetcher(url: str) -> str:
    import httpx

    resp = httpx.get(url, timeout=30.0, follow_redirects=True)
    resp.raise_for_status()
    return resp.text


@dataclass(frozen=True)
class PackRunResult:
    """Aggregate result of a pack run: per-probe verdicts + the ScoreCard."""

    pack: str
    trials: tuple[Any, ...] = field(default_factory=tuple)
