"""Runtime setup — model reachability check + fallback-chain resolution.

Decision D1's latent bug: ``config.py`` and ``.env.example`` defaulted the
Judge to ``llama3.1``, which is **not installed** on this host. A fresh-clone
run would silently hang / error instead of failing closed. This module is
the fix: before a run starts, verify the configured Attacker and Judge
models are reachable; if the Judge model is not, walk the fallback chain;
if none are reachable, abort with a clear error (never fail open).

This is **fail-closed by design**: a security tool that cannot reach its
integrity anchor (the Judge) must not silently produce un-judged verdicts.
"""

from __future__ import annotations

from dataclasses import dataclass

from neuralstrike.core.exceptions import ConfigError, LLMError
from neuralstrike.core.llm_manager import LLMManager
from neuralstrike.utils.logging import get_logger

__all__ = ["ResolvedModels", "resolve_models"]

logger = get_logger("neuralstrike.core.runtime")


@dataclass(frozen=True)
class ResolvedModels:
    """The effective Attacker + Judge models after reachability resolution."""

    attacker_model: str
    judge_model: str
    judge_fell_back: bool
    available: tuple[str, ...]


async def resolve_models(
    llm: LLMManager,
    *,
    attacker_model: str,
    judge_model: str,
    judge_fallbacks: tuple[str, ...] = (),
) -> ResolvedModels:
    """Resolve the effective Judge model via the fallback chain; fail closed.

    The Attacker must be reachable (it is the run's engine). The Judge is
    allowed to fall back through ``judge_fallbacks``; if **none** of the
    Judge model + fallbacks are reachable, abort with :class:`ConfigError`
    — never silently run with a dead Judge.
    """
    try:
        installed = await llm.list_local_models()
    except LLMError as exc:
        raise ConfigError(
            f"cannot reach Ollama at the configured base URL to verify models "
            f"({exc.message}). Set NEURALSTRIKE_SKIP_REACHABILITY_CHECK=true only "
            f"if you accept an un-judged run."
        ) from exc

    installed_set = set(installed)

    if attacker_model not in installed_set:
        raise ConfigError(
            f"Attacker model {attacker_model!r} is not installed on this Ollama "
            f"({len(installed)} models available). Install it or set "
            f"NEURALSTRIKE_ATTACKER_MODEL to an installed model. "
            f"Run `neuralstrike judge-model-list` to see installed models."
        )

    # Judge: walk the chain. Fall back only to *reachable* models.
    chain = [judge_model, *judge_fallbacks]
    resolved_judge = next((m for m in chain if m in installed_set), None)
    if resolved_judge is None:
        raise ConfigError(
            f"Judge model {judge_model!r} and all fallbacks {judge_fallbacks!r} "
            f"are not installed on this Ollama. The Judge is the integrity anchor "
            f"of a run; refusing to run with no reachable Judge (fail-closed). "
            f"Run `neuralstrike judge-model-list` to see installed models."
        )
    fell_back = resolved_judge != judge_model
    if fell_back:
        logger.warning(
            "Judge model %s not reachable; falling back to %s.", judge_model, resolved_judge
        )

    return ResolvedModels(
        attacker_model=attacker_model,
        judge_model=resolved_judge,
        judge_fell_back=fell_back,
        available=tuple(sorted(installed_set)),
    )
