"""Task-local provider controls; never mutate a shared adapter between trials."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass

SEED_DERIVATION = "blake2b-63bit-v2"


@dataclass(frozen=True)
class TrialControls:
    seed: int
    temperature: float


_controls: ContextVar[TrialControls | None] = ContextVar("neuralstrike_trial_controls", default=None)


def current_trial_controls() -> TrialControls | None:
    return _controls.get()


@contextmanager
def trial_controls(seed: int, temperature: float) -> Iterator[None]:
    token = _controls.set(TrialControls(seed, temperature))
    try:
        yield
    finally:
        _controls.reset(token)
