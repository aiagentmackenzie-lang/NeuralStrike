"""Task-local live observations retained when a trial is interrupted.

Only in-process trusted callbacks are registered here; evidence never loads code.
"""

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
from dataclasses import dataclass, replace

from neuralstrike.evaluation.verdict import SutResponse, TrialResult


@dataclass
class TrialCheckpoint:
    response: Callable[[], SutResponse] | None = None
    score: Callable[[SutResponse], TrialResult] | None = None

    def interrupted(self, error: str) -> TrialResult | None:
        if self.score is None:
            return None
        response = deepcopy(self.response()) if self.response else SutResponse(text="")
        return replace(self.score(replace(response, error=error)), error=error)


_current: ContextVar[TrialCheckpoint | None] = ContextVar("trial_checkpoint", default=None)


@contextmanager
def trial_checkpoint(checkpoint: TrialCheckpoint) -> Iterator[None]:
    token = _current.set(checkpoint)
    try:
        yield
    finally:
        _current.reset(token)


def capture_response(snapshot: Callable[[], SutResponse]) -> None:
    checkpoint = _current.get()
    if checkpoint is not None:
        checkpoint.response = snapshot


def capture_scoring(score: Callable[[SutResponse], TrialResult]) -> None:
    checkpoint = _current.get()
    if checkpoint is not None:
        checkpoint.score = score
