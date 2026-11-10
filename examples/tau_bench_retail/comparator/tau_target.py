"""PyRIT ``PromptTarget`` adapter over the comparator episode primitive.

Optional tooling. PyRIT is **not** a NeuralStrike dependency: this module is importable only
in an environment where PyRIT was installed deliberately (see
``docs/implementation/TAU_BENCH_COMPARATOR_PROTOCOL.md``), and nothing in ``src/`` imports it.

The adapter converts PyRIT's conversation into an attacker **turn script** and runs one
episode of the pinned target per send. Ground truth is the state predicate recorded on the
episode, never a PyRIT scorer and never the model's text.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from examples.tau_bench_retail.comparator.episode import episode
from examples.tau_bench_retail.profile import MAX_STEPS, MODEL, SEED, USER_MAX_TURNS
from pyrit.models import Message, MessagePiece, construct_response_from_request
from pyrit.prompt_target import PromptTarget


class TauBenchRetailTarget(PromptTarget):
    """One PyRIT prompt (or conversation) drives one independent tau-bench episode."""

    def __init__(
        self,
        *,
        source: Path,
        policy: str,
        model: str = MODEL,
        seed: int = SEED,
        max_num_steps: int = MAX_STEPS,
        max_requests_per_minute: int | None = None,
    ) -> None:
        if policy not in {"unfiltered", "bound"}:
            raise ValueError(f"unknown policy {policy!r}")
        super().__init__(model_name=model, endpoint="tau-bench-retail", underlying_model=model,
                         max_requests_per_minute=max_requests_per_minute)
        self._source = Path(source)
        self._policy = policy
        self._seed = seed
        self._max_num_steps = max_num_steps
        self.episodes: list[dict[str, Any]] = []
        # PyRIT does not guarantee that a custom target sees prior turns, so the adapter
        # accumulates the attacker's script per conversation itself. Each send therefore
        # re-runs the episode from scratch with one more turn: independent, and quadratic in
        # turns, which is why the script is capped at the declared USER_MAX_TURNS.
        self._history: dict[str, list[str]] = {}

    def _build_identifier(self) -> Any:
        return self._create_identifier(
            params={"policy": self._policy, "seed": self._seed, "max_num_steps": self._max_num_steps}
        )

    @staticmethod
    def _turns(normalized_conversation: list[Message]) -> list[str]:
        return [
            message.get_piece().converted_value
            for message in normalized_conversation
            if message.get_piece().role == "user"
        ]

    async def _send_prompt_to_target_async(
        self, *, normalized_conversation: list[Message]
    ) -> list[Message]:
        request: MessagePiece = normalized_conversation[-1].get_piece()
        turns = self._turns(normalized_conversation)
        if not turns:
            turns = [request.converted_value]
        history = self._history.setdefault(request.conversation_id, [])
        for turn in turns:
            if turn not in history:
                history.append(turn)
        if len(history) > USER_MAX_TURNS:
            raise ValueError(
                f"attacker script exceeds the declared {USER_MAX_TURNS} user turns; refusing"
            )
        turns = tuple(history)
        result = await asyncio.to_thread(
            episode, turns, self._policy, self._source,
            self._model_name, self._seed, self._max_num_steps,
        )
        self.episodes.append(result)
        text = result["assistant_text"] or "(no assistant text)"
        return [construct_response_from_request(request=request, response_text_pieces=[text])]
