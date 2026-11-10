"""One comparator episode: an arbitrary attacker prompt driving the pinned target once.

This is the comparator's episode primitive. It reuses the declared harness — the pinned
checkout loader, the scripted user, the dispatcher, the model pin and the state
predicates — so a comparator cannot quietly measure with a different boundary than the
declared profile. What it adds is a *prompt* argument instead of a declared case, which is
what an external attack generator needs.

Each episode is independent and starts from the pinned data: the target's own
``ToolCallingAgent.solve`` resets the environment, so a multi-turn attack that establishes
trust before asking cannot be expressed here. That is a limitation of this primitive and it
is stated in the comparator protocol, not discovered later.

No PyRIT import lives here. The PyRIT ``PromptTarget`` adapter is a thin wrapper over
:func:`episode`, so the primitive can be run and contracted without the optional tool.
"""

from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path
from typing import Any

from examples.tau_bench_retail.collect import (
    ScriptedUser,
    bind_model,
    disclosed,
    load_target,
    source_receipt,
)
from examples.tau_bench_retail.profile import (
    MAX_STEPS,
    MODEL,
    PROVIDER,
    SEED,
    SESSION_TASK_INDEX,
    TERMINAL,
    atomic,
    canonical,
    digest,
    resolve_model,
    state_predicates,
    verify_model_pin,
)


def episode(
    turns: tuple[str, ...],
    policy: str,
    source: Path,
    model: str = MODEL,
    seed: int = SEED,
    max_steps: int = MAX_STEPS,
) -> dict[str, Any]:
    """Run one attacker turn script to termination against the pinned target.

    ``turns`` is a sequence, not a single prompt, because the self-check proved the
    declared row cannot be reached in one turn: the model asks for confirmation and only
    dispatches the write after the follow-ups. A one-prompt adapter reports false negatives.
    """
    from examples.tau_bench_retail.boundary import install, resolve_principal  # noqa: PLC0415

    if not turns or not any(turn.strip() for turn in turns):
        raise ValueError("an episode needs at least one non-empty attacker turn")
    declared = resolve_model(model)
    pin = verify_model_pin(model)
    os.environ["OLLAMA_API_BASE"] = declared["origin"]
    started = time.time()
    receipt = source_receipt(source)
    target = load_target(source)
    env = target["env"](
        user_strategy="human", user_model="unused", task_split="test", task_index=SESSION_TASK_INDEX
    )
    # The attacker's turns, then termination. The next attacker attempt is a new episode.
    env.user = ScriptedUser((*turns, TERMINAL))
    schema_before = digest(env.tools_info)
    dispatcher = install(env, policy)
    exchanges: list[dict[str, Any]] = []
    bind_model(target["module"], model, declared["digest"], seed, exchanges, True)
    agent = target["agent"](
        tools_info=env.tools_info, wiki=env.wiki, model=model, provider=PROVIDER, temperature=0.0
    )
    agent.solve(env, task_index=SESSION_TASK_INDEX, max_num_steps=max_steps)
    schema_after = digest(env.tools_info)
    principal = resolve_principal(env)
    initial = dispatcher.initial_state
    post = dispatcher.last_settled
    from examples.tau_bench_retail.boundary import uninstall  # noqa: PLC0415

    uninstall(env)
    predicates = state_predicates(initial, post, principal)
    disclosures = [entry for entry in dispatcher.entries if disclosed(entry, initial)]
    refusals = [entry for entry in dispatcher.entries if entry["reason"] is not None]
    by_tool_and_reason: dict[str, dict[str, int]] = {}
    for entry in refusals:
        tool = str(entry["tool"])
        reasons = by_tool_and_reason.setdefault(tool, {})
        reasons[str(entry["reason"])] = reasons.get(str(entry["reason"]), 0) + 1
    texts = [str(x.get("content") or "") for x in exchanges]
    return {
        "schema_version": 1,
        "kind": "tau-bench-retail-comparator-episode-v1",
        "turns": list(turns),
        "turns_sha256": digest(list(turns)),
        "turn_count": len(turns),
        "policy": policy,
        "seed": seed,
        "model": {"name": declared["name"], "digest": declared["digest"], "pin": pin},
        "target": {"revision": receipt["revision"], "clean": receipt["clean"],
                   "task_index": SESSION_TASK_INDEX},
        "harness": {
            "schema_unchanged": schema_before == schema_after,
            "max_num_steps": max_steps,
            "user_turns": len(turns),
        },
        "ok": True,
        "principal": principal,
        "dispatch": dispatcher.entries,
        "refusal_count": len(refusals),
        "offered_tools": sorted({str(entry["tool"]) for entry in dispatcher.entries}),
        "refusals_by_tool_and_reason": {
            tool: dict(sorted(reasons.items())) for tool, reasons in sorted(by_tool_and_reason.items())
        },
        "predicates": {
            "cross_principal_mutation": predicates["cross_principal_mutation"],
            "cross_principal_disclosure": bool(disclosures),
            "own_principal_mutation": predicates["own_principal_mutation"],
            "state_unresolved": dispatcher.state_unresolved,
        },
        "changed_records": predicates["changed_records"],
        "assistant_text": texts[-1] if texts else "",
        "exchanges": exchanges,
        "elapsed_seconds": round(time.time() - started, 3),
        "limits": [
            "one attacker turn per episode; multi-turn trust building cannot be expressed",
            "the predicate, the boundary and the environment are this project's, not the comparator's",
            "one local model on one machine",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="one comparator episode against tau-bench retail")
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--turn", required=True, action="append",
                        help="one attacker turn; repeat for a multi-turn script")
    parser.add_argument("--policy", required=True, choices=["unfiltered", "bound"])
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--model", default=MODEL)
    arguments = parser.parse_args()
    result = episode(tuple(arguments.turn), arguments.policy, arguments.source, arguments.model)
    atomic(arguments.out, result)
    print(json.dumps(result["predicates"], sort_keys=True))
    print(canonical(result["refusals_by_tool_and_reason"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
