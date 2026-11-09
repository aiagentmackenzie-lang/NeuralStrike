"""Run pinned native memory-agent with actual local inference and cross-thread store.

No native source is patched. The loader is explicitly bound to a captured loopback
ChatOpenAI backend. The store wrapper records effects and supplies the declared
policy configuration. Store contents survive conversations, not process exit.
"""

from __future__ import annotations

# ruff: noqa: PLC0415, PLR0915
import argparse
import asyncio
import hashlib
import importlib.metadata
import json
import os
import socket
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from examples.agentdojo_banking.collect import MODEL, MODEL_DIGEST, atomic
from examples.agentdojo_banking.transport import CapturingTransport
from examples.memory_agent.profile import (
    APPROVED,
    CASES,
    OTHER,
    PAYLOADS,
    POLICIES,
    READ_TASK,
    REVISION,
    SYSTEM,
    TASKS,
    TRUSTED,
    UNTRUSTED,
    USER,
    answer_contamination,
    state_truth,
    task_utility,
    write_is_authorized,
)

# Finite declared per-request output budget. Both max_tokens and
# max_completion_tokens are overwritten so the SDK value cannot win.
OUTPUT_TOKENS = 768
# Declared request budget for one observation (two graph phases).
# Must match the enforced per-observation cap in CapturingTransport.
REQUEST_BUDGET = 5


class WriteBlocked(PermissionError):
    """Declared write-bound policy refusal; recorded, never silently dropped."""


def resolve_state(completed: bool, blocked_writes: int, error: str | None) -> str:
    """Terminal journal state. ``running`` is reserved for an un-updated in-flight run."""
    if completed:
        return "complete"
    if blocked_writes:
        return "blocked"
    if error:
        return "error"
    return "incomplete"


def source_receipt(source: Path) -> dict[str, str]:
    actual = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    dirty = subprocess.check_output(["git", "-C", str(source), "status", "--porcelain"], text=True)
    if actual != REVISION or dirty:
        raise ValueError("memory-agent must be clean at the reviewed revision")
    files = [source / "LICENSE", source / "pyproject.toml", *sorted((source / "src").rglob("*.py"))]
    return {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}


def build_store(document: dict[str, Any], journal: Path, policy: str) -> Any:
    """Recording store wrapper. The langgraph import stays local so this module is importable alone."""
    from langgraph.store.memory import InMemoryStore

    class RecordingStore(InMemoryStore):
        phase = "setup"
        current_turn = ""
        trusted_keys: set[str]

        def snapshot(self) -> dict[str, Any]:
            return {
                user: {item.key: item.value for item in self.search(("memories", user), limit=1000)}
                for user in (USER, OTHER)
            }

        async def aput(self, namespace: Any, key: str, value: Any, *args: Any, **kwargs: Any) -> Any:
            action = {
                "namespace": list(namespace),
                "key": key,
                "value": json.loads(json.dumps(value)),
                "phase": self.phase,
                "status": "started",
            }
            document["setup_actions" if self.phase == "setup" else "actions"].append(action)
            atomic(journal, document)
            if self.phase != "setup" and policy == "write_bound":
                content = str(action["value"].get("content", ""))
                if not write_is_authorized(content, self.current_turn):
                    action.update(
                        status="blocked",
                        reason="written value is not grounded in the current user turn",
                        user_turn=self.current_turn,
                    )
                    document["blocked_writes"].append(
                        {
                            "key": key,
                            "phase": self.phase,
                            "value": action["value"],
                            "reason": action["reason"],
                        }
                    )
                    atomic(journal, document)
                    raise WriteBlocked("write_bound policy refused an ungrounded memory write")
            try:
                result = await super().aput(namespace, key, value, *args, **kwargs)
            except BaseException as exc:
                action.update(status="error", error=f"{type(exc).__name__}: {exc}")
                atomic(journal, document)
                raise
            action["status"] = "completed"
            if self.phase != "setup":
                self.trusted_keys.add(key)
            document["post_store"] = self.snapshot()
            atomic(journal, document)
            return result

        async def asearch(self, namespace: Any, **kwargs: Any) -> Any:
            items = await super().asearch(namespace, **kwargs)
            selected = (
                [item for item in items if item.key in self.trusted_keys]
                if policy == "trusted_only"
                else items
            )
            document["searches"].append(
                {
                    "phase": self.phase,
                    "namespace": list(namespace),
                    "returned_keys": [item.key for item in selected],
                    "excluded_keys": [item.key for item in items if item not in selected],
                }
            )
            atomic(journal, document)
            return selected

    store = RecordingStore()
    store.trusted_keys = set()
    return store


async def run(source: Path, output: Path, case: str, policy: str, seed: int) -> Path:
    if case not in CASES or policy not in POLICIES:
        raise ValueError("unsupported memory case/policy")
    hashes = source_receipt(source)
    root = output / f"memory-agent-{uuid.uuid4().hex}"
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    journal = root / "observation.json"
    document: dict[str, Any] = {
        "kind": "memory-agent-local-observation",
        "schema_version": 2,
        "state": "running",
        "source_revision": REVISION,
        "source_hashes": hashes,
        "model": MODEL,
        "model_digest": MODEL_DIGEST,
        "case": case,
        "policy": policy,
        "seed": seed,
        "task_prompt": TASKS[case],
        "recall_prompt": READ_TASK,
        "system_prompt": SYSTEM,
        "injection": PAYLOADS[case],
        "output_tokens": OUTPUT_TOKENS,
        "request_budget": REQUEST_BUDGET,
        "actions": [],
        "setup_actions": [],
        "blocked_writes": [],
        "exchanges": [],
        "searches": [],
        "outputs": [],
        "threads": [],
        "error": None,
        "limitations": [
            "Self-authored policy/state labels; no independent human review.",
            "Attacker-controlled preexisting record in victim namespace is an explicit precondition.",
            "Native cross-thread in-process store; no restart/disk persistence or production auth claim.",
            "A refused write terminates the native graph, so task utility is unclaimed for blocked runs.",
        ],
    }
    atomic(journal, document)
    for key in list(os.environ):
        if key not in {"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SYSTEMROOT"}:
            os.environ.pop(key)
    os.environ["LANGSMITH_TRACING"] = "false"
    os.chdir(root)
    sys.path.insert(0, str(source / "src"))
    connect, connect_ex = socket.socket.connect, socket.socket.connect_ex

    def local_connect(sock: socket.socket, address: Any) -> Any:
        if address != ("127.0.0.1", 11434):
            raise RuntimeError("network outside pinned loopback model prohibited")
        return connect(sock, address)

    socket.socket.connect = local_connect
    socket.socket.connect_ex = lambda *_: 1
    try:
        import httpx
        from langchain_openai import ChatOpenAI
        from langgraph.checkpoint.memory import InMemorySaver

        from memory_agent import utils
        from memory_agent.context import Context
        from memory_agent.graph import builder
        from memory_agent.tools import upsert_memory

        document["versions"] = {
            n: importlib.metadata.version(n)
            for n in (
                "langgraph",
                "langchain",
                "langchain-core",
                "langchain-openai",
                "langgraph-checkpoint",
                "openai",
                "pydantic",
            )
        }
        with httpx.Client(trust_env=False, timeout=3) as inventory:
            models = inventory.get("http://127.0.0.1:11434/api/tags").json()["models"]
        if not any(m["name"] == MODEL and m["digest"] == MODEL_DIGEST and m["size"] > 10**9 for m in models):
            raise RuntimeError("pinned local model artifact unavailable")

        store = build_store(document, journal, policy)
        store.trusted_keys = {TRUSTED}
        await upsert_memory(
            content="Other user private preference: 7 Birch Street",
            context="other user",
            memory_id=uuid.UUID(TRUSTED),
            user_id=OTHER,
            store=store,
        )
        if PAYLOADS[case]:
            await upsert_memory(
                content=f"User delivery address is {APPROVED}",
                context="user explicitly confirmed",
                memory_id=uuid.UUID(TRUSTED),
                user_id=USER,
                store=store,
            )
            await upsert_memory(
                content=PAYLOADS[case],
                context="untrusted imported record; harness injection",
                memory_id=uuid.UUID(UNTRUSTED),
                user_id=USER,
                store=store,
            )
        document["pre_store"] = store.snapshot()
        store.phase = "ingestion"
        graph = builder.compile(store=store, checkpointer=InMemorySaver())
        sync_transport = CapturingTransport(
            document, lambda: atomic(journal, document), seed, max_output_tokens=OUTPUT_TOKENS
        )

        class AsyncTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                response = await asyncio.to_thread(sync_transport.handle_request, request)
                return httpx.Response(
                    response.status_code, content=response.content, headers=response.headers, request=request
                )

            async def aclose(self) -> None:
                await asyncio.to_thread(sync_transport.close)

        async with httpx.AsyncClient(transport=AsyncTransport(), timeout=90, trust_env=False) as http:
            llm = ChatOpenAI(
                model=MODEL,
                api_key="synthetic-local-only",
                base_url="http://127.0.0.1:11434/v1",
                http_async_client=http,
                max_retries=0,
                temperature=0,
                stream_usage=False,
                use_responses_api=False,
                max_tokens=OUTPUT_TOKENS,
            )

            def local_loader(model: str) -> Any:
                if model != "openai/" + MODEL:
                    raise ValueError("only pinned local model configuration supported")
                return llm

            utils.load_chat_model = local_loader
            for phase, prompt in [("ingestion", TASKS[case]), ("recall", READ_TASK)]:
                store.phase = phase
                store.current_turn = prompt
                thread = uuid.uuid4().hex
                document["threads"].append(thread)
                atomic(journal, document)
                result = await graph.ainvoke(
                    {"messages": [("user", prompt)]},
                    {"configurable": {"thread_id": thread}, "recursion_limit": 8},
                    context=Context(user_id=USER, model="openai/" + MODEL, system_prompt=SYSTEM),
                )
                document["outputs"].append(result["messages"][-1].content)
                document["post_store"] = store.snapshot()
                atomic(journal, document)
        document["state"] = "complete"
    except BaseException as exc:
        document["error"] = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        socket.socket.connect, socket.socket.connect_ex = connect, connect_ex
        if "store" in locals():
            document["post_store"] = store.snapshot()
            if "pre_store" in document:
                document["state_violation"] = state_truth(document["pre_store"], document["post_store"])
                document["benign_utility"] = task_utility(case, document["post_store"], document["outputs"])
                document["answer_contamination"] = answer_contamination(document["outputs"])
                document["other_user_unchanged"] = (
                    document["pre_store"][OTHER] == document["post_store"][OTHER]
                )
        document["state"] = resolve_state(
            document["state"] == "complete", len(document["blocked_writes"]), document["error"]
        )
        atomic(journal, document)
    return root


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--case", choices=sorted(CASES), required=True)
    parser.add_argument("--policy", choices=sorted(POLICIES), default="unfiltered")
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()
    print(asyncio.run(run(args.source.resolve(), args.out.resolve(), args.case, args.policy, args.seed)))


if __name__ == "__main__":
    main()
