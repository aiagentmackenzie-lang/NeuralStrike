"""Bind the write receipt where the tool is invoked, not where the record is stored.

v6 verified receipts at the store boundary, but the store had to *ask* the runtime for
them, so the verifier held a channel to the issuer. That is the compromise v6 recorded:
a receipt requested by the same component that verifies it cannot be strictly better than
the code asking for it. This module is the dispatcher that removes the channel.

Concretely:

* the store is built with **no authority at all** under this policy - it can neither mint
  nor request a receipt, so its only input is a receipt somebody else bound;
* the receipt is bound to the exact key and record value at dispatch, before the native
  ``upsert_memory`` tool runs;
* an unattested write returns a typed refusal as the tool *result*, so the model is told
  and the graph continues - unlike the store-boundary policy, where a refusal terminates
  the run;
* the store still verifies as defence in depth, so a dispatcher bug cannot smuggle a pass.

No native source is modified. ``memory_agent.tools.upsert_memory`` is rebound at runtime,
the same pattern this harness already uses for ``utils.load_chat_model``; ``functools.wraps``
keeps the signature, annotations and docstring the model-facing tool schema is generated
from, and a scripted check asserts the generated schema is unchanged.

What this still does not prove: the dispatcher is *ours*, the runtime issuing receipts is
still simulated, and the receipt still proves a key was held rather than that a human
approved anything.
"""

from __future__ import annotations

import functools
import time
import uuid
from collections.abc import Callable, Mapping
from typing import Any

from examples.agentdojo_banking.collect import atomic
from examples.memory_agent.profile import write_is_authorized
from examples.memory_agent.provenance import (
    PRINCIPAL_FIXTURE,
    PRINCIPAL_SESSION,
    AttestationAuthority,
    principal_for_write,
    turn_digest,
)


class BindingStore:
    """Store proxy that attaches the dispatch-issued receipt to the write it was bound for.

    The receipt is bound to one ``(namespace, key, value)``. If the native tool writes
    anything else, the store's content digest and binding checks refuse it - the proxy does
    not need to be trusted for that.
    """

    def __init__(self, store: Any, receipt: Mapping[str, Any]) -> None:
        self._store = store
        self._receipt = receipt

    @property
    def receipt(self) -> Mapping[str, Any]:
        """The receipt this proxy binds. Journalled for review, and checked by the matrix."""
        return self._receipt

    def __getattr__(self, name: str) -> Any:
        return getattr(self._store, name)

    async def aput(self, namespace: Any, key: str, value: Any, *args: Any, **kwargs: Any) -> Any:
        return await self._store.aput(namespace, key, value, *args, attestation=self._receipt, **kwargs)


class WriteDispatcher:
    """The authenticated turn handler's write path: decides, attests, then calls the tool."""

    def __init__(
        self,
        authority: AttestationAuthority,
        document: dict[str, Any],
        journal: Any,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.authority = authority
        self.document = document
        self.journal = journal
        self.clock = clock
        self.phase = "setup"
        self.turn = ""
        # Declared by the harness setup path; only ever a fixture principal or the untrusted one.
        self.pending_principal = PRINCIPAL_FIXTURE
        self.native: Callable[..., Any] | None = None

    def begin(self, phase: str, text: str) -> None:
        self.phase = phase
        self.turn = text

    def principal_for(self, content: str) -> str:
        if self.phase == "setup":
            return self.pending_principal
        return principal_for_write(attested=write_is_authorized(content, self.turn))

    def refuse(self, *, key: str, principal: str, namespace: Any) -> str:
        """Journal the refusal and return it as the tool result. Never a false success."""
        self.document["refused_writes"].append(
            {
                "key": key,
                "phase": self.phase,
                "reason": "principal_has_no_write_authority",
                "principal": principal,
                "receipt_sha256": None,
                "namespace": list(namespace),
                "boundary": "dispatch",
            }
        )
        atomic(self.journal, self.document)
        return (
            f"REFUSED: memory {key} was not stored. The write is not attested: "
            f"{principal} holds no write authority over this namespace. Nothing was saved; "
            f"do not report this as stored."
        )

    async def write(
        self,
        *,
        content: str,
        context: str,
        memory_id: uuid.UUID | None,
        user_id: str,
        store: Any,
    ) -> str:
        key = str(memory_id or uuid.uuid4())
        namespace = ("memories", user_id)
        value = {"content": content, "context": context}
        principal = self.principal_for(content)
        receipt = self.authority.issue(
            principal,
            namespace,
            key,
            value,
            turn_sha256=turn_digest(self.turn) if principal == PRINCIPAL_SESSION and self.turn else None,
        )
        if receipt is None:
            return self.refuse(key=key, principal=principal, namespace=namespace)
        if self.native is None:  # pragma: no cover - install() always sets it
            raise RuntimeError("dispatcher installed without a native tool")
        await self.native(
            content=content,
            context=context,
            memory_id=uuid.UUID(key),
            user_id=user_id,
            store=BindingStore(store, receipt),
        )
        return f"Stored memory {key}"


def install(module: Any, dispatcher: WriteDispatcher) -> Any:
    """Rebind ``module.upsert_memory`` to the dispatcher. Returns the original tool.

    ``functools.wraps`` preserves the signature, annotations and docstring the model-facing
    tool schema is generated from, so the model sees the same tool it saw before.
    """
    native = module.upsert_memory
    dispatcher.native = native

    @functools.wraps(native)
    async def dispatched(  # type: ignore[no-untyped-def]
        content, context, *, memory_id=None, user_id, store
    ):
        return await dispatcher.write(
            content=content,
            context=context,
            memory_id=memory_id,
            user_id=user_id,
            store=store,
        )

    module.upsert_memory = dispatched
    return native


__all__ = ["BindingStore", "WriteDispatcher", "install"]
