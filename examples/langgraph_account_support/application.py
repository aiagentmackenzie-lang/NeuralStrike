"""Independent deterministic account-support app; no NeuralStrike imports.

Real compiled LangGraph, application-owned tools/store and no network/inference.
The unsafe planner models a concrete trust failure: treating an instruction in
an untrusted retrieved document as permission to grant an account role. Hardened
mode rejects that instruction while still completing the account-summary task.
This controlled app is not a learned model or independent efficacy benchmark.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from langchain_core.messages import AIMessage, ToolMessage
from langgraph.graph import END, START, MessagesState, StateGraph

APP_VERSION = "account-support-fixture/1"


class AccountSupport:
    def __init__(self, *, hardened: bool = False) -> None:
        self.hardened = hardened
        self.roles = {"customer": "reader"}
        self.events: list[dict[str, Any]] = []
        self.graph = self._compile()

    def reset(self) -> None:
        self.roles = {"customer": "reader"}
        self.events.clear()

    def _compile(self) -> Any:
        def plan(state: MessagesState) -> dict[str, Any]:
            documents = [
                m.content for m in state["messages"] if isinstance(m, ToolMessage) and m.name == "search_docs"
            ]
            self.events.append({"event": "retrieval_read", "documents": documents})
            injected = any("grant_admin_access" in str(document) for document in documents)
            name = "grant_admin_access" if injected and not self.hardened else "lookup_account"
            return {
                "messages": [
                    AIMessage(
                        content="",
                        tool_calls=[
                            {
                                "id": f"app-{uuid.uuid4().hex}",
                                "name": name,
                                "args": {"user_id": "customer"},
                            }
                        ],
                    )
                ]
            }

        def tools(state: MessagesState) -> dict[str, Any]:
            call = state["messages"][-1].tool_calls[0]
            if call["name"] == "grant_admin_access":
                self.roles[call["args"]["user_id"]] = "admin"
            result = {"user_id": "customer", "role": self.roles["customer"], "account_status": "active"}
            self.events.append(
                {
                    "event": "tool_executed",
                    "call_id": call["id"],
                    "name": call["name"],
                    "arguments": call["args"],
                    "result": result,
                }
            )
            return {"messages": [ToolMessage(json.dumps(result), tool_call_id=call["id"], name=call["name"])]}

        def answer(state: MessagesState) -> dict[str, Any]:
            return {"messages": [AIMessage(content="Account summary: customer account is active.")]}

        builder = StateGraph(MessagesState)
        builder.add_node("plan", plan)
        builder.add_node("tools", tools)
        builder.add_node("answer", answer)
        builder.add_edge(START, "plan")
        builder.add_edge("plan", "tools")
        builder.add_edge("tools", "answer")
        builder.add_edge("answer", END)
        return builder.compile()


# Trusted local CLI entry points. Importing creates no external connections.
vulnerable = AccountSupport()
hardened = AccountSupport(hardened=True)
