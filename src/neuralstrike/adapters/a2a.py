"""A2A (Agent2Agent) adapter — HTTP JSON-RPC + Agent Card (Phase 1, D4).

Per Decision D4, Phase 1 ships **HTTP JSON-RPC + Agent Card fetch +
security-scheme-aware requests**. Full RFC 7515 JWS signature verification,
RFC 8785 JCS canonicalization, and delegation-chain attacks land in
Phase 5. This adapter tests the *deployed* surface today.

What it does:

- Fetches the Agent Card from ``/.well-known/agent-card.json``.
- Reads the card's declared ``securitySchemes`` and the ``security``
  requirement list, and applies the matching credentials the operator
  supplied (API key / HTTP Bearer / OAuth 2.0 / OpenID Connect / mTLS).
- Sends an authenticated JSON-RPC 2.0 ``message/send`` to the agent's URL.
- Returns the agent's response as a :class:`SutResponse` so oracles score it.

It does **not** (Phase 5): verify JWS on the Agent Card, verify per-request
HTTP Message Signatures (RFC 9421), or test delegation-chain abuse.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from typing import Any

import httpx

from neuralstrike.adapters.base import Message, TargetAdapter, ToolSchema
from neuralstrike.evaluation.verdict import SutResponse, ToolCall
from neuralstrike.utils.logging import get_logger

__all__ = ["A2AAdapter", "A2AError", "AgentCard", "SecurityScheme"]

logger = get_logger("neuralstrike.adapters.a2a")


class A2AError(Exception):
    """Raised when an A2A call fails (transport, auth, or JSON-RPC error)."""


@dataclass(frozen=True)
class SecurityScheme:
    """One declared A2A security scheme (subset of OpenAPI securityScheme)."""

    scheme_id: str
    kind: str  # "apiKey" | "http" | "oauth2" | "openIdConnect" | "mutualTLS"
    in_: str = "header"  # for apiKey: header|query|cookie
    name: str = "Authorization"  # header/param name
    bearer_format: str = "JWT"  # for http bearer


@dataclass(frozen=True)
class AgentCard:
    """Parsed A2A Agent Card (the deployed identity-at-rest surface)."""

    url: str
    name: str = ""
    description: str = ""
    version: str = "1.0"
    skills: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    security_schemes: dict[str, SecurityScheme] = field(default_factory=dict)
    security: tuple[tuple[str, ...], ...] = field(default_factory=tuple)
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, base_url: str | None = None) -> AgentCard:
        schemes_raw = data.get("securitySchemes", {}) or {}
        schemes: dict[str, SecurityScheme] = {}
        for sid, s in schemes_raw.items():
            if not isinstance(s, dict):
                continue
            kind = s.get("type", "http")
            schemes[sid] = SecurityScheme(
                scheme_id=sid,
                kind=kind,
                in_=s.get("in", "header"),
                name=s.get("name", "Authorization"),
                bearer_format=str(s.get("bearerFormat") or s.get("scheme") or "bearer"),
            )
        security = tuple(tuple(req) for req in (data.get("security", []) or []) if isinstance(req, list))
        url = data.get("url") or (base_url or "")
        return cls(
            url=url,
            name=str(data.get("name", "")),
            description=str(data.get("description", "")),
            version=str(data.get("version", "1.0")),
            skills=tuple(data.get("skills", []) or []),
            security_schemes=schemes,
            security=security,
            raw=data,
        )


class A2AAdapter(TargetAdapter):
    """Agent2Agent JSON-RPC 2.0 client (HTTP + Agent Card, security-aware)."""

    name = "a2a"
    tier = "text"

    def __init__(
        self,
        base_url: str,
        *,
        api_key: str | None = None,
        bearer_token: str | None = None,
        client_cert: tuple[str, str] | None = None,  # (cert_path, key_path) for mTLS
        timeout: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not base_url.startswith(("http://", "https://")):
            raise ValueError(f"A2A base_url must be http(s)://, got {base_url!r}")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.bearer_token = bearer_token
        self.client_cert = client_cert
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None
        self._card: AgentCard | None = None
        self._transport = transport

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.timeout, cert=self.client_cert, transport=self._transport
            )
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def fetch_agent_card(self) -> AgentCard:
        """Fetch and parse the Agent Card from ``/.well-known/agent-card.json``."""
        url = f"{self.base_url}/.well-known/agent-card.json"
        try:
            resp = await self.client.get(url)
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise A2AError(f"could not fetch agent card at {url}: {exc}") from exc
        if not isinstance(data, dict):
            raise A2AError(f"agent card is not a JSON object: {data!r}")
        self._card = AgentCard.from_dict(data, base_url=self.base_url)
        return self._card

    @property
    def card(self) -> AgentCard | None:
        return self._card

    def _auth_headers(self) -> dict[str, str]:
        """Build request headers from the card's declared security requirements."""
        headers: dict[str, str] = {}
        if self._card is None:
            # No card fetched yet — apply best-effort bearer if provided.
            if self.bearer_token:
                headers["Authorization"] = f"Bearer {self.bearer_token}"
            elif self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            return headers
        for requirement in self._card.security:
            for sid in requirement:
                scheme = self._card.security_schemes.get(sid)
                if scheme is None:
                    continue
                headers.update(self._creds_for(scheme))
                if headers:
                    return headers
        # No security declared -> unauthenticated.
        return headers

    def _creds_for(self, scheme: SecurityScheme) -> dict[str, str]:
        token = self.bearer_token or self.api_key
        if scheme.kind == "apiKey" and self.api_key:
            return {scheme.name: self.api_key}
        # http / oauth2 / openIdConnect all surface as a Bearer header.
        # mTLS uses the client cert on the transport, not a header.
        if scheme.kind in ("http", "oauth2", "openIdConnect") and token:
            return {scheme.name: f"Bearer {token}"}
        return {}

    async def _rpc(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if self._card is None:
            await self.fetch_agent_card()
        assert self._card is not None
        target = self._card.url or self.base_url
        payload = {"jsonrpc": "2.0", "id": str(uuid.uuid4()), "method": method, "params": params}
        headers = self._auth_headers()
        try:
            resp = await self.client.post(target, json=payload, headers=headers)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise A2AError(f"A2A transport error on {method}: {exc}") from exc
        try:
            body = resp.json()
        except ValueError as exc:
            raise A2AError(f"A2A non-JSON response: {exc}") from exc
        if isinstance(body, dict) and "error" in body:
            raise A2AError(f"A2A JSON-RPC error on {method}: {body['error']}")
        return body.get("result", body) if isinstance(body, dict) else {}

    async def send_message(self, text: str, *, role: str = "user") -> dict[str, Any]:
        """A2A ``message/send`` with a fresh message id."""
        msg = {
            "messageId": f"msg-{uuid.uuid4()}",
            "role": role,
            "parts": [{"kind": "text", "text": text}],
            "kind": "message",
        }
        return await self._rpc("message/send", {"message": msg, "configuration": {}})

    async def query(
        self,
        prompt: str,
        *,
        system_prompt: str | None = None,
        tools: tuple[ToolSchema, ...] = (),
        history: tuple[Message, ...] = (),
        canary_tools: tuple[Any, ...] = (),
        trace: Any = None,
    ) -> SutResponse:
        _ = tools, canary_tools, trace, system_prompt, history  # A2A carries text only in Phase 1.
        try:
            result = await self.send_message(prompt)
        except A2AError as exc:
            return SutResponse(text="", error=str(exc))
        text, tool_calls = _extract_a2a_result(result)
        return SutResponse(text=text, tool_calls=tuple(tool_calls))


def _extract_a2a_result(result: Any) -> tuple[str, list[ToolCall]]:
    """Pull the agent's text + any tool_calls out of a ``message/send`` result."""
    if not isinstance(result, dict):
        return "", []
    # A2A result is a Task or Message; be liberal in what we accept.
    text_parts: list[str] = []
    tool_calls: list[ToolCall] = []
    artifacts = result.get("artifacts") or []
    for art in artifacts:
        if isinstance(art, dict):
            for part in art.get("parts", []) or []:
                if isinstance(part, dict) and part.get("kind") == "text":
                    text_parts.append(str(part.get("text", "")))
    # Some servers return the message inline.
    if not text_parts:
        msg = result.get("result") or result
        if isinstance(msg, dict):
            for part in msg.get("parts", []) or []:
                if isinstance(part, dict) and part.get("kind") == "text":
                    text_parts.append(str(part.get("text", "")))
    if not text_parts:
        text_parts.append(json.dumps(result)[:500])
    return "\n".join(text_parts), tool_calls
