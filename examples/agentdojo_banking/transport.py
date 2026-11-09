"""Finite, exact-origin model transport used by the local AgentDojo experiment."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx


class CapturingTransport(httpx.BaseTransport):
    def __init__(
        self,
        document: dict[str, Any],
        save: Callable[[], None],
        seed: int,
        max_output_tokens: int | None = None,
    ) -> None:
        self.document, self.save, self.seed = document, save, seed
        # None preserves the frozen 768-token behaviour of the earlier profiles.
        # A profile that declares its own finite output budget must also override
        # max_completion_tokens, or the SDK-supplied value silently wins.
        if max_output_tokens is not None and max_output_tokens <= 0:
            raise ValueError("max_output_tokens must be positive")
        self.max_output_tokens = max_output_tokens
        self.failed = False
        self.inner = httpx.HTTPTransport(retries=0, trust_env=False)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if self.failed:
            raise RuntimeError("previous model dispatch failed; retry/continuation prohibited")
        try:
            return self._handle_request(request)
        except BaseException:
            self.failed = True
            raise

    def _handle_request(self, request: httpx.Request) -> httpx.Response:
        if request.method != "POST" or str(request.url) != "http://127.0.0.1:11434/v1/chat/completions":
            raise RuntimeError("unsupported inference URL")
        if len(self.document["exchanges"]) >= 5:
            raise RuntimeError("model request budget exhausted")
        body = json.loads(request.content)
        if body.get("model") != "qwen3.5:2b":
            raise RuntimeError("only the pinned local model is authorized")
        if self.max_output_tokens is None:
            body.update(seed=self.seed, max_tokens=768)
        else:
            body.update(
                seed=self.seed,
                max_tokens=self.max_output_tokens,
                max_completion_tokens=self.max_output_tokens,
            )
        exchange: dict[str, Any] = {"request": body, "complete": False}
        self.document["exchanges"].append(exchange)
        self.save()
        request = httpx.Request(
            "POST", request.url, headers=request.headers, content=json.dumps(body).encode()
        )
        # New body length must replace the SDK's original Content-Length.
        request.headers["Content-Length"] = str(len(request.content))
        response = self.inner.handle_request(request)
        chunks = bytearray()
        try:
            for chunk in response.iter_bytes():
                chunks.extend(chunk)
                if len(chunks) > 1024 * 1024:
                    raise RuntimeError("model response size limit")
        finally:
            response.close()
        data = json.loads(chunks)
        choice = (data.get("choices") or [{}])[0]
        exchange.update(
            response=data,
            status=response.status_code,
            finish_reason=choice.get("finish_reason"),
            output_tokens=(data.get("usage") or {}).get("completion_tokens"),
            complete=True,
        )
        self.save()
        if response.status_code != 200:
            raise RuntimeError("local model HTTP error")
        if choice.get("finish_reason") not in {"stop", "tool_calls"}:
            raise RuntimeError("model generation incomplete")
        return httpx.Response(response.status_code, json=data, request=request)

    def close(self) -> None:
        self.inner.close()
