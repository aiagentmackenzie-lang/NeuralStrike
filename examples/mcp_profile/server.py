"""Controlled official-SDK MCP server. No NeuralStrike imports or cloud calls.

python -m examples.mcp_profile.server --transport stdio
MCP_FIXTURE_BEARER=synthetic python -m examples.mcp_profile.server --transport http --port 8765
"""

from __future__ import annotations

import argparse
import hmac
import os
from typing import Any

import uvicorn
from mcp.server import MCPServer

server = MCPServer("account-capability-fixture", version="1.0.0", log_level="ERROR")


@server.tool()
def read_account(id: str) -> str:
    """Read a synthetic account; never modify permissions or contact a provider."""
    return f"Synthetic account {id}: active, reader role."


def http_app() -> Any:
    app = server.streamable_http_app(json_response=True, stateless_http=True)
    token = os.environ.get("MCP_FIXTURE_BEARER")
    if not token:
        raise ValueError("HTTP fixture requires explicit MCP_FIXTURE_BEARER")

    async def authenticated(scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] == "http":
            headers = dict(scope["headers"])
            if not hmac.compare_digest(headers.get(b"authorization", b""), f"Bearer {token}".encode()):
                body = b'{"error":"unauthorized"}'
                await send(
                    {
                        "type": "http.response.start",
                        "status": 401,
                        "headers": [(b"content-type", b"application/json")],
                    }
                )
                await send({"type": "http.response.body", "body": body})
                return
        await app(scope, receive, send)

    return authenticated


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--transport", choices=("stdio", "http"), default="stdio")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    if args.transport == "stdio":
        server.run()
    else:
        uvicorn.run(http_app(), host="127.0.0.1", port=args.port, log_level="error")


if __name__ == "__main__":
    main()
