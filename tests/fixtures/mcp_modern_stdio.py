"""Independent stdlib-only MCP 2026 fixture: no SDK or NeuralStrike imports."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

VERSION = "2026-07-28"


def response(request, mode="valid"):
    meta = request.get("params", {}).get("_meta", {})
    assert meta.get("io.modelcontextprotocol/protocolVersion") == VERSION
    assert "io.modelcontextprotocol/clientCapabilities" in meta
    assert "io.modelcontextprotocol/clientInfo" in meta
    method = request["method"]
    if method == "server/discover":
        result = {
            "supportedVersions": ["2025-06-18"] if mode == "wrong-version" else [VERSION],
            "capabilities": {"tools": {}},
            "_meta": {
                "io.modelcontextprotocol/serverInfo": {"name": "independent-stdlib-mcp", "version": "1.0"}
            },
        }
    elif method == "tools/list":
        result = {
            "tools": [
                {
                    "name": "read_account",
                    "description": "Read a synthetic account.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"id": {"type": "string"}},
                        "required": ["id"],
                    },
                }
            ]
        }
        if mode == "two-tools":
            result["tools"].append({**result["tools"][0], "name": "read_status"})
        if mode == "private-descriptor":
            result["tools"][0]["name"] = os.environ["SELECTED_PRIVATE_VALUE"]
            result["tools"][0]["inputSchema"]["properties"]["id"]["x-mcp-header"] = "Invalid Header"
        if mode == "invalid-header":
            result["tools"][0]["inputSchema"]["properties"]["id"]["x-mcp-header"] = "Invalid Header"
        if mode == "unsafe-schema":
            result["tools"][0]["inputSchema"]["properties"]["id"]["pattern"] = ".*"
        if mode == "pagination-loop":
            result["nextCursor"] = "same-cursor"
    elif method == "tools/call":
        if mode == "input-required":
            result = {"resultType": "input_required", "requestState": "do-not-retry"}
        else:
            result = {
                "content": [{"type": "text", "text": "synthetic account"}],
                "isError": mode == "tool-error",
            }
    else:
        raise AssertionError(f"unexpected method: {method}")
    result.setdefault("resultType", "complete")
    if method in {"server/discover", "tools/list"}:
        result.update(ttlMs=0, cacheScope="private")
    return {"jsonrpc": "2.0", "id": request["id"], "result": result}


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "valid"
    if os.environ.get("FIXTURE_PID"):
        Path(os.environ["FIXTURE_PID"]).write_text(str(os.getpid()))
    if mode == "child":
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        Path(os.environ["FIXTURE_CHILD_PID"]).write_text(str(child.pid))
    for line in sys.stdin:
        request = json.loads(line)
        if os.environ.get("FIXTURE_EVENTS"):
            with open(os.environ["FIXTURE_EVENTS"], "a") as stream:
                stream.write(json.dumps(request) + "\n")
        if mode == "timeout":
            time.sleep(30)
        if mode == "oversize":
            print("x" * 32768, flush=True)
        elif mode == "malformed":
            print("{broken", flush=True)
        else:
            print(json.dumps(response(request, mode)), flush=True)


if __name__ == "__main__":
    main()
