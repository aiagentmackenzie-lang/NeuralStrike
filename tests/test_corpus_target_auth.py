"""CLI authentication against a separate loopback HTTP implementation."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from typer.testing import CliRunner

from neuralstrike.main import app


@pytest.mark.parametrize("command", ["corpus", "doctor"])
@pytest.mark.parametrize("credential", ["synthetic-phase2-token", "wrong-token"])
def test_env_auth_against_local_endpoint(tmp_path, monkeypatch, credential, command):
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            calls.append((self.path, self.headers.get("Authorization")))
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            assert request["model"] == "independent-http-fixture"
            authenticated = self.headers.get("Authorization") == "Bearer synthetic-phase2-token"
            message = {"content": "denied"}
            if command == "doctor" and len(calls) == 1:
                message = {
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "probe-1",
                            "type": "function",
                            "function": {
                                "name": "neuralstrike_preflight",
                                "arguments": '{"value":"probe"}',
                            },
                        }
                    ],
                }
            body = json.dumps({"choices": [{"message": message}]}).encode()
            self.send_response(200 if authenticated else 401)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    monkeypatch.setenv("PHASE2_SYNTHETIC_KEY", credential)
    try:
        args = [
            command,
            "--url",
            f"http://127.0.0.1:{server.server_port}",
            "--model",
            "independent-http-fixture",
            "--target-api-key-env",
            "PHASE2_SYNTHETIC_KEY",
            "--max-response-bytes",
            "2048",
        ]
        if command == "corpus":
            args += [
                "--adapter",
                "openai",
                "--limit",
                "1",
                "--fail-on",
                "vuln",
                "--format",
                "json",
                "--out",
                str(tmp_path / "report"),
                "--run-dir",
                str(tmp_path / "runs"),
            ]
        else:
            args += ["--out", str(tmp_path / "preflight.json")]
        result = CliRunner().invoke(app, args)
        if command == "corpus":
            # Authentication alone cannot satisfy the corpus evidence oracle.
            assert result.exit_code == 3, result.output
            report = json.loads((tmp_path / "report.json").read_text())
            assert report["overall"]["inconclusive"] == 1
            exchanges = []
            for file in (tmp_path / "runs").rglob("*.json"):
                data = json.loads(file.read_text())
                if isinstance(data, dict) and "exchanges" in data:
                    exchanges.extend(data["exchanges"])
            assert exchanges
            assert all(
                e["status_code"] == (200 if credential == "synthetic-phase2-token" else 401)
                for e in exchanges
            )
        else:
            assert result.exit_code == (0 if credential == "synthetic-phase2-token" else 3), result.output
            receipt = json.loads((tmp_path / "preflight.json").read_text())
            assert receipt["security_assessment"] is False
            assert receipt["ready"] is (credential == "synthetic-phase2-token")
        count = 2 if command == "doctor" and credential == "synthetic-phase2-token" else 1
        assert calls == [("/v1/chat/completions", f"Bearer {credential}")] * count
        for file in tmp_path.rglob("*.json"):
            assert credential not in file.read_text()
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def test_missing_auth_reference_fails_before_creating_evidence(tmp_path, monkeypatch):
    monkeypatch.delenv("PHASE2_MISSING_KEY", raising=False)
    result = CliRunner().invoke(
        app,
        [
            "corpus",
            "--adapter",
            "openai",
            "--url",
            "http://127.0.0.1:1",
            "--model",
            "fixture",
            "--target-api-key-env",
            "PHASE2_MISSING_KEY",
            "--run-dir",
            str(tmp_path / "runs"),
        ],
    )
    assert result.exit_code != 0
    assert "credential environment variable is missing or empty" in result.output
    assert not (tmp_path / "runs").exists()
