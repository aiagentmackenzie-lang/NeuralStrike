"""Phase 4 command spine: one assessment name, one compare command, honest aliases.

The gate's criterion is that a single assessment surface, a single comparison surface and
a single replay surface exist, and that a legacy name still works. These contracts hold
the two failure modes that matter: the alias drifting away from the implementation, and a
comparison that cannot be made being reported as a pass.
"""

from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from typer.testing import CliRunner

from neuralstrike.corpus import load_corpus_dir
from neuralstrike.evaluation.assessment import AssessmentRecorder
from neuralstrike.evaluation.runner import RunMeta, RunReport
from neuralstrike.evaluation.verdict import EvidenceFidelity, TrialResult, Verdict
from neuralstrike.main import app

RUNNER = CliRunner()
SEED = 7


def text(result) -> str:
    """The CLI's message, flattened: either stream, no panel borders, no wrapping.

    Two presentation details are not behaviour: a CLI error lands on stdout or
    stderr depending on the click/typer version, and a Rich panel wraps to the
    detected width (CI is 80 columns, a developer's terminal is not). Flattening
    both means the assertion is about the message, not the machine it ran on.
    """
    raw = result.output + (getattr(result, "stderr", "") or "")
    return " ".join(re.sub(r"[│╭╮╰╯─]", " ", raw).split())


def commands() -> dict[str, object]:
    names = {}
    for info in app.registered_commands:
        if info.name is not None:
            names[info.name] = info.callback
        elif info.callback is not None:
            names[info.callback.__name__.replace("_", "-")] = info.callback
    return names


def test_the_spine_commands_exist() -> None:
    registered = commands()
    for name in ("assess", "compare", "replay"):
        assert name in registered, name


def test_the_legacy_corpus_name_is_the_same_callback_as_assess() -> None:
    """An alias that calls a second implementation is a second engine."""
    registered = commands()
    assert registered["assess"] is registered["corpus"]


def test_corpus_prints_a_deprecation_notice_and_assess_does_not() -> None:
    legacy = RUNNER.invoke(app, ["corpus", "--adapter", "not-an-adapter"])
    assert "deprecated" in text(legacy)
    assert "neuralstrike assess" in text(legacy)
    current = RUNNER.invoke(app, ["assess", "--adapter", "not-an-adapter"])
    assert "deprecated" not in text(current)


def bundle(
    root,
    *,
    verdicts: dict[str, Verdict] | None = None,
    target: str = "http://fixture",
    seed: int = SEED,
    omit: tuple[str, ...] = (),
):
    """Commit a real assessment bundle from declared verdicts (no network)."""
    scenarios = load_corpus_dir()[:2]
    verdicts = verdicts or {}
    recorder = AssessmentRecorder(
        root,
        scenarios=scenarios,
        base_seed=seed,
        trials=1,
        adapter="openai",
        target=target,
        fail_on="vuln",
    )
    for scenario in scenarios:
        if scenario.id in omit:
            continue
        trial = TrialResult(
            0,
            seed,
            0.0,
            verdicts.get(scenario.id, Verdict.RESISTED),
            EvidenceFidelity.VERBAL,
            scenario_id=scenario.id,
        )
        meta = RunMeta(f"run-{scenario.id}", scenario.id, seed, 1, 0.0, 0.7, "2026-11-11T00:00:00Z")
        recorder.add(RunReport(meta, trials=(trial,)))
    recorder.finish()
    return recorder.path, [scenario.id for scenario in scenarios]


def compare(baseline, current, *extra):
    return RUNNER.invoke(app, ["compare", str(baseline), str(current), *extra])


def test_unchanged_assessment_passes(tmp_path) -> None:
    first, _ = bundle(tmp_path / "a")
    second, _ = bundle(tmp_path / "b")
    result = compare(first, second)
    assert result.exit_code == 0, text(result)
    assert "pass" in text(result).lower()


def test_a_newly_succeeded_scenario_is_a_regression(tmp_path) -> None:
    first, ids = bundle(tmp_path / "a")
    second, _ = bundle(tmp_path / "b", verdicts={ids[0]: Verdict.SUCCEEDED})
    result = compare(first, second)
    assert result.exit_code == 4, text(result)
    assert "regression" in text(result).lower()
    # Under --fail-on vuln the same change is a vulnerability, not a regression.
    assert compare(first, second, "--fail-on", "vuln").exit_code == 1


def test_a_fix_requires_complete_current_evidence(tmp_path) -> None:
    first_id = load_corpus_dir()[0].id
    first, _ = bundle(tmp_path / "a", verdicts={first_id: Verdict.SUCCEEDED})
    fixed, _ = bundle(tmp_path / "b")
    result = compare(first, fixed)
    assert result.exit_code == 0, text(result)
    assert "1 fixed" in text(result)
    # The same scenario omitted from the current assessment is not a fix.
    omitted, _ = bundle(tmp_path / "c", omit=(first_id,))
    withheld = compare(first, omitted)
    assert withheld.exit_code == 3, text(withheld)
    assert "not_comparable" in text(withheld)


def test_an_inconclusive_current_scenario_is_not_a_fix(tmp_path) -> None:
    first_id = load_corpus_dir()[0].id
    first, _ = bundle(tmp_path / "a", verdicts={first_id: Verdict.SUCCEEDED})
    second, _ = bundle(tmp_path / "b", verdicts={first_id: Verdict.INCONCLUSIVE})
    result = compare(first, second)
    assert result.exit_code == 3, text(result)
    assert "not_comparable" in text(result)
    assert "fixed" not in text(result).lower()


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        ({"seed": SEED + 1}, "seed differs"),
        ({"target": "http://other-target"}, "target differs"),
    ],
)
def test_a_different_run_is_refused_rather_than_scored(tmp_path, change, expected) -> None:
    first, _ = bundle(tmp_path / "a")
    second, _ = bundle(tmp_path / "b", **change)
    result = compare(first, second)
    assert result.exit_code == 3, text(result)
    assert expected in text(result)


def test_a_run_directory_is_not_an_assessment_bundle(tmp_path) -> None:
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "manifest.json").write_text(json.dumps({"kind": "neuralstrike-run"}))
    result = compare(plain, plain)
    assert result.exit_code == 3, text(result)
    assert "not a committed assessment bundle" in text(result)


def test_the_comparison_record_binds_both_bundles(tmp_path) -> None:
    first, _ = bundle(tmp_path / "a")
    second, _ = bundle(tmp_path / "b")
    out = tmp_path / "record.json"
    result = compare(first, second, "--out", str(out))
    assert result.exit_code == 0, text(result)
    document = json.loads(out.read_text())
    assert document["target_calls"] is False
    assert document["comparison"]["decision"] == "pass"
    for key in ("baseline_manifest_sha256", "current_manifest_sha256"):
        assert len(document[key]) == 64


def test_scan_authenticates_with_an_environment_bearer(tmp_path, monkeypatch) -> None:
    """The live-target guide's known gap: `scan` could not send a credential at all."""
    seen: list[str | None] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            self.rfile.read(int(self.headers["Content-Length"]))
            seen.append(self.headers.get("Authorization"))
            body = json.dumps({"choices": [{"message": {"content": "denied"}}]}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_port}"
    monkeypatch.setenv("PHASE4_SYNTHETIC_KEY", "synthetic-phase4-token")
    try:
        result = RUNNER.invoke(
            app,
            [
                "scan",
                "--adapter",
                "openai",
                "--url",
                url,
                "--model",
                "fixture",
                "--target-api-key-env",
                "PHASE4_SYNTHETIC_KEY",
                "--fail-on",
                "never",
                "--run-dir",
                str(tmp_path / "runs"),
            ],
        )
    finally:
        server.shutdown()
        server.server_close()
    assert result.exit_code == 0, text(result)
    assert seen == ["Bearer synthetic-phase4-token"]


def test_scan_refuses_a_missing_credential_before_any_request(tmp_path, monkeypatch) -> None:
    """A missing credential must fail closed, before the target is contacted."""
    seen: list[str | None] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            seen.append(self.headers.get("Authorization"))
            self.send_response(500)
            self.end_headers()

        def log_message(self, *args) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.delenv("PHASE4_ABSENT_KEY", raising=False)
    try:
        result = RUNNER.invoke(
            app,
            [
                "scan",
                "--adapter",
                "openai",
                "--url",
                f"http://127.0.0.1:{server.server_port}",
                "--model",
                "fixture",
                "--target-api-key-env",
                "PHASE4_ABSENT_KEY",
                "--run-dir",
                str(tmp_path / "runs"),
            ],
        )
    finally:
        server.shutdown()
        server.server_close()
    assert result.exit_code == 2, text(result)
    assert seen == [], "the request was sent before the credential was resolved"


def test_a_credential_flag_on_a_non_openai_adapter_is_refused(tmp_path) -> None:
    # Exit 2 is the contract; the wording of a usage error is Typer's rendering layer,
    # which is exactly the part that differs between environments, so it is not pinned.
    result = RUNNER.invoke(
        app,
        [
            "scan",
            "--adapter",
            "a2a",
            "--url",
            "http://127.0.0.1:9",
            "--target-api-key-env",
            "ANY_KEY",
            "--run-dir",
            str(tmp_path / "runs"),
        ],
    )
    assert result.exit_code == 2, text(result)


def test_the_comparison_record_cannot_be_written_into_a_bundle(tmp_path) -> None:
    """A record written inside the evidence it describes would mutate the evidence."""
    first, _ = bundle(tmp_path / "a")
    second, _ = bundle(tmp_path / "b")
    for destination in (first / "report.json", second / "runs"):
        result = compare(first, second, "--out", str(destination))
        assert result.exit_code == 3, text(result)
        assert "outside both bundles" in text(result)
