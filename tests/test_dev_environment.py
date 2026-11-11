"""Contracts for the development environment and the single description of the gate.

Why this exists: on 2026-11-11 the suite passed locally and failed twice in CI on a test that
was correct in substance, because `.venv` and CI resolved different versions from the same
unbounded range. A green local run was not a gate. Three things are asserted here so that
cannot recur silently:

1. the gate has exactly one description (`scripts/ci_gate.sh`), and no workflow inlines a
   different one;
2. the local environment script installs the same pinned lock the gating CI job installs;
3. the lock's pin for the dependency that actually drifted satisfies `pyproject.toml`, so the
   two cannot disagree.

These are structure contracts, not behaviour contracts: they cannot prove the gate passes, only
that the thing called "the gate" is one thing.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / ".github/workflows/ci.yml"
GATE = ROOT / "scripts/ci_gate.sh"
DEV_ENV = ROOT / "scripts/dev_env.sh"
PYPROJECT = ROOT / "pyproject.toml"
DEV_LOCK = ROOT / "requirements-dev.txt"
README = ROOT / "README.md"

GATE_TOOLS = ("ruff", "mypy", "pytest")


def _steps(job: dict[str, object]) -> list[dict[str, object]]:
    steps = job.get("steps") or []
    assert isinstance(steps, list)
    return steps


def _run_bodies(workflow: Path) -> list[str]:
    data = yaml.safe_load(workflow.read_text())
    bodies: list[str] = []
    for job in (data.get("jobs") or {}).values():
        for step in _steps(job):
            run = step.get("run")
            if isinstance(run, str):
                bodies.append(run)
    return bodies


def test_no_workflow_inlines_a_gate_tool() -> None:
    """The gate is one file. A workflow that calls ruff/mypy/pytest directly is a second copy."""
    offenders: list[str] = []
    for workflow in sorted((ROOT / ".github/workflows").glob("*.yml")):
        for body in _run_bodies(workflow):
            for tool in GATE_TOOLS:
                if re.search(rf"(?<![\w-]){tool}(?![\w-])", body):
                    offenders.append(f"{workflow.name}: {body.strip().splitlines()[0]}")
    assert not offenders, (
        "gate tools must be invoked through scripts/ci_gate.sh, not inlined in a workflow: "
        f"{offenders}"
    )


def test_every_gating_job_runs_the_shared_script() -> None:
    data = yaml.safe_load(CI.read_text())
    jobs = data["jobs"]
    assert "quality" in jobs and "supply-chain" in jobs
    for job_name in ("quality", "supply-chain"):
        bodies = [step.get("run", "") for step in _steps(jobs[job_name])]
        assert any("scripts/ci_gate.sh" in str(body) for body in bodies), (
            f"job {job_name} does not run scripts/ci_gate.sh, so its gate is not the shared one"
        )


def test_the_locked_install_is_the_one_used_by_the_gating_job() -> None:
    """`dev_env.sh` and the supply-chain job must issue the same install commands."""
    data = yaml.safe_load(CI.read_text())
    supply_chain = _steps(data["jobs"]["supply-chain"])
    install = next(
        str(step["run"]) for step in supply_chain if "requirements-dev.txt" in str(step.get("run", ""))
    )
    script = DEV_ENV.read_text()

    for required in (
        "--require-hashes -r requirements-dev.txt",
        "--no-deps -e .",
        "install --upgrade pip",
    ):
        assert required in install, f"the CI install step no longer contains {required!r}"
        assert required in script, f"scripts/dev_env.sh no longer contains {required!r}"

    # The unbounded editable install is the thing that drifted; it must not be the documented
    # path. Comments may name it (this file explains why it was removed), executable lines may not.
    executable = "\n".join(
        line for line in script.splitlines() if not line.lstrip().startswith("#")
    )
    assert 'install -e ".[dev,mcp]"' not in executable


def test_dev_env_runs_the_shared_gate_after_installing() -> None:
    script = DEV_ENV.read_text()
    assert "scripts/ci_gate.sh" in script, "dev_env.sh must hand off to the shared gate"
    assert "--no-gate" in script, "a contributor needs a way to install without re-running the gate"


def test_dev_env_refuses_a_non_312_interpreter() -> None:
    """The lock is compiled for 3.12; a different interpreter resolves different wheels."""
    script = DEV_ENV.read_text()
    assert "sys.version_info[:2] != (3, 12)" in script, (
        "scripts/dev_env.sh must fail closed on an interpreter the lock was not compiled for"
    )


def test_lock_pin_satisfies_the_declared_constraint() -> None:
    """The pin that ended the drift must agree between pyproject.toml and the dev lock."""
    declared = re.search(r'"typer(==|>=)([0-9][^",]*)', PYPROJECT.read_text())
    assert declared is not None, "typer must be declared in pyproject.toml"
    if declared.group(1) != "==":
        pytest.fail(
            "typer must carry an exact pin: an unbounded range is what let local and CI resolve "
            f"different versions (found >= {declared.group(2)})"
        )
    pinned = re.search(r"^typer==([^\s\\]+)", DEV_LOCK.read_text(), re.MULTILINE)
    assert pinned is not None, "requirements-dev.txt must pin typer"
    assert pinned.group(1) == declared.group(2), (
        f"pyproject.toml pins typer=={declared.group(2)} but the dev lock installs "
        f"{pinned.group(1)}"
    )


def test_contributor_docs_point_at_the_script() -> None:
    """A script nobody is told about is not a documented environment."""
    readme = README.read_text()
    assert "scripts/dev_env.sh" in readme, "README must document the locked environment script"
    assert "scripts/ci_gate.sh" in readme, "README must document the shared gate script"


@pytest.mark.parametrize("script", [GATE, DEV_ENV])
def test_scripts_are_executable_shell(script: Path) -> None:
    assert script.is_file()
    assert script.stat().st_mode & 0o111, f"{script.name} is not executable"
    result = subprocess.run(["bash", "-n", str(script)], check=False, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_gate_script_runs_the_documented_commands() -> None:
    body = GATE.read_text()
    assert "-m ruff check src tests" in body
    assert "-m mypy src" in body
    assert "-m pytest --cov=neuralstrike" in body
    assert "--cov-fail-under=85" in body, "the coverage floor the README states must be enforced"
