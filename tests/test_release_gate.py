"""Contract: a release may not build an artifact from a commit whose gate has not run.

NS-14 in the master plan named this as a release blocker: the quality gate lived only in `ci.yml`,
so `release.yml` could build, tag and publish a wheel and an image from *any* commit, green or red.
A gate that only runs on push is not a gate on the artifact you ship — the release path is the one
place where "it passed on some other commit" is not good enough.

Two things are asserted, because either one alone is satisfiable by a workflow that still ships
unverified bytes:

1. the release job executes `scripts/ci_gate.sh` — the same single description CI and contributors
   run, never an inlined copy of ruff/mypy/pytest (that is `test_dev_environment.py`'s rule);
2. it does so **before** the distribution is built and before any publishing step, and
   unconditionally — a gate behind `if:` is an optional gate.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
RELEASE = ROOT / ".github/workflows/release.yml"
GATE_SCRIPT = "scripts/ci_gate.sh"


def steps() -> list[dict[str, object]]:
    data = yaml.safe_load(RELEASE.read_text())
    jobs = data["jobs"]
    assert len(jobs) == 1, f"this contract understands a one-job release workflow, found {list(jobs)}"
    found = next(iter(jobs.values()))["steps"]
    assert isinstance(found, list)
    return found


def _run(step: dict[str, object]) -> str:
    run = step.get("run")
    return run if isinstance(run, str) else ""


def _index_of(predicate) -> int:
    for position, step in enumerate(steps()):
        if predicate(step, _run(step)):
            return position
    raise AssertionError("no step matched; the workflow changed shape and this contract is stale")


def test_the_release_job_runs_the_shared_gate() -> None:
    bodies = [_run(step) for step in steps()]
    gating = [body for body in bodies if GATE_SCRIPT in body]
    assert gating, f"release.yml never runs {GATE_SCRIPT}, so it can ship an ungated commit"


def test_the_gate_runs_before_anything_is_built_or_published() -> None:
    gate = _index_of(lambda step, run: GATE_SCRIPT in run)
    build = _index_of(lambda step, run: "python -m build" in run)
    assert gate < build, "the gate must run before the distribution is built"

    for marker in ("Publish to PyPI", "Create GitHub release", "Build (and optionally push)"):
        publish = _index_of(
            lambda step, run, marker=marker: str(step.get("name", "")).startswith(marker)
        )
        assert gate < publish, f"the gate must run before {marker!r}"


def test_the_gate_is_unconditional() -> None:
    """A gate behind `if:` is an optional gate, and this one is the reason to trust the artifact."""
    gating = [step for step in steps() if GATE_SCRIPT in _run(step)]
    assert gating, "no gate step to check"
    for step in gating:
        assert not step.get("if"), (
                "the release gate must not be conditional; publishing is already conditional on "
                "inputs.publish, and the gate is what makes that safe"
            )


def test_the_gate_runs_in_the_locked_environment() -> None:
    """The gate must run against the pins CI gates on, not an unpinned resolution."""
    gate = _index_of(lambda step, run: GATE_SCRIPT in run)
    locked = _index_of(lambda step, run: "requirements-dev.txt" in run)
    assert locked < gate, (
        "the pinned dev lock must be installed before the gate runs, so the release gate is the "
        "same environment as the gating CI job"
    )
