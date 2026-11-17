"""Contract: the release workflow must be able to publish the GitHub+GHCR variant alone.

Measured on 2026-11-17 (run `43995731534`): dispatching with `publish: true` ran the **PyPI** step
first, which failed with `invalid-publisher` — no trusted publisher is registered for this
repository — and every GHCR/release step after it was skipped. The single `publish` input conflated
"publish the GitHub release and the container image" with "publish to PyPI", so Variant A (GitHub +
GHCR only, the variant P4-2's criterion actually names) was **not expressible**. A dry run could
never have found this: the PyPI step is skipped when `publish` is false.

The scope must be two decisions, because they have different prerequisites: an image needs
`packages: write` and a `GITHUB_TOKEN`; PyPI needs a project, a trusted publisher and an account
this project does not have.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
RELEASE = ROOT / ".github/workflows/release.yml"
PLAN = ROOT / "docs/implementation/PHASE4_PLAN.md"


def workflow() -> dict[str, object]:
    return yaml.safe_load(RELEASE.read_text())


def inputs() -> dict[str, object]:
    trigger = workflow()[True] if True in workflow() else workflow().get("on")
    assert isinstance(trigger, dict)
    dispatch = trigger["workflow_dispatch"]
    assert isinstance(dispatch, dict)
    found = dispatch.get("inputs")
    assert isinstance(found, dict)
    return found


def steps() -> list[dict[str, object]]:
    jobs = workflow()["jobs"]
    assert isinstance(jobs, dict) and len(jobs) == 1
    found = next(iter(jobs.values()))["steps"]
    assert isinstance(found, list)
    return found


def step_named(fragment: str) -> dict[str, object]:
    for step in steps():
        if fragment in str(step.get("name", "")):
            return step
    raise AssertionError(f"no step named like {fragment!r}; the workflow changed shape")


def test_pypi_is_its_own_decision() -> None:
    pypi = inputs().get("publish_pypi")
    assert isinstance(pypi, dict), (
        "PyPI publishing must be a separate input: one flag for three destinations means the "
        "GitHub+GHCR variant cannot be dispatched without also publishing to PyPI"
    )
    assert pypi.get("default") is False, "PyPI must be off unless it is explicitly asked for"
    assert pypi.get("type") == "boolean"


def test_the_pypi_step_does_not_run_on_the_image_flag_alone() -> None:
    condition = str(step_named("Publish to PyPI").get("if", ""))
    assert "inputs.publish_pypi" in condition, (
        "the PyPI step is still gated on the image/GitHub flag, which is how run 43995731534 "
        "failed at the first publishing step"
    )


def test_the_image_and_release_do_not_depend_on_pypi() -> None:
    for fragment in ("Log in to GHCR", "Bind the release into one manifest", "Create GitHub release"):
        condition = str(step_named(fragment).get("if", ""))
        assert "inputs.publish" in condition, f"{fragment!r} must still be gated on inputs.publish"
        assert "publish_pypi" not in condition, (
            f"{fragment!r} must not require PyPI: choosing PyPI is not a prerequisite for a "
            "GitHub release or a container image"
        )


def test_the_plan_records_the_measured_failure_and_the_split() -> None:
    plan = PLAN.read_text()
    flat = " ".join(plan.split())
    assert "43995731534" in flat, "the run that failed at the PyPI step must be cited"
    assert "invalid-publisher" in flat, "the measured failure reason must be recorded"
    assert "not expressible" in flat or "could not be expressed" in flat, (
        "the plan must state that Variant A was not dispatchable as built"
    )
    assert "publish_pypi" in flat, "the plan must name the input that now separates the decisions"
