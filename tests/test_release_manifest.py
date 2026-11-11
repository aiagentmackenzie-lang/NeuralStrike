"""Contracts for the release binder (Phase 4 gate P4-2).

The manifest is the artifact that makes "version 1.0.0" mean one build. These tests are about
its refusals as much as its output: a binder that silently drops a missing artifact, accepts a
stale wheel or claims a signature would be worse than no manifest at all.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/release_manifest.py"
CI = ROOT / ".github/workflows/ci.yml"
RELEASE = ROOT / ".github/workflows/release.yml"


def load_binder():
    spec = importlib.util.spec_from_file_location("release_manifest", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["release_manifest"] = module
    spec.loader.exec_module(module)
    return module


binder = load_binder()


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def artifacts(tmp_path: Path) -> dict[str, Path]:
    wheel = tmp_path / "neuralstrike-1.0.0-py3-none-any.whl"
    sdist = tmp_path / "neuralstrike-1.0.0.tar.gz"
    sbom = tmp_path / "sbom.json"
    wheel.write_bytes(b"wheel bytes")
    sdist.write_bytes(b"sdist bytes")
    sbom.write_text(json.dumps({"bomFormat": "CycloneDX", "components": [{"name": "neuralstrike"}]}))
    return {"wheel": wheel, "sdist": sdist, "sbom": sbom}


def test_the_manifest_binds_digests_it_computed_itself(artifacts, tmp_path: Path) -> None:
    manifest = binder.bind(
        version="1.0.0",
        commit="a" * 40,
        tag="v1.0.0",
        wheel=artifacts["wheel"],
        sdist=artifacts["sdist"],
        sbom=artifacts["sbom"],
    )
    recorded = {entry["kind"]: entry for entry in manifest["artifacts"]}
    assert set(recorded) == {"wheel", "sdist", "sbom"}
    assert recorded["wheel"]["sha256"] == digest(artifacts["wheel"])
    assert recorded["sdist"]["sha256"] == digest(artifacts["sdist"])
    assert recorded["sbom"]["sha256"] == digest(artifacts["sbom"])
    assert manifest["version"] == "1.0.0"
    assert manifest["tag"] == "v1.0.0"
    assert manifest["source_commit"] == "a" * 40
    assert manifest["schema_version"] == binder.SCHEMA_VERSION


def test_the_manifest_never_claims_a_signature(artifacts) -> None:
    manifest = binder.bind(
        version="1.0.0",
        commit="a" * 40,
        wheel=artifacts["wheel"],
        sdist=artifacts["sdist"],
        sbom=artifacts["sbom"],
    )
    assert manifest["signed"] is False
    assert manifest["signatures"] == []
    assert "never the wheel or release assets" in manifest["signing_policy"]
    # And it may not be talked into one by a caller that supplies nothing.
    assert binder.bind(
        version="1.0.0",
        commit="a" * 40,
        wheel=artifacts["wheel"],
        sdist=artifacts["sdist"],
        sbom=artifacts["sbom"],
        signatures=None,
    )["signed"] is False


def test_a_stale_or_missing_artifact_is_refused(artifacts, tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="does not carry the declared version"):
        binder.bind(
            version="9.9.9",
            commit="a" * 40,
            wheel=artifacts["wheel"],
            sdist=artifacts["sdist"],
            sbom=artifacts["sbom"],
        )
    with pytest.raises(FileNotFoundError, match="missing"):
        binder.bind(
            version="1.0.0",
            commit="a" * 40,
            wheel=tmp_path / "neuralstrike-1.0.0-py3-none-any-absent.whl",
            sdist=artifacts["sdist"],
            sbom=artifacts["sbom"],
        )


def test_an_unrelated_sbom_is_refused(artifacts, tmp_path: Path) -> None:
    other = tmp_path / "other.json"
    other.write_text(json.dumps({"bomFormat": "CycloneDX", "components": [{"name": "something-else"}]}))
    with pytest.raises(ValueError, match="does not contain"):
        binder.bind(
            version="1.0.0",
            commit="a" * 40,
            wheel=artifacts["wheel"],
            sdist=artifacts["sdist"],
            sbom=other,
        )


def test_an_image_digest_must_be_a_digest_reference(artifacts) -> None:
    with pytest.raises(ValueError, match="not a digest reference"):
        binder.bind(
            version="1.0.0",
            commit="a" * 40,
            wheel=artifacts["wheel"],
            sdist=artifacts["sdist"],
            sbom=artifacts["sbom"],
            image_digest="v1.0.0",
        )
    manifest = binder.bind(
        version="1.0.0",
        commit="a" * 40,
        wheel=artifacts["wheel"],
        sdist=artifacts["sdist"],
        sbom=artifacts["sbom"],
        image_digest="sha256:" + "b" * 64,
        image_repository="ghcr.io/example/neuralstrike",
    )
    assert manifest["image"]["digest"] == "sha256:" + "b" * 64
    assert manifest["image"]["signed"] is False


def test_an_empty_image_is_null_not_omitted(artifacts) -> None:
    manifest = binder.bind(
        version="1.0.0",
        commit="a" * 40,
        wheel=artifacts["wheel"],
        sdist=artifacts["sdist"],
        sbom=artifacts["sbom"],
    )
    assert "image" in manifest
    assert manifest["image"] is None


def test_a_manifest_without_commit_or_version_binds_nothing(artifacts) -> None:
    for field in ("version", "commit"):
        kwargs = {
            "version": "1.0.0",
            "commit": "a" * 40,
            "wheel": artifacts["wheel"],
            "sdist": artifacts["sdist"],
            "sbom": artifacts["sbom"],
        }
        kwargs[field] = ""
        with pytest.raises(ValueError, match="unbound manifest binds nothing"):
            binder.bind(**kwargs)


def test_the_cli_writes_the_same_bytes_twice(artifacts, tmp_path: Path) -> None:
    first, second = tmp_path / "one.json", tmp_path / "two.json"
    argv = [
        "--version", "1.0.0", "--commit", "a" * 40, "--tag", "v1.0.0",
        "--wheel", str(artifacts["wheel"]), "--sdist", str(artifacts["sdist"]),
        "--sbom", str(artifacts["sbom"]),
    ]
    assert binder.main([*argv, "--out", str(first)]) == 0
    assert binder.main([*argv, "--out", str(second)]) == 0
    assert first.read_bytes() == second.read_bytes()
    assert json.loads(first.read_text())["signed"] is False


def test_ci_builds_and_exercises_the_wheel_outside_the_checkout() -> None:
    text = CI.read_text()
    assert "  artifact:" in text
    assert "python -m build" in text
    assert "wheel-venv" in text
    # Must not be an editable install: that is the whole point of the job.
    assert "pip install -e" not in text.split("  artifact:")[1].split("  dashboard:")[0]
    assert "site-packages" in text, "the import-provenance check disappeared"
    assert "release_manifest.py" in text
    assert "cyclonedx-py environment" in text
    # Built from outside the repository, because a gitignored build/ dir shadows the module.
    assert 'cd "$RUNNER_TEMP"' in text


def test_the_release_workflow_binds_the_image_digest_into_the_manifest() -> None:
    text = RELEASE.read_text()
    assert "release_manifest.py" in text
    assert "--image-digest" in text
    assert "steps.build.outputs.digest" in text
    assert "release-manifest.json" in text
    # The manifest must reach the release assets, or the binding is only local.
    assert "release-manifest.json" in text.split("- name: Create GitHub release")[1]
