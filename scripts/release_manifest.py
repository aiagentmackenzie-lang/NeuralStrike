"""Bind one release: version, tag, commit, wheel, sdist, SBOM and (optionally) image digest.

Phase 4 gate P4-2 asks for one artifact that ties the things a reviewer needs together, so that
"neuralstrike 1.0.0" cannot mean two different builds. This script is deliberately small and
strict: every digest is computed here, from files that must exist, and nothing is inferred.

Two things it will not do:

* claim a signature. ``signed`` is always ``false`` and ``signatures`` always empty unless a
  caller passes recorded signature records, and no caller in this repository does. A digest is
  not a signature.
* invent a value. A missing wheel, a wheel whose version disagrees with the declared version, or
  an SBOM that does not contain the project is an error, not a warning, because a manifest that
  quietly omits the thing it was supposed to bind is worse than none.

Usage (CI and release):

    python scripts/release_manifest.py --version 1.0.0 --commit "$GITHUB_SHA" \\
        --wheel dist/*.whl --sdist dist/*.tar.gz --sbom sbom.json --out release-manifest.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
PROJECT = "neuralstrike"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def artifact(path: Path, kind: str, version: str | None = None) -> dict[str, Any]:
    """Digest one artifact, refusing a missing file or a stale build of another version."""
    resolved = path.resolve()
    if not resolved.is_file():
        raise FileNotFoundError(f"{kind} artifact is missing: {resolved}")
    if version is not None and version not in resolved.name:
        raise ValueError(
            f"{kind} artifact {resolved.name!r} does not carry the declared version {version!r}"
        )
    return {"kind": kind, "name": resolved.name, "sha256": sha256(resolved), "bytes": resolved.stat().st_size}


def bind(
    *,
    version: str,
    commit: str,
    wheel: Path,
    sdist: Path,
    sbom: Path,
    tag: str | None = None,
    image_digest: str | None = None,
    image_repository: str | None = None,
    signatures: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """The manifest. Deterministic, strict, and honest about what is not signed."""
    if not version or not commit:
        raise ValueError("version and commit are required: an unbound manifest binds nothing")
    payload = json.loads(sbom.resolve().read_text())
    components = payload.get("components") if isinstance(payload, dict) else None
    names = {
        str(component.get("name", "")).lower()
        for component in components or []
        if isinstance(component, dict)
    }
    if PROJECT not in names:
        raise ValueError(f"SBOM does not contain the {PROJECT!r} component; it is not this release's SBOM")
    if image_digest is not None and not image_digest.startswith("sha256:"):
        raise ValueError(f"image digest {image_digest!r} is not a digest reference")

    return {
        "schema_version": SCHEMA_VERSION,
        "project": PROJECT,
        "version": version,
        "tag": tag,
        "source_commit": commit,
        "artifacts": [
            artifact(wheel, "wheel", version),
            artifact(sdist, "sdist", version),
            artifact(sbom, "sbom"),
        ],
        "image": (
            {"repository": image_repository, "digest": image_digest, "signed": False}
            if image_digest
            else None
        ),
        "built": {"python": platform.python_version(), "platform": platform.platform()},
        "signed": False,
        "signatures": signatures or [],
        "signing_policy": (
            "optional and off by default; when enabled it signs the image digest plus an SBOM "
            "attestation, never the wheel or release assets. No entry in signatures means no "
            "artifact of this release is signed."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tag")
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--sdist", required=True, type=Path)
    parser.add_argument("--sbom", required=True, type=Path)
    parser.add_argument("--image-digest")
    parser.add_argument("--image-repository")
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)

    manifest = bind(
        version=args.version,
        commit=args.commit,
        tag=args.tag,
        wheel=args.wheel,
        sdist=args.sdist,
        sbom=args.sbom,
        image_digest=args.image_digest,
        image_repository=args.image_repository,
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"manifest": str(args.out), "signed": manifest["signed"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
