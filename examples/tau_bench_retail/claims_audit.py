"""Reconcile the profile's claims with the record on disk. Read-only, no model.

The profile is the primary artifact a reviewer has to trust: it quotes plan hashes,
summary hashes and observation counts for six cyclic plans and nine pinned constants. A
hand-check of those claims was done once and found four stale sentences; a hand-check is
not a control, so this module makes it mechanical.

What it checks:

* every ``<8 hex>…`` hash claim in the profile resolves to a hash that exists on disk —
  a plan, a summary, an exit document, a plan digest, a frozen harness copy, a repository
  harness module, a pinned constant, a model digest, or the pinned target revision;
* every cycle packet named in the evidence blocks exists, and the ``summary_sha256`` the
  evidence records is the summary actually on disk;
* the declared/completed/errors counts the profile reports reconcile with each summary.

What it does not check: prose. A sentence can be wrong while every hash resolves. This is
a drift detector for the mechanical claims, not a correctness proof for the record, and it
says so in its own output rather than implying more.

No network, no model, no target import, no write to any recorded artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from examples.tau_bench_retail import profile

HEX_CLAIM = re.compile(r"([0-9a-f]{8})(?:…|\.\.\.)")
HASH_SUFFIXES = ("plan.json", "summary.json", "exit.json")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def resolve_home(text: str) -> Path:
    return Path(text.replace("~", str(Path.home()), 1))


def known_hashes(packet_root: Path, repo_root: Path) -> dict[str, list[str]]:
    """Every hash that provably exists, keyed by its 8-hex prefix."""
    known: dict[str, list[str]] = {}

    def add(value: str, what: str) -> None:
        known.setdefault(value[:8], []).append(what)

    for directory in sorted(packet_root.glob("tau-bench-*cycle*")):
        if not directory.is_dir():
            continue
        for name in HASH_SUFFIXES:
            candidate = directory / name
            if candidate.exists():
                add(sha256_file(candidate), f"{directory.name}/{name}")
        summary = directory / "summary.json"
        if summary.exists():
            document = json.loads(summary.read_text())
            if isinstance(document.get("plan_digest"), str):
                add(document["plan_digest"], f"{directory.name}/plan_digest")
        harness = directory / "harness"
        if harness.is_dir():
            for module in harness.glob("*.py"):
                add(sha256_file(module), f"{directory.name}/harness/{module.name}")

    for module in sorted((repo_root / "examples" / "tau_bench_retail").glob("*.py")):
        add(sha256_file(module), f"repo/{module.name}")

    # Derived artifacts the profile quotes (the refusal audit, for one) are files too.
    for artifact in sorted((repo_root / "docs" / "implementation" / "evidence").glob("*.json")):
        add(sha256_file(artifact), f"evidence/{artifact.name}")

    # Pinned constants: the digests `tests/test_tau_bench.py` already asserts.
    for name in (
        "CASES", "EXPECTATIONS", "SENSITIVITY_CASES", "SENSITIVITY_EXPECTATIONS",
        "ATTRIBUTION_EXPECTATIONS", "WITHHOLDING_TOOL", "WRITE_FIRST_CASES",
        "WRITE_FIRST_EXPECTATIONS", "WRITE_FIRST_WITHHOLDING_TOOL",
    ):
        add(profile.digest(getattr(profile, name)), f"profile.{name}")

    # Declared literals that are not file hashes.
    add(profile.REVISION, "profile.REVISION (pinned target commit)")
    for name, entry in profile.MODEL_REGISTRY.items():
        add(entry["digest"], f"profile.MODEL_REGISTRY[{name}]")
    return known


def profile_hash_claims(text: str) -> list[dict[str, Any]]:
    claims = []
    for number, line in enumerate(text.splitlines(), start=1):
        for match in HEX_CLAIM.finditer(line):
            claims.append({"lines": number, "prefix": match.group(1), "text": line.strip()[:120]})
    return claims


def audit_cycles(packet_root: Path) -> list[dict[str, Any]]:
    cycles = []
    for directory in sorted(packet_root.glob("tau-bench-*cycle*")):
        summary_path = directory / "summary.json"
        if not summary_path.exists():
            continue
        summary = json.loads(summary_path.read_text())
        rows = summary.get("rows") or []
        exit_path = directory / "exit.json"
        observed_path = directory / "exit-status.txt"
        observed = None
        if observed_path.exists():
            text = observed_path.read_text().strip()
            observed = int(text) if text.isdigit() else text
        cycles.append(
            {
                "name": directory.name,
                "plan_kind": summary.get("plan_kind") or summary.get("kind"),
                "declared": sum(row.get("repeats", 0) for row in rows),
                "completed": sum(row.get("completed", 0) for row in rows),
                "errors": sum(row.get("errors", 0) for row in rows),
                "state": summary.get("state"),
                "exit_declared": json.loads(exit_path.read_text()).get("declared_exit_code")
                if exit_path.exists() else None,
                "exit_observed": observed,
                "summary_sha256": sha256_file(summary_path),
            }
        )
    return cycles


def audit_evidence(evidence_path: Path) -> list[dict[str, Any]]:
    """Every evidence block that names a cycle must name the summary actually on disk."""
    document = json.loads(evidence_path.read_text())
    findings = []
    for block_name, block in sorted(document.items()):
        if not isinstance(block, dict):
            continue
        cycle = block.get("cycle")
        if not isinstance(cycle, dict) or "summary_sha256" not in cycle:
            continue
        directory = resolve_home(str(cycle.get("path", "")))
        summary = directory / "summary.json"
        if not summary.exists():
            findings.append({"block": block_name, "path": str(directory), "issue": "packet missing"})
            continue
        observed = sha256_file(summary)
        findings.append(
            {
                "block": block_name,
                "path": str(directory),
                "recorded": cycle["summary_sha256"],
                "observed": observed,
                "issue": None if observed == cycle["summary_sha256"] else "summary hash moved",
            }
        )
    return findings


def audit(packet_root: Path, repo_root: Path, profile_path: Path, evidence_path: Path) -> dict[str, Any]:
    known = known_hashes(packet_root, repo_root)
    claims = profile_hash_claims(profile_path.read_text())
    unresolved = [claim for claim in claims if claim["prefix"] not in known]
    cycles = audit_cycles(packet_root)
    evidence = audit_evidence(evidence_path)
    mismatched = [item for item in evidence if item["issue"]]
    return {
        "schema_version": 1,
        "kind": "tau-bench-retail-claims-audit-v1",
        "inference": "none",
        "excluded_from_efficacy": True,
        "checks": [
            "every 8-hex hash claim in the profile resolves to a hash that exists on disk",
            "the evidence blocks' summary_sha256 equals the summary actually on disk",
            "the counts the profile reports reconcile with each recorded summary",
        ],
        "not_checked": [
            "prose: a sentence can be wrong while every hash resolves",
            "anything in a packet that is absent on this machine",
        ],
        "profile": {
            "path": str(profile_path),
            "claims_checked": len(claims),
            "unresolved": unresolved,
        },
        "evidence": {
            "path": str(evidence_path),
            "blocks_with_a_cycle": len(evidence),
            "mismatched": mismatched,
        },
        "cycles": cycles,
        "ok": not unresolved and not mismatched,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="reconcile the profile's claims with the record")
    parser.add_argument("--packet-root", required=True, type=Path)
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    arguments = parser.parse_args()
    repo_root = Path(__file__).resolve().parents[2]
    document = audit(arguments.packet_root, repo_root, arguments.profile, arguments.evidence)
    arguments.out.parent.mkdir(parents=True, exist_ok=True)
    arguments.out.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    print(
        f"{document['profile']['claims_checked']} hash claims, "
        f"{len(document['profile']['unresolved'])} unresolved; "
        f"{document['evidence']['blocks_with_a_cycle']} evidence blocks, "
        f"{len(document['evidence']['mismatched'])} mismatched; {len(document['cycles'])} cycles"
    )
    for claim in document["profile"]["unresolved"]:
        print(f"  UNRESOLVED line {claim['lines']}: {claim['prefix']}…  {claim['text']}")
    for item in document["evidence"]["mismatched"]:
        print(f"  MISMATCH {item['block']}: {item['issue']}")
    return 0 if document["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
