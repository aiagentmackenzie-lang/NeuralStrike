#!/usr/bin/env bash
# One description of the gate, executed by CI and by contributors.
#
# Why this file exists: on 2026-11-11 a suite passed locally and failed twice in CI on a test
# that was correct in substance, because `.venv` and CI resolved different versions from the
# same unbounded range. Two separate things were wrong — the interpreter was reconstructed from
# an unpinned install, and the gate itself was three inline CI steps that no local command could
# reproduce exactly. This script fixes the second half: every job that gates runs *this* file, so
# "what CI enforces" is a file you can execute before pushing.
#
# It runs against whatever interpreter is already active. It never installs anything: the
# environment is `scripts/dev_env.sh` (locked) or the CI job's own install step.
#
# Exit codes: 0 gate green · non-zero gate red (the failing tool's own code).
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

PYTHON="${PYTHON:-}"
if [ -z "$PYTHON" ]; then
    # CI's setup-python provides `python`; many local installs only provide `python3`.
    if command -v python >/dev/null 2>&1; then PYTHON=python; else PYTHON=python3; fi
fi

echo "== interpreter =="
"$PYTHON" - <<'PY'
import platform, sys

print(sys.executable)
print(f"python {platform.python_version()} on {platform.platform()}")
try:
    import typer

    print(f"typer {typer.__version__}")
except Exception as exc:  # pragma: no cover - diagnostics only
    print(f"typer unavailable: {exc}")
PY

echo "== ruff =="
"$PYTHON" -m ruff check src tests

echo "== mypy =="
"$PYTHON" -m mypy src

echo "== pytest =="
"$PYTHON" -m pytest --cov=neuralstrike --cov-report=term-missing --cov-fail-under=85

echo "== gate green =="
