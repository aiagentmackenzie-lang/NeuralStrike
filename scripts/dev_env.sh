#!/usr/bin/env bash
# Build the environment the gate is measured in — from the hash-pinned lock, not from an
# unbounded `pip install -e ".[dev,mcp]"`.
#
# Background (2026-11-11): the local `.venv` and CI resolved different `typer` versions from the
# same unbounded range (`typer>=0.12` gave 0.29.0 locally, 0.28.0 in CI). The suite passed
# locally and failed twice in CI on a test that was correct in substance. `requirements-dev.txt`
# is the lock for the dev extra (`uv pip compile ... --extra dev --extra mcp`), and this script
# installs it with `--require-hashes`, then installs the project with `--no-deps` — exactly what
# the CI `supply-chain` job does. Same pins, same gate, locally.
#
# The lock was compiled for CPython 3.12, so this script refuses any other interpreter rather
# than resolving a different set of wheels and calling it the same gate (fail-closed).
#
# Usage:
#   scripts/dev_env.sh                 # create/update .venv, then run the gate
#   VENV=/tmp/ns scripts/dev_env.sh    # alternate venv path
#   PYTHON=python3.12 scripts/dev_env.sh --no-gate
#   PIP_ARGS="--no-index" scripts/dev_env.sh   # offline, if a local wheel cache is populated
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

PYTHON="${PYTHON:-python3.12}"
VENV="${VENV:-.venv}"
PIP_ARGS="${PIP_ARGS:-}"
RUN_GATE=1

for arg in "$@"; do
    case "$arg" in
        --no-gate) RUN_GATE=0 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

# The lock is 3.12-specific. An interpreter mismatch would silently change the resolution, which
# is the exact failure this script exists to prevent.
"$PYTHON" - <<'PY'
import sys

if sys.version_info[:2] != (3, 12):
    sys.exit(
        f"requirements-dev.txt is compiled for CPython 3.12; {sys.version_info.major}.{sys.version_info.minor} "
        "would resolve a different wheel set. Point PYTHON= at a 3.12 interpreter, or regenerate the "
        "lock for this version and update this guard in the same commit."
    )
PY

if [ ! -x "$VENV/bin/python" ]; then
    echo "== creating $VENV =="
    "$PYTHON" -m venv "$VENV"
fi

PIP=("$VENV/bin/python" -m pip)

echo "== upgrading pip =="
"${PIP[@]}" install --upgrade pip ${PIP_ARGS}

echo "== installing the locked dev extra (hash-pinned) =="
# shellcheck disable=SC2086
"${PIP[@]}" install --require-hashes -r requirements-dev.txt ${PIP_ARGS}

echo "== installing neuralstrike itself (no dependency resolution) =="
# shellcheck disable=SC2086
"${PIP[@]}" install --no-deps -e . ${PIP_ARGS}

echo "== installed =="
"$VENV/bin/python" - <<'PY'
import sys

import typer

print(f"{sys.executable}\ntyper {typer.__version__}")
PY

if [ "$RUN_GATE" -eq 1 ]; then
    echo "== running the gate (scripts/ci_gate.sh) =="
    PYTHON="$VENV/bin/python" bash scripts/ci_gate.sh
else
    echo "environment ready; run 'PYTHON=$VENV/bin/python bash scripts/ci_gate.sh' for the gate"
fi
