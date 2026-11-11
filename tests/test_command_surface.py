"""Contracts for the declared command surface.

The defect this closes (ENGINEERING_BACKLOG.md E-3): 15 of the registered commands enforced
neither a scope file nor the HITL gate while others enforced both, and nothing in the repository
said which was which. A binary whose offensiveness depends on which subcommand you typed is not a
control, and silence was the failure mode.

These contracts read `main.py`'s AST and the Typer app, not prose:

* every registered command name appears exactly once in `COMMAND_SURFACE`;
* every row that declares `sends_traffic` has a callback that calls `_apply_scope` **and**
  `_apply_safety`;
* that callback also exposes `--scope-file`, `--intent` and `--require-approval`, so the gate is
  reachable and not merely present;
* the legacy set is frozen, so a command cannot be promoted to "supported" by editing one row;
* an unclassified command refuses to dispatch — demonstrated on a fabricated app, because the
  real check runs at import time and a passing import proves only that today's table is complete.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
import typer

from neuralstrike.safety.surface import (
    COMMAND_SURFACE,
    LEGACY_COMMANDS,
    TRAFFIC_COMMANDS,
    CommandRow,
    SurfaceError,
    surface_row,
    verify_surface,
)

ROOT = Path(__file__).resolve().parents[1]
MAIN = ROOT / "src/neuralstrike/main.py"

# Frozen at the audit that produced E-3. Reclassifying a legacy command as accepted is a claim
# about efficacy, not a table edit, so it must move this constant in the same commit as the
# evidence.
FROZEN_LEGACY = frozenset(
    {
        "forge",
        "poison",
        "exhaust",
        "recon",
        "hijack",
        "confuse",
        "schema-poison",
        "intercept",
        "pivot",
        "map-network",
        "extract",
        "timing",
        "c2",
        "evade",
        "neuralguard-bench",
    }
)

GATE_CALLS = ("_apply_scope", "_apply_safety")

#: The two commands that *are* the gate surface. They call the helper by design and send nothing.
GATE_COMMANDS = frozenset({"scope-check", "safety-check"})


def _functions() -> dict[str, ast.FunctionDef]:
    tree = ast.parse(MAIN.read_text())
    return {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}


def _called_names(node: ast.FunctionDef) -> set[str]:
    names: set[str] = set()
    for call in ast.walk(node):
        if isinstance(call, ast.Call) and isinstance(call.func, ast.Name):
            names.add(call.func.id)
    return names


def _parameter_names(node: ast.FunctionDef) -> set[str]:
    return {arg.arg for arg in node.args.args}


def _real_app() -> typer.Typer:
    from neuralstrike.main import app

    return app


def test_table_matches_the_registered_cli() -> None:
    verify_surface(_real_app())  # raises SurfaceError on any gap


def test_every_command_appears_exactly_once() -> None:
    names = [row.name for row in COMMAND_SURFACE]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    assert not duplicates, f"declared more than once: {duplicates}"


def test_the_legacy_set_is_frozen() -> None:
    assert LEGACY_COMMANDS == FROZEN_LEGACY, (
        "the legacy command set changed. Moving a command in or out of it is an acceptance claim: "
        f"added={sorted(LEGACY_COMMANDS - FROZEN_LEGACY)} "
        f"removed={sorted(FROZEN_LEGACY - LEGACY_COMMANDS)}"
    )


@pytest.mark.parametrize("row", [row for row in COMMAND_SURFACE if row.sends_traffic], ids=lambda r: r.name)
def test_traffic_sending_command_enforces_both_gates(row: CommandRow) -> None:
    functions = _functions()
    node = functions.get(row.callback)
    assert node is not None, f"{row.name} points at a callback that does not exist: {row.callback}"
    called = _called_names(node)
    missing = [name for name in GATE_CALLS if name not in called]
    assert not missing, (
        f"{row.name} declares sends_traffic=True but its callback {row.callback} does not call "
        f"{missing}: a traffic-sending command must enforce the scope and HITL gates"
    )
    assert row.gate == "scope+safety", f"{row.name} sends traffic but declares gate={row.gate!r}"


@pytest.mark.parametrize("row", [row for row in COMMAND_SURFACE if row.sends_traffic], ids=lambda r: r.name)
def test_traffic_sending_command_exposes_the_gate_options(row: CommandRow) -> None:
    """A gate the operator cannot address is not a gate."""
    node = _functions()[row.callback]
    params = _parameter_names(node)
    missing = sorted({"scope_file", "intent", "require_approval"} - params)
    assert not missing, (
        f"{row.name} calls the gate but does not accept {missing}: the check would always run "
        "with the permissive default and could never refuse anything"
    )


@pytest.mark.parametrize("row", [row for row in COMMAND_SURFACE if not row.sends_traffic], ids=lambda r: r.name)
def test_non_traffic_command_is_honest_about_it(row: CommandRow) -> None:
    """A row that claims no traffic must not secretly reach the gate helpers."""
    assert row.gate == "none"
    node = _functions().get(row.callback)
    assert node is not None
    if row.name in GATE_COMMANDS:
        # `scope-check` and `safety-check` ARE the gate surface: they call the helper directly and
        # send nothing. Declared by name so this exemption cannot spread silently.
        return
    called = _called_names(node)
    assert not (set(GATE_CALLS) & called), (
        f"{row.name} declares sends_traffic=False but calls {sorted(set(GATE_CALLS) & called)}; "
        "either the classification or the gate call is wrong"
    )


def test_traffic_and_legacy_sets_are_derived_from_the_rows() -> None:
    derived = frozenset(row.name for row in COMMAND_SURFACE if row.sends_traffic)
    assert derived == TRAFFIC_COMMANDS
    assert LEGACY_COMMANDS <= TRAFFIC_COMMANDS, "every legacy command attacks something"


def test_surface_row_refuses_an_unclassified_name() -> None:
    with pytest.raises(SurfaceError):
        surface_row("not-a-registered-command")


def test_an_unclassified_new_command_refuses_to_dispatch() -> None:
    """The fail-closed behaviour, demonstrated: a new command cannot slip in unclassified."""
    fake = typer.Typer()

    @fake.command()
    def brand_new_attack(target: str = "") -> None:  # pragma: no cover - never invoked
        """A command nobody classified."""

    with pytest.raises(SurfaceError) as excinfo:
        verify_surface(fake)
    assert "unclassified" in str(excinfo.value)
    assert "brand-new-attack" in str(excinfo.value)


def test_a_removed_command_is_not_left_declared() -> None:
    """The other direction: a row for a command the CLI no longer has is stale, and fails."""
    fake = typer.Typer()

    @fake.command()
    def forge(target: str = "") -> None:  # pragma: no cover - never invoked
        """A single command, so most of the table is stale."""

    with pytest.raises(SurfaceError) as excinfo:
        verify_surface(fake)
    assert "declared but not registered" in str(excinfo.value)


def test_main_verifies_the_surface_at_import() -> None:
    """The runtime control, not just the test: `main.py` must call verify_surface(app)."""
    tree = ast.parse(MAIN.read_text())
    calls = [
        node
        for node in tree.body
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "verify_surface"
    ]
    assert calls, "main.py must call verify_surface(app) so an unclassified command cannot dispatch"


# --- Behaviour, not structure: the gate has to actually refuse ------------------------------
#
# The AST checks above prove the calls exist. They cannot prove the calls *work*, and a gate
# placed after the first request would satisfy them while protecting nothing. These tests drive
# the CLI with a scope file that excludes the target and a poisoned implementation that fails the
# test if it is ever constructed — so a refusal here means nothing was sent.

class _TrafficBomb(AssertionError):
    """Raised if a legacy command reaches the code that would send traffic."""


def _scope_file(tmp_path: Path, targets: str = "http://localhost:*") -> Path:
    import yaml

    path = tmp_path / "scope.yaml"
    path.write_text(yaml.safe_dump({"in_scope": {"targets": [targets], "intents": ["*"]}}))
    return path


def _invoke(args: list[str]) -> object:
    from typer.testing import CliRunner

    from neuralstrike.main import app

    return CliRunner().invoke(app, args)


@pytest.mark.parametrize(
    ("args", "module", "attribute"),
    [
        (
            ["forge", "--target", "prod.example.com", "--goal", "x", "--target-type", "remote"],
            "neuralstrike.modules.weaponize.jailbreak_forge",
            "JailbreakForge",
        ),
        (
            ["recon", "--target", "https://prod.example.com", "--target-type", "remote"],
            "neuralstrike.modules.recon.llm_recon",
            "LLMRecon",
        ),
        (
            ["c2", "--agent-id", "prod-agent", "--command", "whoami"],
            "neuralstrike.modules.post_ex.agent_c2",
            "AgentC2",
        ),
    ],
)
def test_legacy_command_refuses_out_of_scope_before_any_traffic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    args: list[str],
    module: str,
    attribute: str,
) -> None:
    """Out of scope means the attack code is never constructed, let alone called."""
    import importlib

    def _bomb(*_args: object, **_kwargs: object) -> object:
        raise _TrafficBomb(f"{attribute} was constructed despite an out-of-scope target")

    monkeypatch.setattr(importlib.import_module(module), attribute, _bomb)
    result = _invoke([*args, "--scope-file", str(_scope_file(tmp_path))])
    assert result.exit_code == 1, result.output
    assert not isinstance(result.exception, _TrafficBomb)


def test_forge_refuses_an_unapproved_irreversible_intent() -> None:
    """The HITL gate is reachable from a legacy command and refuses by default."""
    result = _invoke(
        [
            "forge",
            "--target",
            "mistral:7b",
            "--goal",
            "x",
            "--target-type",
            "local",
            "--intent",
            "delete the customer database",
        ]
    )
    assert result.exit_code == 1
    rendered = str(result.output) + str(getattr(result, "exception", ""))
    assert "requires --require-approval" in rendered


def test_forge_proceeds_once_the_gates_are_satisfied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The other half: the gate must not be a blanket refusal.

    Without this, a command that always exits 1 would pass every test above. The bomb fires
    inside the command's coroutine, so the runtime error handler turns it into exit 3 and logs the
    reason — the assertion is on that reason, which can only appear if the attack code was reached.
    """
    import neuralstrike.modules.weaponize.jailbreak_forge as forge_module

    def _reached(*_args: object, **_kwargs: object) -> object:
        raise _TrafficBomb("the gate allowed the command through")

    monkeypatch.setattr(forge_module, "JailbreakForge", _reached)
    result = _invoke(
        [
            "forge",
            "--target",
            "mistral:7b",
            "--goal",
            "x",
            "--target-type",
            "local",
            "--scope-file",
            str(_scope_file(tmp_path, "mistral:*")),
            "--intent",
            "delete the customer database",
            "--require-approval",
        ]
    )
    assert result.exit_code == 3, result.output
    assert "the gate allowed the command through" in caplog.text
