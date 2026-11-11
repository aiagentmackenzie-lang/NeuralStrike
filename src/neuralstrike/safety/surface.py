"""The declared command surface: what every registered command does to a network, and which
gates it must therefore enforce.

Why this file exists. Before it, `neuralstrike` had two classes of command and no declaration of
which was which: `scan`, `assess`, `doctor`, `pack`, `adaptive`, `mcp-*-scan`, `a2a-scan`, `minja`,
`rag-poison` and `exec-context` enforced a scope file and the HITL gate, while `forge`, `poison`,
`exhaust`, `recon`, `hijack`, `confuse`, `schema-poison`, `intercept`, `pivot`, `map-network`,
`extract`, `timing`, `c2`, `evade` and `neuralguard-bench` enforced neither. A binary whose
offensiveness depended on which subcommand you typed is not a control. The silence was the defect
— nothing in the repository said which commands send traffic, so "it must be gated, it isn't
excluded" was unfalsifiable.

So the table is the declaration, and it is enforced three ways:

1. `verify_surface` runs at import time in `main.py`. A registered command with no row raises
   before the CLI can dispatch anything: an unclassified command cannot be run, not even `--help`.
2. `tests/test_command_surface.py` reads `main.py`'s AST and fails if a row claims
   `scope+safety` for a callback that does not call both gates, or if the table and the Typer app
   disagree by even one name.
3. `docs/SUPPORT_MATRIX.md` is generated from the same distinction and a contract fails if the
   document goes silent on a traffic-sending command again.

The honest limit, stated here because a table invites the opposite reading: **the scope file is
opt-in on every command, including the accepted ones.** `_apply_scope` does nothing when
`--scope-file` is absent. This table does not create a global gate; it makes the gate's presence
uniform and its absence visible.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import typer.main

if TYPE_CHECKING:  # pragma: no cover - typing only
    import typer

# Gate values. There is no "safety only": the HITL gate classifies an intent the operator
# declares, and an operator who declares an intent has a scope question to answer too. A
# read-only command that sends traffic therefore gets both gates and refuses nothing it used to.
GATE_NONE = "none"
GATE_SCOPE_AND_SAFETY = "scope+safety"

# Command kinds, used by the documents and by the contract that keeps them from going silent.
KIND_ACCEPTED = "accepted"  # carries a Phase 2 acceptance claim (see SUPPORT_MATRIX.md)
KIND_EXPERIMENTAL = "experimental"  # available, no acceptance claim
KIND_LEGACY = "legacy"  # legacy offensive surface: no acceptance claim, no efficacy record
KIND_LOCAL = "local"  # no target traffic: reads or writes local state only
KIND_UTILITY = "utility"  # operator utility that does reach a service but attacks nothing


class SurfaceError(RuntimeError):
    """Raised when the declared surface and the registered CLI disagree."""


@dataclass(frozen=True)
class CommandRow:
    """One registered command name and the properties that decide how it may be invoked."""

    name: str
    callback: str
    sends_traffic: bool
    gate: str
    kind: str
    note: str

    @property
    def gated(self) -> bool:
        return self.gate == GATE_SCOPE_AND_SAFETY


def _t(name: str, callback: str, kind: str, note: str) -> CommandRow:
    return CommandRow(name, callback, True, GATE_SCOPE_AND_SAFETY, kind, note)


def _l(name: str, callback: str, kind: str, note: str) -> CommandRow:
    return CommandRow(name, callback, False, GATE_NONE, kind, note)


#: Every registered command name appears exactly once. Order is alphabetical so a diff shows
#: insertions rather than reshuffles.
COMMAND_SURFACE: tuple[CommandRow, ...] = (
    _t(
        "a2a-scan",
        "a2a_scan",
        KIND_EXPERIMENTAL,
        "Fetches an A2A Agent Card and verifies its signature. Identity handling has no "
        "independent implementation to test against.",
    ),
    _t(
        "adaptive",
        "adaptive",
        KIND_ACCEPTED,
        "PAIR/TAP/Crescendo against a real adapter. Sends iterative attack turns to the target.",
    ),
    _t(
        "assess",
        "assess",
        KIND_ACCEPTED,
        "The single assessment command: runs the corpus through an adapter and commits a bundle.",
    ),
    _l(
        "attack-memory",
        "attack_memory",
        KIND_LOCAL,
        "Read-only SQLite aggregate view. No target traffic.",
    ),
    _t(
        "c2",
        "c2",
        KIND_LEGACY,
        "Registers agents and dispatches commands through them. `--list-agents` and "
        "`--deregister` are local-only but the command as a whole dispatches to agents.",
    ),
    _l("compare", "compare", KIND_ACCEPTED, "Diffs two committed bundles offline."),
    _t("confuse", "confuse", KIND_LEGACY, "Tool-confusion attack: sends a decoy-redirecting turn."),
    _t(
        "corpus",
        "assess",
        KIND_ACCEPTED,
        "Legacy name for `assess` — the same callback registered twice. It cannot drift because "
        "there is only one implementation; it prints a deprecation notice.",
    ),
    _t(
        "doctor",
        "doctor",
        KIND_ACCEPTED,
        "Capability preflight against the target endpoint. Sends probe requests, attacks nothing.",
    ),
    _l("efficacy", "efficacy", KIND_EXPERIMENTAL, "Compares recorded predictions with labels."),
    _t(
        "evade",
        "evade",
        KIND_LEGACY,
        "Persona/delimiter/steganography are pure string ops, but `--technique mimicry` calls the "
        "local attacker model, so the command as a whole sends traffic.",
    ),
    _t("evaluate", "evaluate", KIND_EXPERIMENTAL, "k-trial canary-extraction probe against a model."),
    _t("exec-context", "exec_context", KIND_EXPERIMENTAL, "Execution-context and skill attack pack."),
    _t("exhaust", "exhaust", KIND_LEGACY, "Context-window exhaustion (DoS class) against a model."),
    _l(
        "export-summary",
        "export_summary_command",
        KIND_ACCEPTED,
        "Exports validated counts and hashed observation refs from a committed bundle.",
    ),
    _t("extract", "extract", KIND_LEGACY, "Fingerprinting prompts against a model (informational)."),
    _t("forge", "forge", KIND_LEGACY, "Iterative jailbreak loop (Attacker-Victim-Judge)."),
    _t("hijack", "hijack", KIND_LEGACY, "Tool-use parameter injection."),
    _t(
        "intercept",
        "intercept",
        KIND_LEGACY,
        "MCP interception proxy: forwards tool traffic and can rewrite it.",
    ),
    _t(
        "judge-audit",
        "judge_audit",
        KIND_EXPERIMENTAL,
        "Audits the configured judge. The judge model is the subject, so the command calls it.",
    ),
    _t(
        "judge-model-list",
        "judge_model_list",
        KIND_UTILITY,
        "Lists models on an Ollama endpoint. Sends a request but attacks nothing.",
    ),
    _t("map-network", "map_network", KIND_LEGACY, "Discovers agents and trust levels."),
    _t(
        "mcp-inspect",
        "mcp_inspect",
        KIND_ACCEPTED,
        "Read-only MCP capability discovery over HTTP or stdio. No security verdict.",
    ),
    _l("mcp-receipt", "mcp_receipt", KIND_ACCEPTED, "Verifies a capability receipt offline."),
    _t("mcp-scan", "mcp_scan", KIND_ACCEPTED, "MCP tool-poisoning scan against a server."),
    _t("minja", "minja", KIND_EXPERIMENTAL, "MINJA memory-injection sequence."),
    _t(
        "neuralguard-bench",
        "neuralguard_bench",
        KIND_LEGACY,
        "Runs the canonical attack chain against a NeuralGuard-defended victim.",
    ),
    _t("pack", "pack", KIND_ACCEPTED, "Benchmark pack run against a target."),
    _t("pivot", "pivot", KIND_LEGACY, "Lateral movement across agent trust boundaries."),
    _t("poison", "poison", KIND_LEGACY, "Context manipulation and system-prompt extraction."),
    _t(
        "purple-report",
        "purple_report",
        KIND_EXPERIMENTAL,
        "Joins a local receipt with SecurityScarletAI alerts and logs over HTTP with a bearer "
        "token. Read-only on that system, but it is another system.",
    ),
    _t("rag-poison", "rag_poison", KIND_ACCEPTED, "PoisonedRAG-style retrieval-corpus poisoning."),
    _l("readme-mapping", "readme_mapping", KIND_LOCAL, "Regenerates a table from corpus/*.yaml."),
    _t("recon", "recon", KIND_LEGACY, "Scans LLM endpoints and enumerates capabilities."),
    _l("replay", "replay", KIND_ACCEPTED, "Re-verifies and re-scores a committed bundle."),
    _l("rescore", "rescore", KIND_ACCEPTED, "Re-scores recorded responses with an explicit policy."),
    _l(
        "safety-check",
        "safety_check",
        KIND_LOCAL,
        "The HITL gate itself, as a command. Classifies an intent; sends nothing.",
    ),
    _t("scan", "scan", KIND_ACCEPTED, "Drives a real target through an adapter."),
    _t("schema-poison", "schema_poison", KIND_LEGACY, "Redefines a tool's purpose via its schema."),
    _l(
        "scope-check",
        "scope_check",
        KIND_LOCAL,
        "The scope gate itself, as a command. Validates a target/intent; sends nothing.",
    ),
    _l("smoke", "smoke", KIND_ACCEPTED, "Offline bundled-fixture smoke. No model, no network."),
    _t("timing", "timing", KIND_LEGACY, "Average response latency (informational)."),
)

#: Legacy offensive commands: present in the CLI, no acceptance claim, no efficacy record.
#: Frozen so a command cannot be reclassified as "supported" by editing a row quietly.
LEGACY_COMMANDS: frozenset[str] = frozenset(row.name for row in COMMAND_SURFACE if row.kind == KIND_LEGACY)

#: Commands that transmit to a model, server or network target.
TRAFFIC_COMMANDS: frozenset[str] = frozenset(row.name for row in COMMAND_SURFACE if row.sends_traffic)

# What each legacy command *is*, in the only three categories the support matrix allows. None of
# them carries an acceptance claim; naming the category is what stops "it must work, it isn't
# excluded" from being the only available reading. `docs/SUPPORT_MATRIX.md` repeats this table and
# `tests/test_command_surface.py` fails if the two disagree — the document cannot go silent again.
EFFECT_SIMULATION = "local-simulation"  # drives a real model, no independent acceptance record
EFFECT_INFORMATIONAL = "informational"  # reports an observation, asserts no vulnerability
EFFECT_EXPERIMENTAL = "experimental"  # an attack technique with no efficacy record at all

LEGACY_EFFECT: dict[str, str] = {
    "forge": EFFECT_SIMULATION,
    "poison": EFFECT_SIMULATION,
    "exhaust": EFFECT_SIMULATION,
    "recon": EFFECT_INFORMATIONAL,
    "hijack": EFFECT_SIMULATION,
    "confuse": EFFECT_SIMULATION,
    "schema-poison": EFFECT_SIMULATION,
    "intercept": EFFECT_SIMULATION,
    "pivot": EFFECT_EXPERIMENTAL,
    "map-network": EFFECT_INFORMATIONAL,
    "extract": EFFECT_INFORMATIONAL,
    "timing": EFFECT_INFORMATIONAL,
    "c2": EFFECT_EXPERIMENTAL,
    "evade": EFFECT_SIMULATION,
    "neuralguard-bench": EFFECT_EXPERIMENTAL,
}

if set(LEGACY_EFFECT) != LEGACY_COMMANDS:  # pragma: no cover - import-time invariant
    raise SurfaceError(
        "LEGACY_EFFECT must classify exactly the legacy commands; "
        f"missing={sorted(LEGACY_COMMANDS - set(LEGACY_EFFECT))} "
        f"stale={sorted(set(LEGACY_EFFECT) - LEGACY_COMMANDS)}"
    )

_BY_NAME: dict[str, CommandRow] = {row.name: row for row in COMMAND_SURFACE}


def surface_row(name: str) -> CommandRow:
    """Return the declared row for a registered command name, or refuse."""
    try:
        return _BY_NAME[name]
    except KeyError as exc:  # pragma: no cover - verify_surface catches this first
        raise SurfaceError(
            f"command {name!r} has no row in COMMAND_SURFACE; it cannot be run until it is "
            "classified (see src/neuralstrike/safety/surface.py)"
        ) from exc


def registered_names(app: typer.Typer) -> set[str]:
    """Read the registered command names from the Typer app, not from decorator text.

    A callback registered under two names (`assess` / `corpus`) appears twice here on purpose:
    both names are things an operator can type, and both must be classified.

    A `Typer` with exactly one command collapses to that command rather than to a group, so both
    shapes are handled — the verifier is used by contracts on fabricated single-command apps.
    """
    group = typer.main.get_command(app)
    commands = getattr(group, "commands", None)
    if commands is None:
        return {group.name} if group.name else set()
    return set(commands)


def verify_surface(app: typer.Typer) -> None:
    """Refuse to run if the registered CLI and the declared surface disagree.

    Fail-closed by construction: an unknown name raises rather than defaulting to "no traffic,
    no gate", because the default for an unclassified offensive command is the unsafe one.
    """
    registered = registered_names(app)
    declared = set(_BY_NAME)
    missing = sorted(registered - declared)
    stale = sorted(declared - registered)
    duplicated = sorted(
        name for name in declared if sum(1 for row in COMMAND_SURFACE if row.name == name) > 1
    )
    problems: list[str] = []
    if missing:
        problems.append(f"registered but unclassified: {missing}")
    if stale:
        problems.append(f"declared but not registered: {stale}")
    if duplicated:
        problems.append(f"declared more than once: {duplicated}")
    if problems:
        raise SurfaceError(
            "the declared command surface disagrees with the CLI (" + "; ".join(problems) + "). "
            "Every registered command must appear exactly once in "
            "src/neuralstrike/safety/surface.py before the CLI may dispatch anything."
        )
