"""NeuralStrike oracles — deterministic verifiers + an advisory Judge.

The oracle layer is the *verifier* half of the
Attacker-generates / Judge-scores / Verifier-decides separation.
Deterministic oracles (canary, forbidden-tool, predicate, schema,
system-prompt-extraction) come first; the LLM Judge is advisory and can
never flip a deterministic verdict (see
:func:`neuralstrike.oracles.base.combine_oracle_results`).

Phase 1 adds:
- :mod:`tool_harness` — instrumented canary tools (Tier-2 Behavioral evidence).
- :mod:`system_prompt` — system-prompt extraction canary (Inconclusive on
  absence, never a false Resisted).
- :mod:`evidence` — fidelity promotion IntentToAct -> Behavioral from traces.
"""

from neuralstrike.oracles.base import Oracle, OracleResult, combine_oracle_results
from neuralstrike.oracles.canary import CanaryOracle, mint_canary
from neuralstrike.oracles.evidence import fidelity_of, upgrade_fidelity_from_traces
from neuralstrike.oracles.forbidden_tool import ArgConstraint, ForbiddenToolOracle, ForbiddenToolSpec
from neuralstrike.oracles.judge import JudgeOracle, JudgeVerdict
from neuralstrike.oracles.predicate import PredicateOracle
from neuralstrike.oracles.schema import SchemaOracle
from neuralstrike.oracles.system_prompt import SystemPromptExtraction, mint_system_prompt_canary
from neuralstrike.oracles.tool_harness import CanaryTool, TraceLog, make_canary_tools

__all__ = [
    "ArgConstraint",
    "CanaryOracle",
    "CanaryTool",
    "ForbiddenToolOracle",
    "ForbiddenToolSpec",
    "JudgeOracle",
    "JudgeVerdict",
    "Oracle",
    "OracleResult",
    "PredicateOracle",
    "SchemaOracle",
    "SystemPromptExtraction",
    "TraceLog",
    "combine_oracle_results",
    "fidelity_of",
    "make_canary_tools",
    "mint_canary",
    "mint_system_prompt_canary",
    "upgrade_fidelity_from_traces",
]
