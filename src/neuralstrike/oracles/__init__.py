"""NeuralStrike oracles — deterministic verifiers + an advisory Judge.

The oracle layer is the *verifier* half of the
Attacker-generates / Judge-scores / Verifier-decides separation.
Deterministic oracles (canary, forbidden-tool, predicate, schema) come
first; the LLM Judge is advisory and can never flip a deterministic
verdict (see :func:`neuralstrike.oracles.base.combine_oracle_results`).
"""

from neuralstrike.oracles.base import Oracle, OracleResult, combine_oracle_results
from neuralstrike.oracles.canary import CanaryOracle, mint_canary
from neuralstrike.oracles.forbidden_tool import ArgConstraint, ForbiddenToolOracle, ForbiddenToolSpec
from neuralstrike.oracles.judge import JudgeOracle, JudgeVerdict
from neuralstrike.oracles.predicate import PredicateOracle
from neuralstrike.oracles.schema import SchemaOracle

__all__ = [
    "ArgConstraint",
    "CanaryOracle",
    "ForbiddenToolOracle",
    "ForbiddenToolSpec",
    "JudgeOracle",
    "JudgeVerdict",
    "Oracle",
    "OracleResult",
    "PredicateOracle",
    "SchemaOracle",
    "combine_oracle_results",
    "mint_canary",
]
