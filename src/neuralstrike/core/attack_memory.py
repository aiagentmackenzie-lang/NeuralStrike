"""SQLite attack memory: what worked, recorded honestly, ratcheted safely.

Phase 9 (G1). Adaptive attack research (AutoRedTeamer, GPT-Red's attack
memory) keeps what worked across runs instead of restarting from zero every
time. This module is that memory — with the house discipline bolted on:

- **Memory never affects run verdicts (P2-7 mirror).** ``record_run`` is
  best-effort: any storage failure is logged + counted and ``record_run``
  returns ``False`` — a completed run's verdicts are already proven by the
  deterministic oracles and a bookkeeping failure must never touch them.
- **Selection is fail-closed.** ``strategy_ranking`` *raises*
  :class:`AttackMemoryError` when the memory is unreadable or its schema
  version mismatches. A run asked to pick a strategy *from* memory
  (``--strategy auto``) refuses to guess rather than silently falling back
  to an arbitrary strategy.
- **Deterministic ranking, lower-bound-gated ratchet.** Strategies rank by
  the Wilson *lower* bound of their recorded conclusive-only ASR — a lucky
  single run cannot top the board, and an INCONCLUSIVE run never inflates a
  rank (coverage gaps are not evidence of strength). The champion ratchet
  (``champions`` table) only moves when a challenger's lower bound beats the
  incumbent's.
- **No goal text stored.** Goals are stored as a 16-hex SHA-256 prefix
  (:func:`neuralstrike.core.trajectory.hash_goal`) — the memory is a join
  key, not a leak surface.
- **stdlib sqlite3 only.** Zero new dependencies; WAL journal for concurrent
  readers; ``user_version`` pins the schema (v1).
"""

from __future__ import annotations

import hashlib
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from neuralstrike.core.exceptions import NeuralStrikeError
from neuralstrike.core.trajectory import hash_goal
from neuralstrike.evaluation.statistics import wilson_ci
from neuralstrike.utils.logging import get_logger

logger = get_logger("neuralstrike.core.attack_memory")

__all__ = [
    "AttackMemory",
    "AttackMemoryError",
    "MemoryRecord",
    "StrategyStat",
    "rank_labels",
]

_SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_utc TEXT NOT NULL,
    victim TEXT NOT NULL,
    victim_type TEXT NOT NULL,
    strategy TEXT NOT NULL,
    scenario_id TEXT NOT NULL,
    category TEXT NOT NULL,
    goal_hash TEXT NOT NULL,
    verdict TEXT NOT NULL,
    fidelity TEXT NOT NULL,
    iterations INTEGER NOT NULL,
    seed INTEGER NOT NULL,
    payload_sha256 TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_runs_lookup
    ON runs (victim, goal_hash, strategy);
CREATE TABLE IF NOT EXISTS champions (
    victim TEXT NOT NULL,
    goal_hash TEXT NOT NULL,
    strategy TEXT NOT NULL,
    lb REAL NOT NULL,
    runs INTEGER NOT NULL,
    conclusive INTEGER NOT NULL,
    succeeded INTEGER NOT NULL,
    updated_utc TEXT NOT NULL,
    PRIMARY KEY (victim, goal_hash, strategy)
);
"""


class AttackMemoryError(NeuralStrikeError):
    """Memory is unreadable, corrupt, or its schema version mismatches.

    Raised on the READ path used for strategy selection (fail-closed) —
    never from ``record_run``, which is best-effort by contract.
    """


@dataclass(frozen=True)
class MemoryRecord:
    """One completed trial's outcome, as written to the ``runs`` table."""

    victim: str
    victim_type: str
    strategy: str
    scenario_id: str
    category: str
    goal: str  # stored hashed; never persisted as text
    verdict: str  # "resisted" | "succeeded" | "inconclusive"
    fidelity: str
    iterations: int
    seed: int
    payload: str  # stored hashed


@dataclass(frozen=True)
class StrategyStat:
    """One strategy's recorded evidence for a (victim, goal) pair.

    ``lb`` is the Wilson lower bound of ``succeeded / conclusive`` — the
    conservative rank signal. ``conclusive`` excludes INCONCLUSIVE runs by
    contract (a coverage gap is not evidence).
    """

    strategy: str
    runs: int
    conclusive: int
    succeeded: int
    lb: float


def rank_labels(
    stats: list[StrategyStat],
    *,
    min_conclusive: int = 1,
) -> list[StrategyStat]:
    """Deterministic ranking: Wilson LB desc, then label asc (stable ties).

    Strategies with fewer than ``min_conclusive`` conclusive runs are excluded —
    no evidence, no rank. Deterministic in ``stats`` order-independent way:
    the sort key is (-lb, strategy), so the same evidence always yields the
    same order.
    """
    eligible = [s for s in stats if s.conclusive >= min_conclusive]
    return sorted(eligible, key=lambda s: (-s.lb, s.strategy))


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class AttackMemory:
    """SQLite-backed attack memory (WAL, schema-versioned, fail-soft writes)."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._conn: sqlite3.Connection | None = None

    def _connect(self) -> sqlite3.Connection:
        """Open (once) + verify schema. Raises AttackMemoryError when unusable."""
        if self._conn is not None:
            return self._conn
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(self._path))
            conn.execute("PRAGMA journal_mode=WAL")
            version = int(conn.execute("PRAGMA user_version").fetchone()[0])
            if version == 0:
                conn.executescript(_SCHEMA)
                conn.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
                conn.commit()
            elif version != _SCHEMA_VERSION:
                conn.close()
                raise AttackMemoryError(
                    f"attack memory schema version {version} != {_SCHEMA_VERSION}: {self._path}"
                )
            conn.row_factory = sqlite3.Row
            self._conn = conn
            return conn
        except AttackMemoryError:
            raise
        except (sqlite3.Error, OSError) as exc:
            raise AttackMemoryError(f"attack memory unusable ({self._path}): {exc}") from exc

    def record_run(self, record: MemoryRecord) -> bool:
        """Record one trial outcome + update the champion ratchet. Best-effort.

        Returns ``True`` when recorded, ``False`` when storage failed (logged;
        never raised — telemetry must not affect run verdicts).
        """
        try:
            conn = self._connect()
            now = _utc_now()
            with conn:
                conn.execute(
                    "INSERT INTO runs (ts_utc, victim, victim_type, strategy, scenario_id,"
                    " category, goal_hash, verdict, fidelity, iterations, seed, payload_sha256)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        now,
                        record.victim,
                        record.victim_type,
                        record.strategy,
                        record.scenario_id,
                        record.category,
                        hash_goal(record.goal),
                        record.verdict,
                        record.fidelity,
                        int(record.iterations),
                        int(record.seed),
                        hashlib.sha256(record.payload.encode("utf-8")).hexdigest(),
                    ),
                )
                self._ratchet(conn, record, now)
            return True
        except (sqlite3.Error, AttackMemoryError, OSError) as exc:
            logger.warning("attack-memory write failed (run verdicts unaffected): %s", exc)
            return False

    def _ratchet(self, conn: sqlite3.Connection, record: MemoryRecord, now: str) -> None:
        """Champion ratchet: a strategy takes the crown only via its LOWER bound.

        Cumulative per (victim, goal_hash, strategy): all recorded runs feed
        the aggregate, so a challenger must sustain its evidence, not spike.
        """
        strategy = record.strategy
        row = conn.execute(
            "SELECT COUNT(*) AS runs,"
            " SUM(CASE WHEN verdict IN ('resisted','succeeded') THEN 1 ELSE 0 END) AS conclusive,"
            " SUM(CASE WHEN verdict = 'succeeded' THEN 1 ELSE 0 END) AS succeeded"
            " FROM runs WHERE victim = ? AND goal_hash = ? AND strategy = ?",
            (record.victim, hash_goal(record.goal), strategy),
        ).fetchone()
        runs = int(row["runs"])
        conclusive = int(row["conclusive"] or 0)
        succeeded = int(row["succeeded"] or 0)
        lb = wilson_ci(succeeded, conclusive)[0] if conclusive else 0.0
        conn.execute(
            "INSERT INTO champions (victim, goal_hash, strategy, lb, runs, conclusive,"
            " succeeded, updated_utc)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
            " ON CONFLICT (victim, goal_hash, strategy) DO UPDATE"
            " SET lb = excluded.lb, runs = excluded.runs, conclusive = excluded.conclusive,"
            " succeeded = excluded.succeeded, updated_utc = excluded.updated_utc",
            (record.victim, hash_goal(record.goal), strategy, lb, runs, conclusive, succeeded, now),
        )

    def champion(self, victim: str, goal: str) -> StrategyStat | None:
        """The incumbent best strategy for (victim, goal), or ``None`` with no evidence.

        Raises on read failure (fail-closed for selection).
        """
        conn = self._connect()
        row = conn.execute(
            "SELECT strategy, lb, runs, conclusive, succeeded FROM champions"
            " WHERE victim = ? AND goal_hash = ? ORDER BY lb DESC, strategy ASC LIMIT 1",
            (victim, hash_goal(goal)),
        ).fetchone()
        if row is None:
            return None
        return StrategyStat(
            strategy=str(row["strategy"]),
            runs=int(row["runs"]),
            conclusive=int(row["conclusive"]),
            succeeded=int(row["succeeded"]),
            lb=float(row["lb"]),
        )

    def strategy_ranking(self, victim: str, goal: str, *, min_conclusive: int = 1) -> list[StrategyStat]:
        """Rank every strategy with evidence for (victim, goal). Deterministic.

        Raises :class:`AttackMemoryError` on read failure — callers must not
        silently fall back to an arbitrary strategy (fail-closed selection).
        """
        conn = self._connect()
        rows = conn.execute(
            "SELECT strategy, COUNT(*) AS runs,"
            " SUM(CASE WHEN verdict IN ('resisted','succeeded') THEN 1 ELSE 0 END) AS conclusive,"
            " SUM(CASE WHEN verdict = 'succeeded' THEN 1 ELSE 0 END) AS succeeded"
            " FROM runs WHERE victim = ? AND goal_hash = ? GROUP BY strategy",
            (victim, hash_goal(goal)),
        ).fetchall()
        stats: list[StrategyStat] = []
        for r in rows:
            conclusive = int(r["conclusive"] or 0)
            succeeded = int(r["succeeded"] or 0)
            lb = wilson_ci(succeeded, conclusive)[0] if conclusive else 0.0
            stats.append(
                StrategyStat(
                    strategy=str(r["strategy"]),
                    runs=int(r["runs"]),
                    conclusive=conclusive,
                    succeeded=succeeded,
                    lb=lb,
                )
            )
        return rank_labels(stats, min_conclusive=min_conclusive)

    def summary(self) -> list[sqlite3.Row]:
        """Read-only per-strategy aggregate for the ``attack-memory`` view.

        Raises on read failure (the inspect command is an explicit read).
        """
        conn = self._connect()
        return conn.execute(
            "SELECT victim, strategy, COUNT(*) AS runs,"
            " SUM(CASE WHEN verdict IN ('resisted','succeeded') THEN 1 ELSE 0 END) AS conclusive,"
            " SUM(CASE WHEN verdict = 'succeeded' THEN 1 ELSE 0 END) AS succeeded"
            " FROM runs GROUP BY victim, strategy ORDER BY victim, strategy"
        ).fetchall()

    def close(self) -> None:
        """Close the connection if open (idempotent)."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None
