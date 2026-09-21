"""Attack-memory tests (Phase 9, G1) — fail-soft writes, fail-closed reads, ratchet."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from neuralstrike.core.attack_memory import (
    AttackMemory,
    AttackMemoryError,
    MemoryRecord,
    rank_labels,
)
from neuralstrike.core.trajectory import hash_goal


def _rec(
    strategy: str,
    verdict: str,
    *,
    victim: str = "victim-a",
    goal: str = "goal-text-alpha",
    seed: int = 0,
) -> MemoryRecord:
    return MemoryRecord(
        victim=victim,
        victim_type="local",
        strategy=strategy,
        scenario_id=f"adaptive-{strategy}",
        category=f"adaptive-{strategy}",
        goal=goal,
        verdict=verdict,
        fidelity="verbal",
        iterations=2,
        seed=seed,
        payload=f"payload-for-{strategy}-{seed}",
    )


class TestRecordAndRank:
    def test_rank_prefers_higher_lower_bound(self, tmp_path: Path) -> None:
        mem = AttackMemory(tmp_path / "mem.sqlite")
        assert mem.record_run(_rec("pair", "succeeded")) is True
        assert mem.record_run(_rec("crescendo", "resisted")) is True

        ranking = mem.strategy_ranking("victim-a", "goal-text-alpha")
        assert [s.strategy for s in ranking] == ["pair", "crescendo"]
        pair = ranking[0]
        assert pair.conclusive == 1 and pair.succeeded == 1
        assert pair.lb > 0.0
        # Crescendo: 0 succeeded of 1 conclusive -> lower bound 0.0.
        assert ranking[1].lb == 0.0
        mem.close()

    def test_inconclusive_never_counts_as_evidence(self, tmp_path: Path) -> None:
        mem = AttackMemory(tmp_path / "mem.sqlite")
        assert mem.record_run(_rec("pair", "inconclusive")) is True
        # A strategy with zero conclusive runs is excluded (no evidence, no rank).
        assert mem.strategy_ranking("victim-a", "goal-text-alpha") == []
        mem.close()

    def test_ranking_is_deterministic_ties_alphabetical(self, tmp_path: Path) -> None:
        mem = AttackMemory(tmp_path / "mem.sqlite")
        assert mem.record_run(_rec("zulu", "succeeded")) is True
        assert mem.record_run(_rec("alpha", "succeeded")) is True
        ranking = mem.strategy_ranking("victim-a", "goal-text-alpha")
        # Identical evidence (1/1 each) -> alphabetical tiebreak, stable.
        assert [s.strategy for s in ranking] == ["alpha", "zulu"]
        assert rank_labels(list(reversed(ranking))) == ranking
        mem.close()

    def test_min_conclusive_floor(self, tmp_path: Path) -> None:
        mem = AttackMemory(tmp_path / "mem.sqlite")
        assert mem.record_run(_rec("pair", "succeeded")) is True
        assert mem.record_run(_rec("tap", "resisted")) is True
        ranking = mem.strategy_ranking("victim-a", "goal-text-alpha", min_conclusive=2)
        assert ranking == []  # both have only 1 conclusive run
        mem.close()

    def test_goal_and_payload_never_stored_as_text(self, tmp_path: Path) -> None:
        mem = AttackMemory(tmp_path / "mem.sqlite")
        assert mem.record_run(_rec("pair", "succeeded")) is True
        conn = mem._connect()
        rows = conn.execute("SELECT * FROM runs").fetchall()
        assert len(rows) == 1
        stored_values = {str(v) for v in tuple(rows[0])}
        assert "goal-text-alpha" not in stored_values
        assert "payload-for-pair-0" not in stored_values
        assert hash_goal("goal-text-alpha") in stored_values
        mem.close()


class TestRatchet:
    def test_champion_tracks_cumulative_lower_bound(self, tmp_path: Path) -> None:
        mem = AttackMemory(tmp_path / "mem.sqlite")
        # pair: 1/1 succeeded (lb ~= 0.21) -> champion pair.
        assert mem.record_run(_rec("pair", "succeeded")) is True
        champ = champ_of(mem)
        assert champ is not None and champ.strategy == "pair"
        # pair degrades cumulatively: +1 resisted -> 1/2 (lb drops).
        assert mem.record_run(_rec("pair", "resisted")) is True
        # tap: 1/1 succeeded — dethrones pair's degraded lb (1/1 lb beats 1/2 lb).
        assert mem.record_run(_rec("tap", "succeeded")) is True
        champ = champ_of(mem)
        assert champ is not None and champ.strategy == "tap"
        mem.close()

    def test_single_lucky_run_cannot_rewrite_a_strong_champion(self, tmp_path: Path) -> None:
        mem = AttackMemory(tmp_path / "mem.sqlite")
        # Build a 4/4-succeeded pair record base (high lb).
        for i in range(4):
            assert mem.record_run(_rec("pair", "succeeded", seed=i)) is True
        champ = champ_of(mem)
        assert champ is not None and champ.strategy == "pair"
        # tap 1/1 succeeded: wilson lb(1,1) < wilson lb(4,4) — no dethrone.
        assert mem.record_run(_rec("tap", "succeeded")) is True
        champ = champ_of(mem)
        assert champ is not None and champ.strategy == "pair"
        mem.close()


def champ_of(mem: AttackMemory):
    return mem.champion("victim-a", "goal-text-alpha")


class TestFailSoftWrites:
    def test_unwritable_path_returns_false_never_raises(self, tmp_path: Path) -> None:
        blocker = tmp_path / "blocker.txt"
        blocker.write_text("a file, not a directory", encoding="utf-8")
        # A DB *under a file* cannot be created -> OSError -> fail-soft.
        mem = AttackMemory(blocker / "mem.sqlite")
        assert mem.record_run(_rec("pair", "succeeded")) is False

    def test_write_failure_does_not_raise_on_record(self, tmp_path: Path) -> None:
        mem = AttackMemory(tmp_path / "mem.sqlite")
        mem._connect().close()
        # Corrupt the DB file after first open.
        (tmp_path / "mem.sqlite").write_bytes(b"not a database at all")
        mem._conn = None  # force reconnect on next use
        assert mem.record_run(_rec("pair", "succeeded")) is False


class TestFailClosedReads:
    def test_corrupt_db_raises_on_selection_read(self, tmp_path: Path) -> None:
        db = tmp_path / "mem.sqlite"
        db.write_bytes(b"garbage bytes, not sqlite")
        mem = AttackMemory(db)
        with pytest.raises(AttackMemoryError):
            mem.strategy_ranking("victim-a", "goal-text-alpha")

    def test_schema_version_mismatch_raises(self, tmp_path: Path) -> None:
        db = tmp_path / "mem.sqlite"
        conn = sqlite3.connect(str(db))
        conn.execute("PRAGMA user_version = 99")
        conn.commit()
        conn.close()
        mem = AttackMemory(db)
        with pytest.raises(AttackMemoryError):
            mem.strategy_ranking("victim-a", "goal-text-alpha")
        # Writes ALSO fail (best-effort -> False), never raise.
        assert mem.record_run(_rec("pair", "succeeded")) is False

    def test_summary_is_explicit_read_raises_when_unusable(self, tmp_path: Path) -> None:
        db = tmp_path / "mem.sqlite"
        db.write_bytes(b"nope")
        mem = AttackMemory(db)
        with pytest.raises(AttackMemoryError):
            mem.summary()


class TestRankLabelsPure:
    def test_excludes_and_orders(self) -> None:
        from neuralstrike.core.attack_memory import StrategyStat

        stats = [
            StrategyStat("no-evidence", 3, 0, 0, 0.0),
            StrategyStat("pair", 4, 4, 2, 0.30),
            StrategyStat("tap", 5, 5, 4, 0.55),
        ]
        ranked = rank_labels(stats)
        assert [s.strategy for s in ranked] == ["tap", "pair"]
        # Floor excludes strategies below it (no-evidence has 0 conclusive).
        assert [s.strategy for s in rank_labels(stats, min_conclusive=5)] == ["tap"]
        # A floor of 4 keeps both (pair has exactly 4).
        assert [s.strategy for s in rank_labels(stats, min_conclusive=4)] == ["tap", "pair"]

    def test_stable_under_input_reordering(self) -> None:
        from neuralstrike.core.attack_memory import StrategyStat

        stats = [
            StrategyStat("a", 2, 2, 1, 0.2),
            StrategyStat("b", 2, 2, 1, 0.2),
            StrategyStat("c", 2, 2, 1, 0.2),
        ]
        forward = [s.strategy for s in rank_labels(stats)]
        assert forward == ["a", "b", "c"]
        assert [s.strategy for s in rank_labels(list(reversed(stats)))] == forward
