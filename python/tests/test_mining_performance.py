"""Regression checks for mining optimizations that must preserve selection."""
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from pyroclastic.taint import generate_bugs, taint_utils
from pyroclastic.utils.database_types import BugKind, Range


class CountingDua:
    lval_relationship = SimpleNamespace(ast_name="value")

    def __init__(self):
        self.reads = 0

    @property
    def viable_bytes(self):
        self.reads += 1
        return [SimpleNamespace(labels=[i]) for i in range(4)]

    def __str__(self):
        raise AssertionError("disabled debug must not render a DUA")


def test_dead_range_without_debug():
    dua = CountingDua()
    assert taint_utils.get_dua_dead_range(
        dua, [], {}, {"debug": False, "max_liveness": 0}
    ) == Range(0, 4)
    assert dua.reads == 1


@pytest.mark.parametrize("instructions, expected", [
    ([1, 1, 2], [3]),
    ([1, 2, 2], []),  # One prior DUA fails the historical strict 1 < end_index.
    ([1, 1, 1], []),
    ([1, 2, 3, 3], [3, 4]),
])
def test_extra_selection_strict_prior_boundary(instructions, expected):
    accepted = []
    duas = [SimpleNamespace(id=i + 1, instr=instr, lval=i + 1, fake_dua=False)
            for i, instr in enumerate(instructions)]

    def dua_bytes(db, cache, dua, selected):
        return SimpleNamespace(id=dua.id, all_labels=list(range(dua.id * 4, dua.id * 4 + 4)))

    with patch.object(generate_bugs, "get_dua_dead_range", return_value=Range(0, 4)), \
            patch.object(generate_bugs, "get_or_create_dua_bytes", side_effect=dua_bytes), \
            patch.object(generate_bugs, "Bug", side_effect=lambda **kw: kw):
        generate_bugs._get_or_create_bug_like_cpp(
            db=SimpleNamespace(session=SimpleNamespace(add=accepted.append)),
            dua_bytes_cache={}, atp=SimpleNamespace(id=1),
            bug_type=BugKind.BUG_RET_BUFFER, stackoff=0,
            available_duas=duas, offline_liveness={}, project_data={}, is_new_atp=True,
        )

    assert [bug["trigger"].id for bug in accepted] == expected
    assert all(bug["extra_duas"] == [1] for bug in accepted)


def snapshot_session():
    """Use SQLite for the scalar snapshot table, without PostgreSQL-only mappings."""
    from sqlalchemy import Column, Integer, MetaData, Table, Text, create_engine
    from sqlalchemy.orm import Session
    engine = create_engine("sqlite://")
    Table("liveness_snapshot", MetaData(),
          Column("id", Integer, primary_key=True),
          Column("inputfile", Text, nullable=False),
          Column("label", Integer, nullable=False),
          Column("atp_instr", Integer, nullable=False),
          Column("liveness_count", Integer, nullable=False)).create(engine)
    return Session(engine)


def test_snapshot_batches_preserve_contents_and_first_checkpoint(monkeypatch):
    from sqlalchemy import select
    from pyroclastic.taint import find_bug_injection as mining
    from pyroclastic.utils.database_types import LivenessSnapshot
    monkeypatch.setattr(mining, "LIVENESS_INSERT_BATCH_SIZE", 2)
    monkeypatch.setattr(mining, "last_snapshotted_instr", -1)
    counts = {"first": {1: 0, 2: 3, 3: 5}, "second": {4: 2}}
    monkeypatch.setattr(mining, "liveness_by_file", counts)
    with snapshot_session() as session:
        mining.save_liveness_to_db(session, 10)
        counts["first"][2] = 7
        mining.save_liveness_to_db(session, 10)  # Equal instr keeps first state.
        mining.save_liveness_to_db(session, 11)
        rows = session.execute(select(LivenessSnapshot.inputfile, LivenessSnapshot.label,
                                      LivenessSnapshot.atp_instr,
                                      LivenessSnapshot.liveness_count)
                               .order_by(LivenessSnapshot.id)).all()
        assert rows == [("first", 1, 10, 0), ("first", 2, 10, 3),
                        ("first", 3, 10, 5), ("second", 4, 10, 2),
                        ("first", 1, 11, 0), ("first", 2, 11, 7),
                        ("first", 3, 11, 5), ("second", 4, 11, 2)]


def test_snapshot_insert_does_not_flush_and_rolls_back(monkeypatch):
    from sqlalchemy import select, func
    from pyroclastic.taint import find_bug_injection as mining
    from pyroclastic.utils.database_types import LivenessSnapshot
    monkeypatch.setattr(mining, "last_snapshotted_instr", -1)
    monkeypatch.setattr(mining, "liveness_by_file", {"input": {1: 3}})
    with snapshot_session() as session:
        pending = LivenessSnapshot(inputfile="pending", label=99, atp_instr=1,
                                   liveness_count=0)
        session.add(pending)
        mining.save_liveness_to_db(session, 10)
        assert pending in session.new
        count = select(func.count()).select_from(LivenessSnapshot.__table__)
        assert session.connection().execute(count).scalar_one() == 1
        session.rollback()
        assert session.connection().execute(count).scalar_one() == 0


def test_active_dua_removal_preserves_survivor_order(monkeypatch):
    from collections import defaultdict
    from pyroclastic.taint import find_bug_injection as mining

    class ActiveDua:
        def __init__(self, lval):
            self.lval_relationship = SimpleNamespace(id=lval)
            self.all_labels = [7]
            self.death_instr = None

    first, dead, last = [ActiveDua(i) for i in range(3)]
    monkeypatch.setattr(mining, "recent_dead_duas", {0: first, 1: dead, 2: last})
    monkeypatch.setattr(mining, "recent_duas_by_instr", dict.fromkeys([first, dead, last]))
    monkeypatch.setattr(mining, "dua_dependencies", {7: {first, dead, last}})
    monkeypatch.setattr(mining, "liveness_by_file", {"input": defaultdict(int)})
    monkeypatch.setattr(mining, "ptr_to_labelset", {1: SimpleNamespace(labels=[7])})
    monkeypatch.setattr(mining, "is_dua_dead", lambda dua, *args: dua is not dead)
    monkeypatch.setattr(mining, "save_liveness_to_db", lambda *args: None)
    mining.update_liveness({"instr": "0x10", "taintedBranch": {"taintQuery": [{"ptr": 1}]}},
                           None, {"input_file": "input"})
    assert list(mining.recent_duas_by_instr) == [first, last]
    assert list(mining.recent_dead_duas.values()) == [first, last]
    assert dead.death_instr == 16
    # Preserve C++'s whole-bucket removal, including surviving shared dependencies.
    assert mining.dua_dependencies == {}
