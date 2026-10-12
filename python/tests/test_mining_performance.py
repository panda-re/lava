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
    Table("liveness_delta", MetaData(),
          Column("id", Integer, primary_key=True),
          Column("inputfile", Text, nullable=False),
          Column("label", Integer, nullable=False),
          Column("atp_instr", Integer, nullable=False),
          Column("liveness_count", Integer, nullable=False)).create(engine)
    return Session(engine)


def test_snapshot_batches_preserve_contents_and_first_checkpoint(monkeypatch):
    from sqlalchemy import select
    from pyroclastic.taint import find_bug_injection as mining
    from pyroclastic.utils.database_types import LivenessDelta
    monkeypatch.setattr(mining, "MINING_INSERT_BATCH_SIZE", 2)
    monkeypatch.setattr(mining, "last_snapshotted_instr", -1)
    counts = {"first": {1: 0, 2: 3, 3: 5}, "second": {4: 2}}
    counts = {f: mining.LivenessCounts(c) for f, c in counts.items()}
    monkeypatch.setattr(mining, "liveness_by_file", counts)
    with snapshot_session() as session:
        mining.save_liveness_to_db(session, 10)
        counts["first"][2] = 7
        mining.save_liveness_to_db(session, 10)  # Equal instr keeps first state.
        mining.save_liveness_to_db(session, 11)
        rows = session.execute(select(LivenessDelta.inputfile, LivenessDelta.label,
                                      LivenessDelta.atp_instr,
                                      LivenessDelta.liveness_count)
                               .order_by(LivenessDelta.id)).all()
        assert rows == [("first", 1, 10, 0), ("first", 2, 10, 3),
                        ("first", 3, 10, 5), ("second", 4, 10, 2),
                        ("first", 2, 11, 7)]
        timeline = generate_bugs.LivenessTimeline(session, "first")
        timeline.PAGE_SIZE = 2
        assert dict(timeline.at(10)) == {1: 0, 2: 3, 3: 5}
        assert dict(timeline.at(11)) == {1: 0, 2: 7, 3: 5}
        assert dict(timeline.at(12)) == {1: 0, 2: 7, 3: 5}
        assert dict(timeline.at(9)) == {}
        assert dict(timeline.at(10)) == {1: 0, 2: 3, 3: 5}


def test_snapshot_insert_does_not_flush_and_rolls_back(monkeypatch):
    from sqlalchemy import select, func
    from pyroclastic.taint import find_bug_injection as mining
    from pyroclastic.utils.database_types import LivenessDelta
    monkeypatch.setattr(mining, "last_snapshotted_instr", -1)
    monkeypatch.setattr(mining, "liveness_by_file", {"input": mining.LivenessCounts({1: 3})})
    with snapshot_session() as session:
        pending = LivenessDelta(inputfile="pending", label=99, atp_instr=1,
                                   liveness_count=0)
        session.add(pending)
        mining.save_liveness_to_db(session, 10)
        assert pending in session.new
        count = select(func.count()).select_from(LivenessDelta.__table__)
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
    monkeypatch.setattr(mining, "liveness_by_file", {"input": mining.LivenessCounts()})
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


def test_execution_batches_keep_identity_payload_and_order(monkeypatch):
    from sqlalchemy import Column, Integer, MetaData, Table, Text, create_engine, event, select
    from sqlalchemy.orm import Session
    from pyroclastic.taint import find_bug_injection as mining
    from pyroclastic.utils.database_types import AtpExecution
    engine = create_engine("sqlite://")
    table = Table("atp_execution", MetaData(),
                  Column("id", Integer, primary_key=True), Column("atp", Integer),
                  Column("inputfile", Text), Column("instr", Integer),
                  Column("pid", Integer), Column("tid", Integer))
    table.create(engine)
    with engine.begin() as connection:
        connection.execute(table.insert(), dict(atp=8, inputfile="a", instr=1, pid=10, tid=20))
    statements = []
    event.listen(engine, "before_cursor_execute",
                 lambda conn, cursor, statement, params, context, many: statements.append(statement))
    monkeypatch.setattr(mining, "MINING_INSERT_BATCH_SIZE", 2)
    with Session(engine) as session:
        # Existing rows and repeated buffered identities keep their first payload.
        mining.record_atp_execution(session, atp_id=8, inputfile="a", instr=1, pid=99)
        mining.record_atp_execution(session, atp_id=9, inputfile="a", instr=2, pid=30, tid=40)
        mining.record_atp_execution(session, atp_id=9, inputfile="a", instr=2, pid=99)
        mining.record_atp_execution(session, atp_id=9, inputfile="b", instr=2, pid=50, tid=60)
        mining.record_atp_execution(session, atp_id=8, inputfile="a", instr=3, pid=70, tid=80)
        mining.flush_atp_executions(session)
        session.commit()
        assert sum(s.startswith("SELECT") for s in statements) == 2
        assert sum(s.startswith("INSERT") for s in statements) == 2
        rows = session.connection().execute(select(table).order_by(table.c.id)).all()
        assert [tuple(row) for row in rows] == [
            (1, 8, "a", 1, 10, 20), (2, 9, "a", 2, 30, 40),
            (3, 9, "b", 2, 50, 60), (4, 8, "a", 3, 70, 80)]


def test_dua_bytes_cache_and_existing_row_avoid_work():
    from unittest.mock import MagicMock
    session = MagicMock()
    existing = SimpleNamespace(id=10)
    session.query.return_value.filter_by.return_value.first.return_value = existing
    cache = {}
    dua = SimpleNamespace(id=1)  # No viable_bytes: an existing row needs no labels.
    db = SimpleNamespace(session=session)
    assert generate_bugs.get_or_create_dua_bytes(db, cache, dua, Range(0, 4)) is existing
    assert generate_bugs.get_or_create_dua_bytes(db, cache, dua, Range(0, 4)) is existing
    session.query.assert_called_once()
    session.flush.assert_not_called()


def test_dua_bytes_creation_flushes_only_new_row():
    from unittest.mock import MagicMock
    session = MagicMock()
    session.query.return_value.filter_by.return_value.first.return_value = None
    dua = CountingDua()
    dua.id = 1
    cache = {}
    created = generate_bugs.get_or_create_dua_bytes(
        SimpleNamespace(session=session), cache, dua, Range(0, 4))
    assert created.all_labels == [0, 1, 2, 3]
    assert dua.reads == 1
    session.flush.assert_called_once_with([created])
    assert cache[(1, 0, 4)] is created


def test_execution_buffer_commit_and_root_rollback():
    from sqlalchemy import Column, Integer, MetaData, Table, Text, create_engine, select
    from sqlalchemy.orm import Session
    from pyroclastic.taint import find_bug_injection as mining
    engine = create_engine("sqlite://")
    table = Table("atp_execution", MetaData(),
                  Column("id", Integer, primary_key=True), Column("atp", Integer),
                  Column("inputfile", Text), Column("instr", Integer),
                  Column("pid", Integer), Column("tid", Integer))
    table.create(engine)
    with Session(engine) as session:
        mining.record_atp_execution(session, atp_id=1, inputfile="a", instr=1)
        session.rollback()  # Discard buffered rows and their deduplication keys.
        mining.record_atp_execution(session, atp_id=1, inputfile="a", instr=1, pid=7)
        session.commit()  # Commit hook drains the partial batch.
        rows = session.connection().execute(select(table)).all()
        assert [tuple(row) for row in rows] == [(1, 1, "a", 1, 7, 0)]


@pytest.mark.parametrize("malformed", [False, True])
def test_log_import_is_atomic_after_former_commit_boundary(tmp_path, monkeypatch, malformed):
    import json
    from contextlib import contextmanager
    from sqlalchemy import select, func
    from pyroclastic.taint import find_bug_injection as mining
    from pyroclastic.utils.database_types import LivenessDelta

    (tmp_path / "lavadb").write_text("")
    entries = [{"attackPoint": {}, "instr": hex(i)} for i in range(1, 502)]
    encoded = json.dumps(entries)
    # Fail after 501 complete events, beyond the former 500-entry commit.
    log = tmp_path / "queries.json"
    log.write_text(encoded[:-1] + ', {"attackPoint":' if malformed else encoded)
    monkeypatch.setenv("POSTGRES_USER", "test")
    monkeypatch.setenv("POSTGRES_PASSWORD", "test")
    monkeypatch.setattr(mining, "last_snapshotted_instr", -1)
    monkeypatch.setattr(mining, "liveness_by_file", {"input": mining.LivenessCounts({1: 3})})
    session = snapshot_session()

    @contextmanager
    def database(project):
        yield SimpleNamespace(session=session)

    monkeypatch.setattr(mining, "LavaDatabase", database)
    def save_checkpoint(entry, session, *args):
        instr = int(entry["instr"], 0)
        mining.liveness_by_file["input"][1] = instr
        mining.save_liveness_to_db(session, instr)
    monkeypatch.setattr(mining, "attack_point_lval_usage", save_checkpoint)
    try:
        if malformed:
            import ijson
            with pytest.raises(ijson.JSONError):
                mining.parse_panda_log(str(log), {"output_dir": str(tmp_path)})
        else:
            mining.parse_panda_log(str(log), {"output_dir": str(tmp_path)})
        count = session.connection().execute(
            select(func.count()).select_from(LivenessDelta.__table__)).scalar_one()
        assert count == (0 if malformed else 501)
    finally:
        session.close()


@pytest.mark.parametrize("fail", [False, True])
def test_atomic_get_or_create_without_savepoints(monkeypatch, fail):
    from sqlalchemy import Column, Integer, Text, create_engine, event, select, func
    from sqlalchemy.exc import IntegrityError
    from sqlalchemy.orm import Session, declarative_base
    from pyroclastic.taint import find_bug_injection as mining

    base = declarative_base()

    class Entity(base):
        __tablename__ = "entity"
        id = Column(Integer, primary_key=True)
        name = Column(Text, unique=True)
        payload = Column(Integer)

    engine = create_engine("sqlite://")
    base.metadata.create_all(engine)
    statements = []
    event.listen(engine, "before_cursor_execute",
                 lambda conn, cursor, sql, params, context, many: statements.append(sql))
    monkeypatch.setattr(mining, "_L1_CACHE", {})
    with Session(engine) as session:
        def import_entities():
            with session.begin():
                session.info["atomic_mining"] = True
                first = mining.get_or_create(session, Entity, name="a", defaults={"payload": 1})
                again = mining.get_or_create(session, Entity, name="a", defaults={"payload": 99})
                assert again is first
                assert first.payload == 1
                second = mining.get_or_create(session, Entity, name="b", defaults={"payload": 2})
                assert second.id > first.id
                if fail:
                    session.add(Entity(name="a", payload=3))
                    session.flush()
        if fail:
            with pytest.raises(IntegrityError):
                import_entities()
        else:
            import_entities()
        assert not any("SAVEPOINT" in sql for sql in statements)
        assert sum(sql.startswith("SELECT") for sql in statements) == 2
        assert session.execute(select(func.count()).select_from(Entity)).scalar_one() == (0 if fail else 2)


def test_delta_reconstruction_matches_full_snapshots(monkeypatch):
    import random
    from sqlalchemy import select, func
    from pyroclastic.taint import find_bug_injection as mining
    from pyroclastic.utils.database_types import LivenessDelta
    rng = random.Random(1234)
    monkeypatch.setattr(mining, "last_snapshotted_instr", -1)
    monkeypatch.setattr(mining, "MINING_INSERT_BATCH_SIZE", 3)
    counts = {"a": {}, "b": {0: 0}}
    counts = {f: mining.LivenessCounts(c) for f, c in counts.items()}
    monkeypatch.setattr(mining, "liveness_by_file", counts)
    baseline = []
    with snapshot_session() as session:
        for instr in range(100):
            for _ in range(rng.randrange(4)):
                filename = rng.choice(["a", "b"])
                label = rng.randrange(12)
                counts[filename][label] = counts[filename].get(label, 0) + 1
            mining.save_liveness_to_db(session, instr)
            baseline.append({f: dict(c) for f, c in counts.items()})
            # Changes at the same instr must wait for the next saved checkpoint.
            counts["a"][99] = counts["a"].get(99, 0) + 1
            mining.save_liveness_to_db(session, instr)
        timelines = {f: generate_bugs.LivenessTimeline(session, f) for f in counts}
        for timeline in timelines.values():
            timeline.PAGE_SIZE = 3
        for instr, checkpoint in enumerate(baseline):
            for filename, timeline in timelines.items():
                assert dict(timeline.at(instr)) == checkpoint[filename]
        stored = session.execute(select(func.count()).select_from(LivenessDelta)).scalar_one()
        full_rows = sum(len(c) for checkpoint in baseline for c in checkpoint.values())
        assert stored < full_rows


def test_delta_failed_insert_does_not_advance_comparison_state(monkeypatch):
    from unittest.mock import MagicMock
    from pyroclastic.taint import find_bug_injection as mining
    monkeypatch.setattr(mining, "last_snapshotted_instr", -1)
    monkeypatch.setattr(mining, "liveness_by_file", {"a": mining.LivenessCounts({1: 2})})
    session = MagicMock()
    session.info = {}
    session.connection.return_value.execute.side_effect = RuntimeError("write failed")
    with pytest.raises(RuntimeError, match="write failed"):
        mining.save_liveness_to_db(session, 10)
    assert session.info["mining_liveness_counts"] == {"a": {}}
    assert mining.last_snapshotted_instr == -1


def test_dirty_labels_include_missing_zero_and_deferred_changes(monkeypatch):
    from pyroclastic.taint import find_bug_injection as mining
    monkeypatch.setattr(mining, "last_snapshotted_instr", -1)
    counts = mining.LivenessCounts()
    monkeypatch.setattr(mining, "liveness_by_file", {"a": counts})
    assert counts[7] == 0
    with snapshot_session() as session:
        mining.save_liveness_to_db(session, 10)
        assert not counts.dirty
        counts[7] += 1
        counts[8] += 1
        mining.save_liveness_to_db(session, 10)
        assert set(counts.dirty) == {7, 8}
        mining.save_liveness_to_db(session, 11)
        assert not counts.dirty
        timeline = generate_bugs.LivenessTimeline(session, "a")
        assert dict(timeline.at(10)) == {7: 0}
        assert dict(timeline.at(11)) == {7: 1, 8: 1}


def test_unchanged_checkpoint_does_not_scan_all_labels(monkeypatch):
    from pyroclastic.taint import find_bug_injection as mining
    from unittest.mock import MagicMock

    class NoFullScan(mining.LivenessCounts):
        def items(self):
            raise AssertionError("checkpoint scanned every label")

        def __iter__(self):
            raise AssertionError("checkpoint copied every label")

    monkeypatch.setattr(mining, "last_snapshotted_instr", -1)
    counts = NoFullScan({i: 0 for i in range(1000)})
    monkeypatch.setattr(mining, "liveness_by_file", {"a": counts})
    session = MagicMock()
    session.info = {}
    mining.save_liveness_to_db(session, 10)
    session.connection.return_value.execute.reset_mock()
    mining.save_liveness_to_db(session, 11)
    session.connection.return_value.execute.assert_not_called()
    counts[999] = 3
    mining.save_liveness_to_db(session, 12)
    rows = session.connection.return_value.execute.call_args.args[1]
    assert rows == [dict(inputfile="a", label=999, atp_instr=12, liveness_count=3)]
