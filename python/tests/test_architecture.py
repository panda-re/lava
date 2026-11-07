"""Mixed-target selection and injection boundaries; no running Postgres needed."""
import unittest
from collections import defaultdict
from types import SimpleNamespace
from unittest.mock import Mock, patch

from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from pyroclastic.utils.database_types import FileTaint, LavaDatabase, Bug, BugKind, SourceLval, Dua, LabelSet, Range
from pyroclastic.taint.generate_bugs import BugSkipCache
from pyroclastic.inject import inject


class ArchitectureTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine('sqlite://')
        self.session = Session(self.engine)
        FileTaint.__table__.create(self.engine)
        # Only scalar columns are needed here; production arrays remain PostgreSQL types.
        with self.engine.begin() as c:
            for ddl in (
                'CREATE TABLE dua (id INTEGER PRIMARY KEY, inputfile INTEGER, fake_dua BOOLEAN, lval INTEGER)',
                'CREATE TABLE duabytes (id INTEGER PRIMARY KEY, dua INTEGER)',
                'CREATE TABLE bug (id INTEGER PRIMARY KEY, trigger INTEGER, trigger_lval INTEGER, atp INTEGER, type INTEGER)',
                'CREATE TABLE build (id INTEGER PRIMARY KEY)',
                'CREATE TABLE build_bugs (object_id INTEGER, value INTEGER)',
                'CREATE TABLE run (fuzzed INTEGER)',
                'CREATE TABLE sourcelval (id INTEGER PRIMARY KEY, ast_name TEXT)',
            ):
                c.execute(text(ddl))
            for i, (arch, command, complete) in enumerate((
                ('x86_64', 'tool {input_file}', True),
                ('aarch64', 'tool {input_file}', True),
                ('aarch64', 'other {input_file}', True),
                ('aarch64', 'tool {input_file}', False),
            ), 1):
                c.execute(FileTaint.__table__.insert(), dict(
                    id=i, filename=f'/seed/{i}', sha256='same', command=command,
                    architecture=arch, complete=complete))
                c.execute(text('INSERT INTO dua VALUES (:i, :i, 0, 9)'), dict(i=i))
                c.execute(text('INSERT INTO duabytes VALUES (:i, :i)'), dict(i=i))
                c.execute(text('INSERT INTO bug VALUES (:i, :i, 9, 8, 0)'), dict(i=i))
            c.execute(text("INSERT INTO sourcelval VALUES (9, 'lava_chaff_value')"))
        self.db = object.__new__(LavaDatabase)
        self.db.session = self.session
        self.db.project = dict(qemu='aarch64', command='tool {input_file}')

    def tearDown(self):
        self.session.close()
        self.engine.dispose()

    def test_scoped_selection_and_type_filter(self):
        self.assertEqual(self.db.uninjected().with_entities(Bug.id).all(), [(2,)])
        self.assertEqual(self.db.uninjected2(False, [BugKind.BUG_PTR_ADD]).with_entities(Bug.id).all(), [(2,)])
        self.assertEqual(self.db.uninjected2(False, [BugKind.BUG_RET_BUFFER]).with_entities(Bug.id).count(), 0)
        self.db.project['qemu'] = 'x86_64'
        self.assertEqual(self.db.uninjected().with_entities(Bug.id).all(), [(1,)])

    def test_balancing_ignores_types_from_other_targets(self):
        self.session.execute(text('UPDATE bug SET type = 1 WHERE id = 1'))
        with patch.object(self.db, 'uninjected_random', side_effect=lambda fake:
                          self.db.uninjected2(fake).with_entities(Bug.id)):
            selected = self.db.uninjected_random_balance(
                False, 1, [BugKind.BUG_PTR_ADD, BugKind.BUG_RET_BUFFER])
        self.assertEqual([row.id for row in selected], [2])

    def test_skip_cache_does_not_suppress_other_target(self):
        # The only existing bug is x86; AArch64 must be free to claim the same lval.
        self.session.execute(text('DELETE FROM bug WHERE id != 1'))
        self.assertEqual(BugSkipCache(self.db).snapshot(8, BugKind.BUG_PTR_ADD), set())
        self.db.project['qemu'] = 'x86_64'
        self.assertEqual(BugSkipCache(self.db).snapshot(8, BugKind.BUG_PTR_ADD), {9})

    def test_cleanup_only_active_target_and_command(self):
        inject.nuke_invalid_lava_bugs(self.db)
        self.assertEqual(self.session.execute(text('SELECT id FROM bug ORDER BY id')).scalars().all(), [1, 3, 4])

    def test_same_input_has_separate_completion_by_architecture(self):
        base = dict(filename='/same', sha256='hash', command='tool {input_file}')
        self.session.add_all([FileTaint(id=5, **base, architecture='x86_64', complete=True),
                              FileTaint(id=6, **base, architecture='aarch64', complete=False)])
        self.session.commit()
        self.assertFalse(self.session.query(FileTaint).filter_by(**base, architecture='aarch64').one().complete)
        self.session.add(FileTaint(id=7, **base, architecture='aarch64', complete=False))
        with self.assertRaises(IntegrityError):
            self.session.commit()
        self.session.rollback()

    def test_source_identity_has_no_observed_width(self):
        self.assertNotIn('len_bytes', SourceLval.__table__.columns)
        lval = SourceLval(id=1, ast_name='ptr')
        short = Dua(lval_relationship=lval, length=4)
        wide = Dua(lval_relationship=lval, length=8)
        self.assertIs(short.lval_relationship, wide.lval_relationship)
        self.assertEqual((short.length, wide.length), (4, 8))


class ObservedWidthTests(unittest.TestCase):
    def test_importer_stores_capped_width_on_each_observation(self):
        from pyroclastic.taint import find_bug_injection as mining
        created = []
        lval = SourceLval(id=9, ast_name='value')
        def lookup(session, model, defaults=None, **identity):
            if model is SourceLval:
                return lval
            row = model(id=len(created) + 1, **identity, **(defaults or {}))
            created.append(row)
            return row
        project = dict(file_taint_id=1, max_lval_size=8, max_tcn=10, max_cardinality=10)
        queries = [dict(offset=i, ptr=hex(i + 1), tcn=0) for i in range(4)]
        labels = {i + 1: LabelSet(id=i + 1, labels=[i]) for i in range(4)}
        with patch.multiple(mining, ptr_to_labelset=labels, dua_dependencies=defaultdict(set),
                            recent_dead_duas={}, recent_duas_by_instr={},
                            liveness_by_file={1: {}}, num_real_duas=0), \
             patch.object(mining, 'get_or_create', side_effect=lookup), \
             patch.object(mining, 'get_dead_range', return_value=Range(0, 4)), \
             patch.object(mining, 'record_calltrace', return_value=[]), \
             patch.object(mining, 'record_atp_execution'), patch.object(mining, 'save_liveness_to_db'):
            for instr, width in [(1, 4), (2, 16)]:
                event = dict(instr=hex(instr), taintQueryPri=dict(
                    len=width, numTainted=4, taintQuery=queries,
                    srcInfo=dict(filename='toy.c', astLocId=1, astnodename='value')))
                mining.taint_query_pri(event, Mock(), {1: '1:1:1:5:toy.c'}, project, instr)
        observations = [row for row in created if isinstance(row, Dua)]
        self.assertEqual([row.length for row in observations], [4, 8])
        self.assertEqual([len(row.byte_tcn) for row in observations], [4, 8])
        self.assertEqual([row.lval for row in observations], [9, 9])


class InjectionTargetTests(unittest.TestCase):
    def setUp(self):
        self.project = dict(qemu='aarch64', command='tool {input_file}')
        self.source = SimpleNamespace(architecture='aarch64', command='tool {input_file}', complete=True)
        self.bug = SimpleNamespace(id=7, extra_duas=[], execution=None,
            trigger_relationship=SimpleNamespace(dua_relationship=SimpleNamespace(file_taint=self.source)))
        self.db = SimpleNamespace(project=self.project, session=Mock())

    def validate(self):
        with patch.object(inject, 'get_bugs', return_value=[self.bug]):
            return inject.validate_bug_targets(self.db, [7])

    def test_matching_bug_may_already_have_builds(self):
        self.bug.builds = [object()]
        self.assertEqual(self.validate(), [self.bug])

    def test_reject_trigger_command_architecture_and_incomplete(self):
        for field, wrong in [('architecture', 'x86_64'), ('command', 'other'), ('complete', False)]:
            old = getattr(self.source, field)
            setattr(self.source, field, wrong)
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate()
            setattr(self.source, field, old)

    def test_reject_wrong_extra_and_execution(self):
        wrong = SimpleNamespace(architecture='arm', command=self.project['command'], complete=True)
        self.bug.extra_duas = [10]
        self.db.session.get.return_value = SimpleNamespace(dua_relationship=SimpleNamespace(file_taint=wrong))
        with self.assertRaises(ValueError):
            self.validate()
        self.bug.extra_duas = []
        self.bug.execution = SimpleNamespace(input=wrong)
        with self.assertRaises(ValueError):
            self.validate()

    def test_reject_missing_id(self):
        with patch.object(inject, 'get_bugs', return_value=[]), self.assertRaises(ValueError):
            inject.validate_bug_targets(self.db, [99])

    def test_validation_rejects_before_execution(self):
        self.source.architecture = 'x86_64'
        with patch.object(inject, 'get_bugs', return_value=[self.bug]), \
             patch.object(inject, 'run_modified_program') as run, self.assertRaises(ValueError):
            inject.validate_bugs([7], self.db, SimpleNamespace(), self.project,
                                 [], SimpleNamespace(), SimpleNamespace())
        run.assert_not_called()

    def test_inject_rejects_before_filesystem_changes(self):
        self.source.architecture = 'x86_64'
        with patch.object(inject, 'get_bugs', return_value=[self.bug]), \
             patch.object(inject.os.path, 'exists') as exists, self.assertRaises(ValueError):
            inject.inject_bugs([7], self.db, SimpleNamespace(), self.project, SimpleNamespace())
        exists.assert_not_called()


if __name__ == '__main__':
    unittest.main()
