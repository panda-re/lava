"""Regression checks for input identity and repeat parsing."""
from unittest.mock import Mock, patch

import pytest

from sqlalchemy.orm import configure_mappers
from pyroclastic.utils.database_types import Dua, FileTaint, SourceTrace
from pyroclastic.taint import find_bug_injection as fbi


def test_trace_relationship_is_scoped_to_file_taint():
    configure_mappers()
    join = str(Dua.source_trace_relationship.property.primaryjoin)
    assert 'dua.inputfile = sourcetrace.file_taint' in join
    constraint = next(c for c in SourceTrace.__table__.constraints if c.name == 'SourceTraceUniq')
    assert {c.name for c in constraint.columns} == {'file_taint', 'index'}


def test_input_identity_includes_path_hash_and_command():
    constraint = next(c for c in FileTaint.__table__.constraints if c.name == 'FileTaintUniq')
    assert {c.name for c in constraint.columns} == {'filename', 'sha256', 'command'}


def test_labelset_lookup_includes_input():
    fbi.ptr_to_labelset.clear()
    try:
        with patch.object(fbi, 'get_or_create', return_value=Mock()) as lookup:
            fbi.update_unique_taint_sets({'ptr': '0x12', 'label': ['0x1']}, Mock(),
                                         {'file_taint_id': 7, 'debug': False})
            assert lookup.call_args.kwargs['inputfile'] == 7
            assert 'inputfile' not in lookup.call_args.kwargs['defaults']
    finally:
        fbi.ptr_to_labelset.clear()


def test_snapshots_keep_first_equal_instruction_checkpoint():
    fbi.liveness_by_file.clear()
    fbi.last_snapshotted_instr = -1
    fbi.liveness_by_file['/seed/one'] = fbi.LivenessCounts({3: 2})
    try:
        session = Mock(info={})
        fbi.save_liveness_to_db(session, 10)
        fbi.save_liveness_to_db(session, 10)
        session.connection.return_value.execute.assert_called_once()
        assert session.connection.return_value.execute.call_args.args[1] == [
            dict(inputfile='/seed/one', label=3, atp_instr=10, liveness_count=2)]
    finally:
        fbi.liveness_by_file.clear()
        fbi.last_snapshotted_instr = -1


def test_completed_input_skips_panda_and_copy(tmp_path):
    from pyroclastic.taint import bug_mining
    inputs = tmp_path / 'inputs'
    inputs.mkdir()
    (inputs / 'seed').write_bytes(b'input')
    database = Mock()
    database.session.query.return_value.filter_by.return_value.first.return_value = Mock(complete=True)
    project = {'config_dir': str(tmp_path), 'output_dir': str(tmp_path / 'output'),
               'command': '{install_dir}/bin/tool --input {input_file} --flag'}
    with patch.object(bug_mining, 'LavaDatabase') as db, patch.object(bug_mining, 'Panda') as panda:
        db.return_value.__enter__.return_value = database
        bug_mining.run_taint_pipeline(project)
        panda.assert_not_called()
        database.session.add.assert_not_called()
        assert not (tmp_path / 'output').exists()


def test_new_input_tracks_path_hash_and_raw_command_without_archiving(tmp_path, monkeypatch):
    import hashlib
    from pyroclastic.taint import bug_mining
    inputs = tmp_path / 'inputs'
    inputs.mkdir()
    source = inputs / 'seed with spaces'
    source.write_bytes(b'input')
    output = tmp_path / 'output'
    output.mkdir()
    database = Mock()
    database.session.query.return_value.filter_by.return_value.first.return_value = None
    project = {'config_dir': str(tmp_path), 'output_dir': str(output), 'name': 'test',
               'tarfile': 'target.tar', 'command': '{install_dir}/bin/tool --input {input_file} --flag',
               'qemu': 'i386'}
    monkeypatch.chdir(tmp_path)
    with patch.object(bug_mining, 'LavaDatabase') as db, \
         patch.object(bug_mining.subprocess, 'check_output', return_value=b'target/\n'), \
         patch.object(bug_mining, 'Panda', side_effect=RuntimeError('stop before recording')):
        db.return_value.__enter__.return_value = database
        with pytest.raises(RuntimeError, match='stop before recording'):
            bug_mining.run_taint_pipeline(project)
    row = database.session.add.call_args.args[0]
    assert row.filename == str(source)
    assert row.sha256 == hashlib.sha256(b'input').hexdigest()
    assert row.command == project['command']
    assert row.complete is False
    assert not (output / 'mined-inputs').exists()
    assert source.read_bytes() == b'input'


def test_record_filters_inputs_and_parse_reuses_log_without_panda(tmp_path, monkeypatch):
    from pyroclastic.taint import bug_mining
    inputs = tmp_path / 'inputs'
    inputs.mkdir()
    (inputs / 'done').write_bytes(b'old')
    source = inputs / 'new input'
    source.write_bytes(b'new')
    output = tmp_path / 'output'
    output.mkdir()
    database = Mock()
    database.session.query.return_value.filter_by.side_effect = lambda **identity: Mock(
        first=lambda: Mock(complete=True) if identity['filename'].endswith('/done') else None)
    project = dict(config_dir=str(tmp_path), output_dir=str(output), name='test',
                   tarfile='target.tar', command='{install_dir}/bin/tool --input {input_file} --flag',
                   qemu='i386', complete_rr=False, lava_mode='lava1')
    panda = Mock()
    panda.run.side_effect = lambda: panda.queue_blocking.call_args.args[0]()
    monkeypatch.chdir(tmp_path)
    with patch.object(bug_mining, 'LavaDatabase') as db, \
         patch.object(bug_mining.subprocess, 'check_output', return_value=b'target/\n'), \
         patch.object(bug_mining, 'Panda', return_value=panda) as factory, \
         patch.object(bug_mining, 'parse_panda_log') as parse, \
         patch.object(bug_mining, 'record_injectable_bugs_offline'), \
         patch.object(bug_mining, 'print_bug_stats'), patch.object(bug_mining, 'print_phase2_stats'):
        db.return_value.__enter__.return_value = database
        bug_mining.run_taint_pipeline(project, steps=['record'])
        factory.assert_called_once()
        command = panda.record_cmd.call_args.kwargs['guest_command']
        guest_input = output / 'target' / 'lava-install' / 'inputs' / source.name
        assert '--input "$f" --flag' in command
        assert f"{guest_input.parent}/*" in command
        assert guest_input.read_bytes() == b'new'
        assert not (guest_input.parent / 'done').exists()
        bug_mining.run_taint_pipeline(project, steps=['parse'])
        factory.assert_called_once()  # Parsing must not open PANDA's QCOW.
        log_path = parse.call_args.args[0]
        bug_mining.run_taint_pipeline(project, steps=['parse'])
        assert parse.call_args.args[0] == log_path

        # Preserve the original default behavior: an existing JSON bypasses recording/replay.
        (output / 'queries-test.json').write_text('[]')
        bug_mining.run_taint_pipeline(project)
        assert parse.call_args.args[0] == str(output / 'queries-test.json')
        factory.assert_called_once()  # JSON reuse must not construct another PANDA.
        assert panda.run.call_count == 1
        panda.run_replay.assert_not_called()


@pytest.mark.parametrize('malformed', [False, True])
def test_import_marks_only_observed_inputs_complete_atomically(tmp_path, monkeypatch, malformed):
    import json
    from contextlib import contextmanager
    from types import SimpleNamespace
    import ijson
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import Session

    engine = create_engine('sqlite://')
    FileTaint.__table__.create(engine)
    inputs = tmp_path / 'inputs'
    inputs.mkdir()
    for key in ('one', 'two', 'unseen'):
        (inputs / key).write_text(key)
    with Session(engine) as session:
        session.add_all([FileTaint(id=i, **FileTaint.identity(inputs / key, 'tool {input_file}'), complete=False)
                         for i, key in enumerate(('one', 'two', 'unseen'), start=1)])
        session.commit()
    events = [dict(fileTaintMatch=dict(filename='/guest/one'))] * 20 + [
              dict(sourceTraceId={}), dict(fileTaintMatch=dict(filename='/guest/two')),
              dict(sourceTraceId={})]
    encoded = json.dumps(events)
    log = tmp_path / 'queries.json'
    log.write_text(encoded[:-1] + ', {' if malformed else encoded)
    (tmp_path / 'lavadb').write_text('')
    monkeypatch.setenv('POSTGRES_USER', 'test')
    monkeypatch.setenv('POSTGRES_PASSWORD', 'test')
    scopes = []
    monkeypatch.setattr(fbi, 'record_trace', lambda ple, lava_db, session, index, scope:
                        scopes.append((index, scope)))

    @contextmanager
    def database(project):
        with Session(engine) as session:
            yield SimpleNamespace(session=session)

    monkeypatch.setattr(fbi, 'LavaDatabase', database)
    identity = Mock(wraps=FileTaint.identity)
    monkeypatch.setattr(FileTaint, 'identity', identity)
    project = dict(output_dir=str(tmp_path), config_dir=str(tmp_path), command='tool {input_file}')
    if malformed:
        with pytest.raises(ijson.JSONError):
            fbi.parse_panda_log(str(log), project)
    else:
        fbi.parse_panda_log(str(log), project)
    with Session(engine) as session:
        completed = dict(session.execute(select(FileTaint.id, FileTaint.complete)).all())
    assert completed == {1: not malformed, 2: not malformed, 3: False}
    assert scopes == [(0, 1), (0, 2)]
    assert project["file_taint_id"] == 2
    assert "input_file" not in project
    assert identity.call_count == 2  # Repeated opens must not rehash the corpus.


def test_atp_identity_is_static_and_execution_owns_context():
    from pyroclastic.utils.database_types import AttackPoint, AtpExecution, CallTrace
    constraint = next(c for c in AttackPoint.__table__.constraints if c.name == 'AttackPointUniq')
    assert {c.name for c in constraint.columns} == {
        'loc_filename', 'loc_begin_line', 'loc_begin_column',
        'loc_end_line', 'loc_end_column', 'type'}
    for field in ('calltrace', 'stack_offset', 'trace_index'):
        assert field not in AttackPoint.__table__.columns
        assert field in AtpExecution.__table__.columns
    assert 'file_taint' not in AttackPoint.__table__.columns
    assert {c.name for c in CallTrace.__table__.columns} == {'id', 'caller', 'file'}


def test_chaff_injection_uses_the_selected_execution_call_stack(tmp_path):
    from types import SimpleNamespace
    from pyroclastic.inject.dataflow import genStackVarHelper
    from pyroclastic.utils.database_types import Bug, CallTrace
    bugs = [SimpleNamespace(atp=1, execution=SimpleNamespace(calltrace=[11])),
            SimpleNamespace(atp=1, execution=SimpleNamespace(calltrace=[22]))]
    traces = {11: SimpleNamespace(caller='target!first'), 22: SimpleNamespace(caller='target!second')}
    bug_query = Mock()
    bug_query.filter.return_value = bug_query
    bug_query.all.return_value = bugs
    db = SimpleNamespace(session=SimpleNamespace(query=lambda model:
        bug_query if model is Bug else SimpleNamespace(get=traces.get)))
    whitelist = tmp_path / 'whitelist'
    genStackVarHelper(db, [1, 2], str(whitelist))
    assert whitelist.read_text().splitlines() == ['NOFILENAME addvar first', 'NOFILENAME addvar second']


@pytest.mark.parametrize('mode', ['lava1', 'lava2'])
def test_generation_filters_current_command_without_option(mode):
    from types import SimpleNamespace
    from pyroclastic.taint import generate_bugs
    query = Mock()
    for method in ('join', 'filter', 'distinct', 'order_by', 'options'):
        getattr(query, method).return_value = query
    query.all.return_value = []
    session = Mock()
    session.query.return_value = query
    with patch.object(generate_bugs, 'LavaDatabase') as database:
        database.return_value.__enter__.return_value = SimpleNamespace(session=session)
        getattr(generate_bugs, '_record_injectable_bugs_offline_' + mode)({'command': 'tool {input_file}'})
    predicates = query.filter.call_args.args
    assert any('filetaint.command' in str(predicate) and
               predicate.right.value == 'tool {input_file}' for predicate in predicates)
    assert any('filetaint.complete IS true' in str(predicate) for predicate in predicates)


@pytest.mark.parametrize('steps', [None, ['parse'], ['record'], ['replay']])
def test_precomputed_json_avoids_qcow_download_unless_live_step_requested(tmp_path, monkeypatch, steps):
    from pyroclastic.taint import bug_mining
    inputs = tmp_path / 'inputs'
    inputs.mkdir()
    (inputs / 'seed').write_bytes(b'input')
    output = tmp_path / 'output'
    output.mkdir()
    log = output / 'queries-test.json'
    log.write_text('[]')
    database = Mock()
    database.session.query.return_value.filter_by.return_value.first.return_value = None
    project = dict(config_dir=str(tmp_path), output_dir=str(output), name='test',
                   tarfile='target.tar', command='tool {input_file}', qemu='x86_64', lava_mode='lava1')
    monkeypatch.chdir(tmp_path)
    with patch.object(bug_mining, 'LavaDatabase') as db, \
         patch.object(bug_mining.subprocess, 'check_output', return_value=b'target/\n'), \
         patch.object(bug_mining, 'Panda', side_effect=RuntimeError('PANDA would download QCOW')) as panda, \
         patch.object(bug_mining, 'parse_panda_log') as parse, \
         patch.object(bug_mining, 'record_injectable_bugs_offline'), \
         patch.object(bug_mining, 'print_bug_stats'), patch.object(bug_mining, 'print_phase2_stats'):
        db.return_value.__enter__.return_value = database
        if steps in (['record'], ['replay']):
            with pytest.raises(RuntimeError, match='PANDA would download QCOW'):
                bug_mining.run_taint_pipeline(project, steps=steps)
            panda.assert_called_once()
            parse.assert_not_called()
        else:
            bug_mining.run_taint_pipeline(project, steps=steps)
            panda.assert_not_called()
            parse.assert_called_once_with(str(log), project)
