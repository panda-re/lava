"""Regression checks for input identity and repeat parsing."""
from unittest.mock import Mock, patch

import pytest

from sqlalchemy.orm import configure_mappers
from pyroclastic.utils.database_types import Dua, FileTaint, SourceTrace
from pyroclastic.taint import find_bug_injection as fbi


def test_trace_relationship_is_scoped_to_recording():
    configure_mappers()
    join = str(Dua.source_trace_relationship.property.primaryjoin)
    assert 'dua.recording = sourcetrace.recording' in join
    constraint = next(c for c in SourceTrace.__table__.constraints if c.name == 'SourceTraceUniq')
    assert {c.name for c in constraint.columns} == {'recording', 'index'}


def test_input_identity_includes_path_hash_and_command():
    constraint = next(c for c in FileTaint.__table__.constraints if c.name == 'FileTaintUniq')
    assert {c.name for c in constraint.columns} == {'filename', 'sha256', 'command'}


def test_labelset_lookup_includes_input():
    fbi.ptr_to_labelset.clear()
    try:
        with patch.object(fbi, 'get_or_create', return_value=Mock()) as lookup:
            fbi.update_unique_taint_sets({'ptr': '0x12', 'label': ['0x1']}, Mock(),
                                         {'input_file': '/seed/one', 'debug': False})
            assert lookup.call_args.kwargs['inputfile'] == '/seed/one'
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
               'command': '{install_dir}/bin/tool --input {input_file} --flag', 'use_c_fbi': False}
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
        assert f"--input '{guest_input}' --flag" in command
        assert guest_input.read_bytes() == b'new'
        assert not (guest_input.parent / 'done').exists()
        manifest = dict(project['mining_inputs'])
        bug_mining.run_taint_pipeline(project, steps=['parse'])
        factory.assert_called_once()  # Parsing must not open PANDA's QCOW.
        log_path = parse.call_args.args[0]
        assert manifest == project['mining_inputs']
        bug_mining.run_taint_pipeline(project, steps=['parse'])
        assert parse.call_args.args[0] == log_path


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
    with Session(engine) as session:
        session.add_all([FileTaint(id=i, filename=f'/inputs/{key}', sha256=key,
                                  command='tool {input_file}', input_key=key, complete=False)
                         for i, key in enumerate(('one', 'two', 'unseen'), start=1)])
        session.commit()
    events = [dict(fileTaintMatch=dict(filename='/guest/one')),
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
    project = dict(output_dir=str(tmp_path), mining_inputs={'/guest/one': 'one', '/guest/two': 'two'})
    if malformed:
        with pytest.raises(ijson.JSONError):
            fbi.parse_panda_log(str(log), project)
    else:
        fbi.parse_panda_log(str(log), project)
    with Session(engine) as session:
        completed = dict(session.execute(select(FileTaint.input_key, FileTaint.complete)).all())
    assert completed == {'one': not malformed, 'two': not malformed, 'unseen': False}
    assert scopes == [(0, 'one'), (0, 'two')]
