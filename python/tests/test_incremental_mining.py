"""Regression checks for input identity and repeat parsing."""
from unittest.mock import Mock, patch

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


def test_snapshots_use_repeat_safe_lookup():
    fbi.liveness_by_file.clear()
    fbi.last_snapshotted_instr = -1
    fbi.liveness_by_file['/seed/one'][3] = 2
    try:
        with patch.object(fbi, 'get_or_create') as lookup:
            fbi.save_liveness_to_db(Mock(), 10)
            fbi.save_liveness_to_db(Mock(), 10)
            assert lookup.call_count == 1
            assert lookup.call_args.kwargs['atp_instr'] == 10
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
        bug_mining.run_taint_pipeline('test', project)
        panda.assert_not_called()
        database.session.add.assert_not_called()
        assert not (tmp_path / 'output').exists()


def test_new_input_retains_seed_and_raw_command(tmp_path):
    from pyroclastic.taint import bug_mining
    inputs = tmp_path / 'inputs'
    inputs.mkdir()
    source = inputs / 'seed with spaces'
    source.write_bytes(b'input')
    database = Mock()
    database.session.query.return_value.filter_by.return_value.first.return_value = None
    project = {'config_dir': str(tmp_path), 'output_dir': str(tmp_path / 'output'),
               'command': '{install_dir}/bin/tool --input {input_file} --flag',
               'use_c_fbi': False, 'qemu': 'i386'}
    import pytest
    from pathlib import Path
    with patch.object(bug_mining, 'LavaDatabase') as db, patch.object(bug_mining, 'Panda', side_effect=RuntimeError('stop before recording')):
        db.return_value.__enter__.return_value = database
        with pytest.raises(RuntimeError, match='stop before recording'):
            bug_mining.run_taint_pipeline('test', project)
    row = database.session.add.call_args.args[0]
    assert row.filename == str(source)
    assert row.command == project['command']
    assert row.complete is False
    assert Path(row.seed_path).read_bytes() == b'input'
    assert Path(row.seed_path).name == source.name
