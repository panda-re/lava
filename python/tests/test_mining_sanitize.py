"""Phase I -> DUASan -> Phase II is a required gate, including optional artifact cleanup.

Compile the actual orchestration functions from their AST to isolate these tests
from PANDA/SQLAlchemy imports. Collaborators are mocks; ordering, snapshot lifetime
and exception propagation run through the production function bodies unchanged.
The C++/PostgreSQL behavior is covered separately by test_duasan.py.
"""
import ast
from contextlib import contextmanager
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace
from typing import Optional
from unittest.mock import Mock, MagicMock

import pytest


MINING = Path(__file__).resolve().parents[1] / 'src/pyroclastic/taint/bug_mining.py'


def mining_function(name, namespace, source=MINING):
    tree = ast.parse(source.read_text())
    function = next(node for node in ast.walk(tree)
                    if isinstance(node, ast.FunctionDef) and node.name == name)
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), 'exec'), namespace)
    return namespace[name]


@pytest.mark.parametrize('error', [None, RuntimeError('bad snapshot'),
                                  subprocess.CalledProcessError(1, ['duasan']), SystemExit(1)])
@pytest.mark.parametrize('delete_logs', [False, True])
def test_phase2_requires_sanitization_success(error, delete_logs, tmp_path):
    events = []
    log = tmp_path / 'log.json'
    log.write_text('[]')
    namespace = dict(project_data={'lava_mode': 'lava1', 'delete_panda_log': delete_logs},
                     pandalog_json=str(log), Path=Path,
                     state=SimpleNamespace(tar_directory='/source', guest_command='tool input'),
                     tick=lambda: 0, tock=lambda _: 0, progress=Mock(),
                     sys=SimpleNamespace(stdout=Mock()))
    for function, label in [('parse_panda_log', 'mine'), ('dua_sanitize', 'sanitize'),
                            ('print_bug_stats', 'stats1'),
                            ('record_injectable_bugs_offline', 'generate'),
                            ('print_phase2_stats', 'stats2')]:
        def invoke(*args, label=label, **kwargs):
            events.append(label)
            if label == 'sanitize' and error is not None:
                raise error
        namespace[function] = Mock(side_effect=invoke)
    parse = mining_function('parse_replay_output', namespace)
    if error is None:
        parse()
        assert events == ['mine', 'sanitize', 'stats1', 'generate', 'stats2']
    else:
        with pytest.raises(type(error)):
            parse()
        assert events == ['mine', 'sanitize']
    assert log.exists() == (error is not None or not delete_logs)
    namespace['dua_sanitize'].assert_called_once_with(namespace['project_data'], '/source')


@pytest.mark.parametrize('failure', [False, True])
def test_sanitizer_uses_checked_runner_while_snapshot_exists(tmp_path, failure):
    events = []
    snapshot = tmp_path / 'pristine source'
    source_file = str(snapshot / 'input.c')
    config = dict(output_dir=str(tmp_path), database='localhost', database_port=5544,
                  db='test', instrument_exclude_dirs=r'template\.c')

    @contextmanager
    def sources(source, exclusions):
        assert source == '/live source'
        assert exclusions == config['instrument_exclude_dirs']
        events.append('snapshot')
        try:
            yield snapshot, [source_file]
        finally:
            events.append('cleanup')

    def execute(command, log):
        assert events == ['snapshot']
        assert command == ['duasan', f'-p={snapshot}/compile_commands.json',
                           f'-src-prefix={snapshot}', '-host=localhost', '-port=5544',
                           '-db=test', source_file]
        assert log == str(tmp_path / 'logs/sanitize.log')
        events.append('run')
        if failure:
            raise subprocess.CalledProcessError(1, command)

    sanitize = mining_function('dua_sanitize', dict(
        Path=Path, sanitizer_sources=sources, progress=Mock(), run_local=Mock(side_effect=execute)))
    if failure:
        with pytest.raises(subprocess.CalledProcessError):
            sanitize(config, '/live source')
    else:
        sanitize(config, '/live source')
    assert events == ['snapshot', 'run', 'cleanup']


def test_empty_source_selection_blocks_sanitization(tmp_path):
    @contextmanager
    def sources(*args):
        yield tmp_path, []

    runner = Mock()
    sanitize = mining_function('dua_sanitize', dict(
        Path=Path, sanitizer_sources=sources, progress=Mock(), run_local=runner))
    with pytest.raises(RuntimeError, match='at least one source file'):
        sanitize(dict(output_dir=str(tmp_path)), tmp_path)
    runner.assert_not_called()


@pytest.mark.parametrize('steps', [None, ['parse']])
def test_completed_inputs_skip_saved_json_and_panda(tmp_path, monkeypatch, steps):
    inputs = tmp_path / 'inputs'
    inputs.mkdir()
    (inputs / 'seed').write_bytes(b'input')
    output = tmp_path / 'output'
    output.mkdir()
    log = output / 'panda_logs/x86_64-seed.json'
    log.parent.mkdir()
    log.write_text('[]')
    project = dict(config_dir=str(tmp_path), output_dir=str(output), name='test',
                   tarfile='source.tar', command='tool', qemu='x86_64', lava_mode='lava1')
    database = MagicMock()
    database.session.query.return_value.filter_by.return_value.first.return_value = SimpleNamespace(complete=True)
    connection = MagicMock()
    connection.return_value.__enter__.return_value = database
    namespace = dict(Path=Path, os=os, Optional=Optional, LavaDatabase=connection,
                     FileTaint=SimpleNamespace(identity=lambda *args: {}),
                     subprocess=SimpleNamespace(check_output=Mock(return_value=b'source/\n')),
                     Panda=Mock(), tick=lambda: 0, tock=lambda _: 0, progress=Mock(),
                     sys=SimpleNamespace(stdout=Mock()), parse_panda_log=Mock(),
                     dua_sanitize=Mock(), print_bug_stats=Mock(), print_phase2_stats=Mock(),
                     record_injectable_bugs_offline=Mock())
    pipeline = mining_function('run_taint_pipeline', namespace)
    monkeypatch.chdir(tmp_path)
    pipeline(project, steps=steps)
    namespace['Panda'].assert_not_called()
    namespace['parse_panda_log'].assert_not_called()
    namespace['dua_sanitize'].assert_not_called()
    namespace['record_injectable_bugs_offline'].assert_not_called()
    assert log.read_text() == '[]'


@pytest.mark.parametrize('mode', ['lava1', 'lava2'])
def test_rejected_observation_evicts_previous_candidate(mode):
    """A rejected DUA must neither become a trigger/extra nor revive an old value."""
    class Dua:
        def __init__(self, dua_id, lval, fake):
            self.id, self.lval, self.fake_dua = dua_id, lval, fake

    source = MINING.with_name('generate_bugs.py')
    accepted = Dua(1, 10, False)
    unrelated = Dua(2, 20, False)
    rejected = Dua(3, 10, True)
    later_accepted = Dua(4, 10, False)
    observations = [accepted, unrelated, rejected]
    if mode == 'lava1':
        replace = mining_function('replace_available_dua', {}, source)
        available, by_instr = {}, {}
        for observation in observations:
            replace(observation, available, by_instr)
        assert available == {20: unrelated}
        assert list(by_instr) == [unrelated]
        replace(later_accepted, available, by_instr)
        assert available == {20: unrelated, 10: later_accepted}
        assert list(by_instr) == [unrelated, later_accepted]
        replacement = Dua(5, 20, False)
        replace(replacement, available, by_instr)
        # Accepted replacements preserve lval insertion order for equal-instr ties.
        assert list(available) == [20, 10]
        assert list(by_instr) == [later_accepted, replacement]
    else:
        latest = mining_function('most_recent_dua_per_lval', dict(Dua=Dua), source)
        assert latest(observations) == {20: unrelated}
        assert latest(observations + [later_accepted]) == {20: unrelated, 10: later_accepted}
        assert latest([rejected]) == {}


@pytest.mark.parametrize('delete_logs', [False, True])
@pytest.mark.parametrize('conversion_fails', [False, True])
def test_recording_cleanup_requires_successful_conversion(tmp_path, delete_logs, conversion_fails):
    import sys

    prefix = tmp_path / 'x86_64-seed'
    artifacts = [Path(str(prefix) + suffix)
                 for suffix in ('.plog', '-rr-snp', '-rr-nondet.log')]
    for path in artifacts:
        path.write_bytes(b'recording')
    unrelated = tmp_path / 'x86_64-other.plog'
    unrelated.write_bytes(b'keep')
    log = Path(str(prefix) + '.json')

    def convert(command, *, stdout, **kwargs):
        if conversion_fails:
            raise subprocess.CalledProcessError(1, command)
        stdout.write(b'[]')

    namespace = dict(project_data={'delete_panda_log': delete_logs},
                     panda_log=str(artifacts[0]), pandalog_json=str(log), Path=Path,
                     state=SimpleNamespace(recording_name=str(prefix), guest_command='tool seed'),
                     tick=lambda: 0, tock=lambda _: 0, progress=Mock(), sys=sys,
                     pandalog_conversion_env=lambda: {},
                     subprocess=SimpleNamespace(check_call=convert,
                                                CalledProcessError=subprocess.CalledProcessError,
                                                list2cmdline=subprocess.list2cmdline))
    conversion = mining_function('convert_plog_to_json', namespace)
    if conversion_fails:
        with pytest.raises(subprocess.CalledProcessError):
            conversion()
    else:
        conversion()
        assert log.read_text() == '[]'
    assert all(path.exists() == (conversion_fails or not delete_logs) for path in artifacts)
    assert unrelated.read_bytes() == b'keep'
