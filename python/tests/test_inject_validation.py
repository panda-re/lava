"""Validation accepts the bug IDs returned by selection and resolves them once."""
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from pyroclastic.inject import inject
from pyroclastic.utils.database_types import Bug


@pytest.mark.parametrize('original_exit', [0, 1])
def test_validate_bug_ids_resolves_objects_and_checks_each_seed_once(tmp_path, original_exit):
    seeds = [tmp_path / 'one', tmp_path / 'two']
    for seed in seeds:
        seed.write_bytes(b'input')
    inputs = [SimpleNamespace(filename=str(seed), command=f'tool{index} {{input_file}}')
              for index, seed in enumerate(seeds)]
    bugs = [SimpleNamespace(id=bug_id, trigger_relationship=SimpleNamespace(
        dua_relationship=SimpleNamespace(inputfile=input_id + 1, file_taint=inputs[input_id])))
        for bug_id, input_id in [(11, 0), (12, 0), (13, 1)]]
    database = SimpleNamespace(session=Mock())
    database.session.query.return_value.filter.return_value.all.return_value = bugs
    paths = SimpleNamespace(bugs_install='/install')
    project = {'config_dir': str(tmp_path)}
    arguments = SimpleNamespace(exitCode=0)
    build = object()
    results = {}
    output = (b'normal output', b'')

    with patch.object(inject, 'run_modified_program', return_value=(original_exit, output)) as run, \
         patch.object(inject, 'Run'), \
         patch.object(inject, 'validate_bug', side_effect=lambda db, lp, project, bug, *args, **kwargs:
                      {'validated': bug.id != 12}) as validate:
        if original_exit:
            with pytest.raises(AssertionError):
                inject.validate_bugs([11, 12, 13], database, paths, project, [], build,
                                     arguments, bug_results=results)
            validate.assert_not_called()
            database.session.commit.assert_not_called()
            assert results == {}
        else:
            validated = inject.validate_bugs([11, 12, 13], database, paths, project, [], build,
                                            arguments, bug_results=results)
            assert validated == [11, 13]
            assert list(results) == [11, 12, 13]
            assert [call.args[3] for call in validate.call_args_list] == bugs
            assert all(call.args[6] == {1: output, 2: output} for call in validate.call_args_list)
            assert run.call_count == 2  # Two bugs share the first seed and command.
            assert [call.args[2] for call in run.call_args_list] == [str(seed) for seed in seeds]
            assert [call.kwargs['command'] for call in run.call_args_list] == [item.command for item in inputs]
            database.session.commit.assert_called_once()
        database.session.query.assert_called_once_with(Bug)
