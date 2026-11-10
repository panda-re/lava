import json
from pathlib import Path
import subprocess
import sys

import pytest

from pyroclastic.utils.sanitize import QUERY_SOURCE_REVISION, sanitizer_sources


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args], text=True).strip()


def project(tmp_path, baseline):
    git(tmp_path, 'init', '-q')
    (tmp_path / 'input.c').write_text(baseline)
    (tmp_path / 'template.c').write_text('NOT_VALID_C\n')
    git(tmp_path, 'add', '.')
    git(tmp_path, '-c', 'user.name=Test', '-c', 'user.email=test@example.com',
        'commit', '-qm', 'Preprocessed source')
    entries = [dict(directory=str(tmp_path), file=str(tmp_path / filename),
                    arguments=['clang', '-I' + str(tmp_path), '-c', filename])
               for filename in ['input.c', 'template.c']]
    (tmp_path / 'compile_commands.json').write_text(json.dumps(entries))


@pytest.mark.parametrize('pin_revision', [False, True])
def test_sanitizer_uses_original_coordinates_without_changing_live_tree(tmp_path, pin_revision):
    baseline = 'int f(int x) {\n  return x;\n}\n'
    project(tmp_path, baseline)
    if pin_revision:
        (tmp_path / QUERY_SOURCE_REVISION).write_text(git(tmp_path, 'rev-parse', 'HEAD'))
        # A later commit must not change the coordinate baseline.
        (tmp_path / 'input.c').write_text('// later edit\n' + baseline)
        git(tmp_path, 'add', 'input.c')
        git(tmp_path, '-c', 'user.name=Test', '-c', 'user.email=test@example.com',
            'commit', '-qm', 'Later changes')
    instrumented = '#include <lava/pirate_mark_lava.h>\n' + baseline
    (tmp_path / 'input.c').write_text(instrumented)
    before_status = git(tmp_path, 'status', '--porcelain')

    with sanitizer_sources(tmp_path, r'template\.c') as (root, files):
        assert files == [str(root / 'input.c')]
        assert (root / 'input.c').read_text() == baseline
        assert (root / 'input.c').read_text().splitlines()[1] == '  return x;'
        entries = json.loads((root / 'compile_commands.json').read_text())
        assert entries[0]['file'] == str(root / 'input.c')
        assert entries[0]['directory'] == str(root)
        assert entries[0]['arguments'][1] == '-I' + str(root)

    assert not root.exists()
    assert (tmp_path / 'input.c').read_text() == instrumented
    assert git(tmp_path, 'status', '--porcelain') == before_status


def test_instrumented_baseline_is_rejected_before_sanitization(tmp_path):
    project(tmp_path, '#include <lava/pirate_mark_lava.h>\nint f(void) { return 0; }\n')
    with pytest.raises(RuntimeError, match='requires pre-query source'):
        with sanitizer_sources(tmp_path):
            pytest.fail('must not run DUASan against instrumented coordinates')


@pytest.mark.parametrize('exit_code', [0, 7])
def test_dry_run_cli_uses_pristine_snapshot_and_forwards_exit_code(tmp_path, exit_code):
    """The standalone preview always passes --dry-run, even when DUASan fails."""
    from pyroclastic.utils import sanitize

    source = tmp_path / 'source tree'
    source.mkdir()
    baseline = 'int f(int x) {\n  return x;\n}\n'
    project(source, baseline)
    instrumented = '#include <lava/pirate_mark_lava.h>\n' + baseline
    (source / 'input.c').write_text(instrumented)
    executable = tmp_path / 'fake duasan'
    executable.write_text(
        f'#!{sys.executable}\n'
        'import json, sys\n'
        'from pathlib import Path\n'
        'print(json.dumps({"args": sys.argv[1:], '
        '"source": Path(sys.argv[-1]).read_text()}))\n'
        f'sys.exit({exit_code})\n')
    executable.chmod(0o755)

    result = subprocess.run(
        [sys.executable, sanitize.__file__, str(source), '--db', 'preview',
         '--host', 'localhost', '--port', '5544', '--exclude-dirs', r'template\.c',
         '--duasan', str(executable)], text=True, capture_output=True)

    assert result.returncode == exit_code, result.stderr
    output = json.loads(result.stdout)
    arguments = output['args']
    snapshot = Path(next(arg.split('=', 1)[1] for arg in arguments
                         if arg.startswith('-src-prefix=')))
    assert arguments == [
        '--dry-run', f'-p={snapshot}/compile_commands.json', f'-src-prefix={snapshot}',
        '-db=preview', '-host=localhost', '-port=5544', str(snapshot / 'input.c')]
    assert output['source'] == baseline
    assert not snapshot.exists()
    assert (source / 'input.c').read_text() == instrumented
