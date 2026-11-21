"""Reproduce preprocessing pitfalls found by the FuzzBench -qm builds."""
import io
from pathlib import Path
import shlex
import shutil
import subprocess

import pytest

from pyroclastic.utils.build_support import preserve_shell_arguments
from pyroclastic.utils.funcs import _to_preprocess_args, git_addable_c_files, should_instrument_source


def test_capture_and_preprocess_preserve_literal_string_macros_and_include_paths(tmp_path, monkeypatch):
    from compiledb import parser
    compiler = shutil.which('clang-14')
    if not compiler:
        pytest.skip('Clang 14 required')
    monkeypatch.setattr(parser, 'CommandProcessor', parser.CommandProcessor)
    monkeypatch.setattr(parser, 'unescape', parser.unescape)
    preserve_shell_arguments()
    include = tmp_path / 'include with spaces'
    include.mkdir()
    (include / 'settings.h').write_text('#define ANSWER 42\n')
    source = tmp_path / 'input.c'
    source.write_text('#include "settings.h"\n'
                      'const char *directory = SYSCONFDIR;\n'
                      'int main(void) { return directory[0] != \'/\' || ANSWER != 42; }\n')
    arguments = [compiler, '-I', str(include), '-DSYSCONFDIR="/tmp/prefix with spaces/etc"',
                 '-MT', 'input.o', '-MF', 'input.d', '-c', str(source), '-o', 'input.o']
    captured = parser.parse_build_log(io.StringIO(shlex.join(arguments) + '\n'),
                                     str(tmp_path), []).compdb
    assert len(captured) == 1
    assert captured[0]['arguments'] == arguments
    subprocess.run(_to_preprocess_args(captured[0]['arguments'], str(source)),
                   cwd=tmp_path, check=True)
    source.write_bytes(Path(str(source) + '_pre').read_bytes())
    binary = tmp_path / 'native'
    subprocess.run([compiler, str(source), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)


def test_source_filter_keeps_cpp_and_excludes_assembly_and_png_generators():
    exclude = r'pnglibconf\.c|scripts/(vers|prefix|intprefix)\.c'
    assert should_instrument_source('/src/harness.cc', exclude)
    assert should_instrument_source('/src/parser.c', exclude)
    assert not should_instrument_source('/src/crypto/asm.s', exclude)
    assert not should_instrument_source('/src/crypto/asm.S', exclude)
    assert not should_instrument_source('/src/scripts/prefix.c', exclude)
    assert not should_instrument_source('/src/scripts/intprefix.c', exclude)
    assert not should_instrument_source('/src/pnglibconf.c', exclude)


def test_preprocessed_cpp_is_included_in_source_snapshot(tmp_path):
    if not shutil.which('git'):
        pytest.skip('Git required')
    subprocess.run(['git', 'init', '-q', str(tmp_path)], check=True)
    for name in ['driver.c', 'harness.cc', 'other.cpp', 'assembly.s']:
        (tmp_path / name).write_text('source')
    assert set(git_addable_c_files(tmp_path)) == {'driver.c', 'harness.cc', 'other.cpp'}


def test_implicit_cpp_constructor_can_have_a_point_source_range():
    from pyroclastic.add_queries.fninstr import Function
    function = Function({'start': 'harness.cc:123:9', 'end': 'harness.cc:123:9',
                         'name': '__type_identity', 'hasbody': True,
                         'fundecl': {'ret_type': 'void', 'params': None}})
    assert function.start == function.end  # analysis skips these definitions


def test_cpp_analysis_skips_implicit_records_and_handles_unknown_callers(tmp_path, monkeypatch):
    import yaml
    from pyroclastic.add_queries.fninstr import analysis
    monkeypatch.chdir(tmp_path)
    declaration = {'ret_type': 'int', 'params': None}
    records = [
        {'fun': {'name': 'operator new', 'hasbody': False, 'fundecl': declaration}},
        {'fun': {'name': 'implicit', 'hasbody': True, 'fundecl': declaration,
                 'start': 'harness.cc:1:1', 'end': 'harness.cc:1:1'}},
    ]
    for name, line in [('harness', 10), ('helper', 20)]:
        records.append({'fun': {'name': name, 'hasbody': True, 'fundecl': declaration,
                               'start': f'harness.cc:{line}:1', 'end': f'harness.cc:{line+1}:1'}})
    records.append({'call': {'name': 'helper', 'containing_function': 'Unknown',
                             'start': 'harness.cc:30:1', 'end': 'harness.cc:30:9',
                             'fnptr': False, 'args': None, 'ret_type': 'int'}})
    manifest = tmp_path / 'harness.cc.fn'
    manifest.write_text(yaml.safe_dump(records))
    output = tmp_path / 'fninstr'
    analysis(str(output), [str(manifest)], {'debug': False})
    assert output.read_text() == 'NOFILENAME df harness\n'
