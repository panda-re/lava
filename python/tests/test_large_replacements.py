"""Compare the large-edit path with LLVM's byte-offset replacement semantics."""
from pathlib import Path
import shutil
import subprocess

import pytest
import yaml

from pyroclastic.utils.build_support import apply_large_replacements


def write_yaml(path, edits):
    path.write_text(yaml.safe_dump({'MainSourceFile': 'input.c', 'Replacements': edits},
                                   explicit_start=True, explicit_end=True, default_style='"'))


def edit(offset, length, text, file='input.c'):
    return dict(FilePath=file, Offset=offset, Length=length, ReplacementText=text)


def test_matches_llvm_for_insert_replace_delete_and_utf8_offsets(tmp_path):
    llvm = shutil.which('clang-apply-replacements-14')
    if not llvm:
        pytest.skip('LLVM replacement tool required')
    original = '/* café */\nint x = 1;\n'.encode()
    source = tmp_path / 'input.c'
    source.write_bytes(original)
    edits = [edit(0, 0, '// inserted\n'), edit(original.index(b'x'), 1, 'renamed'),
             edit(original.index(b'1'), 1, '42'), edit(len(original)-1, 1, '')]
    manifest = tmp_path / 'input.c.yaml'
    write_yaml(manifest, edits)
    subprocess.run([llvm, str(tmp_path)], cwd=tmp_path, check=True)
    expected = source.read_bytes()
    source.write_bytes(original)
    assert apply_large_replacements([manifest], tmp_path, [source], minimum=0)
    assert source.read_bytes() == expected


@pytest.mark.parametrize('edits', [
    [edit(0, 2, 'x'), edit(1, 0, 'y')],
    [edit(1, 0, 'x'), edit(1, 0, 'y')],
    [edit(1, 0, 'x'), edit(1, 0, 'x')],
    [edit(100, 0, 'x')],
    [edit(0, 0, 'é')],
    [edit(0, 0, 'x', '../outside.c')],
])
def test_ambiguous_or_unsupported_edits_fall_back_without_writes(tmp_path, edits):
    source = tmp_path / 'input.c'
    source.write_bytes(b'abc')
    manifest = tmp_path / 'input.c.yaml'
    write_yaml(manifest, edits)
    assert not apply_large_replacements([manifest], tmp_path, [source], minimum=0)
    assert source.read_bytes() == b'abc'


def test_small_edits_stay_with_llvm(tmp_path):
    source = tmp_path / 'input.c'
    source.write_bytes(b'abc')
    manifest = tmp_path / 'input.c.yaml'
    write_yaml(manifest, [edit(0, 0, 'x')])
    assert not apply_large_replacements([manifest], tmp_path, [source])
    assert source.read_bytes() == b'abc'


def test_folded_multiline_yaml_stays_with_llvm(tmp_path):
    source = tmp_path / 'input.c'
    source.write_bytes(b'abc')
    manifest = tmp_path / 'input.c.yaml'
    manifest.write_text(yaml.safe_dump({'MainSourceFile': 'input.c',
                                       'Replacements': [edit(0, 0, 'two\nlines\n')]}))
    assert not apply_large_replacements([manifest], tmp_path, [source], minimum=0)
    assert source.read_bytes() == b'abc'
