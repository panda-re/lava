import struct
from types import SimpleNamespace

import pytest

from pyroclastic.inject.inject import mutate_file
from pyroclastic.utils.database_types import BugKind


def read_values(path):
    data = path.read_bytes()
    return tuple(struct.unpack_from('<I', data, offset)[0] for offset in (0, 4, 8))


@pytest.mark.parametrize('magic, values', [
    (3, (1, 2, 1)),
    (4, (1, 5, 1)),
    (8, (0, 0, 1)),
])
def test_rel_write_uses_lavatool_solution(tmp_path, magic, values):
    source = tmp_path / 'source'
    mutated = tmp_path / 'mutated'
    source.write_bytes(b'\x00' * 12)
    bug = SimpleNamespace(type=BugKind.BUG_REL_WRITE, magic=magic)

    solution = [struct.pack('<I', value) for value in values]
    mutate_file(str(source), [list(range(4)), list(range(4, 8)), list(range(8, 12))],
                str(mutated), bug, solution=solution)

    a, b, c = read_values(mutated)
    mask = 0xffffffff
    mode = magic % 3
    if mode == 0:
        result = ((a + b) * c) & mask
    elif mode == 1:
        result = ((a * b) - c) & mask
    else:
        result = ((a + 2) * (c + 3) * (b + 1)) & mask
    assert result == magic


def test_rel_write_requires_lavatool_solution(tmp_path):
    source = tmp_path / 'source'
    mutated = tmp_path / 'mutated'
    source.write_bytes(b'\x00' * 12)
    bug = SimpleNamespace(type=BugKind.BUG_REL_WRITE, id=99, magic=3)

    with pytest.raises(RuntimeError, match='LavaTool did not provide a solution'):
        mutate_file(str(source), [list(range(4)), list(range(4, 8)), list(range(8, 12))],
                    str(mutated), bug)