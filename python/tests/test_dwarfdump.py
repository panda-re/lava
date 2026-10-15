"""DWARF line intervals must follow addresses, not source-line order."""
import json

import pytest

from pyroclastic.taint.dwarfdump import parse_dwarfdump


def convert(tmp_path, rows):
    prefix = str(tmp_path / "binary")
    parse_dwarfdump("\n".join(rows), prefix)
    return json.loads((tmp_path / "binary_lineinfo.json").read_text())


def intervals(lines):
    return [(r["lowpc"], r["highpc"], r["lno"], r["col"]) for r in lines]


def test_libxml2_function_boundary(tmp_path):
    # Real xmlFreeDoc / xmlFreeNodeList boundary. Previously line 6532
    # could extend across the following function and win PANDA's lookup.
    result = convert(tmp_path, [
        '0x006405db [6532,1] NS uri: "/src/tree.c"',
        '0x006405f0 [8063,0] NS',
        '0x00640603 [8064,5] NS PE',
        '0x00640610 [8064,5] ET',
    ])
    assert intervals(result["/src/tree.c"]) == [
        (0x6405DB, 0x6405F0, 6532, 1),
        (0x6405F0, 0x640603, 8063, 0),
        (0x640603, 0x640610, 8064, 5),
    ]
    owners = [r for r in result["/src/tree.c"]
              if r["lowpc"] <= 0x6405F0 < r["highpc"]]
    assert [r["lno"] for r in owners] == [8063]


def test_backward_lines_and_filename_changes(tmp_path):
    result = convert(tmp_path, [
        '0x100 [100,1] NS uri: "/src/main.c"',
        '0x110 [12,2] NS',
        '0x120 [7,3] NS uri: "/src/helper.h"',
        '0x130 [101,4] NS uri: "/src/main.c"',
        '0x140 [101,4] ET',
    ])
    assert intervals(result["/src/main.c"]) == [
        (0x100, 0x110, 100, 1), (0x110, 0x120, 12, 2),
        (0x130, 0x140, 101, 4),
    ]
    assert intervals(result["/src/helper.h"]) == [(0x120, 0x130, 7, 3)]


def test_sequence_end_does_not_bridge_gap_or_add_source_row(tmp_path):
    result = convert(tmp_path, [
        '0x100 [10,0] NS uri: "/src/main.c"',
        '0x110 [10,0] ET',
        # Independent sequences can restart at lower addresses.
        '0x20 [20,0] NS uri: "/src/main.c"',
        '0x30 [20,0] ET',
    ])
    assert intervals(result["/src/main.c"]) == [
        (0x100, 0x110, 10, 0), (0x20, 0x30, 20, 0),
    ]


def test_same_address_uses_last_row(tmp_path):
    result = convert(tmp_path, [
        '0x100 [10,0] NS uri: "/src/main.c"',
        '0x100 [11,2] NS',
        '0x110 [11,2] ET',
    ])
    assert intervals(result["/src/main.c"]) == [(0x100, 0x110, 11, 2)]


def test_unterminated_row_does_not_invent_range(tmp_path):
    result = convert(tmp_path, ['0x100 [10,0] NS uri: "/src/main.c"'])
    assert not any(result.values())


def test_address_regression_without_sequence_end_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="address.*decreased"):
        convert(tmp_path, [
            '0x100 [10,0] NS uri: "/src/main.c"',
            '0x80 [11,0] NS',
        ])
