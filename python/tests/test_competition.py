"""Competition policy and real-process grading, independent of mining infrastructure."""
import json
from pathlib import Path
from types import SimpleNamespace as NS
import subprocess

import pytest

from pyroclastic.competition import (FORMAT, digest, execute, grade, main,
                                     select_candidates, verify)
from pyroclastic.inject.inject import process_crash


def bug(ident, filename, line, column=1):
    return NS(id=ident, atp_relationship=NS(loc=NS(filename=filename, begin=NS(line=line, column=column))))


def test_selection_is_seeded_and_limits_lines_across_types_and_columns():
    candidates = [bug(1, 'a/../a/x.c', 5), bug(2, 'a/x.c', 5, 12),
                  bug(3, 'b/x.c', 5), bug(4, 'a/x.c', 6)]
    first = select_candidates(iter(candidates), 100, 7)
    assert first == select_candidates(iter(candidates), 100, 7)
    assert len(first) == 3
    assert not {1, 2} <= set(first)
    assert {3, 4} <= set(first)
    assert len(select_candidates(iter(candidates), 1, 7)) == 1


@pytest.fixture
def corpus(tmp_path):
    for mode in ('public', 'internal'):
        install = tmp_path / mode
        install.mkdir()
        script = install / 'target'
        logging = 'echo "LAVALOG: $id: target.c:1" >&2' if mode == 'internal' else ':'
        script.write_text('#!/bin/bash\n'
            'id=$(cat "$1")\n'
            'if [ "$id" = clean ]; then exit 0; fi\n'
            'if [ "$id" = timeout ]; then sleep 10; fi\n'
            f'{logging}\n'
            'kill -SEGV $$\n')
        script.chmod(0o755)
    (tmp_path / 'seed').write_text('clean')
    (tmp_path / 'answer').write_text('42')
    manifest = {'format': FORMAT, 'complete': True,
                'command': '{install_dir}/target {input_file}', 'timeout': 5,
                'variants': {mode: {'install': mode} for mode in ('public', 'internal')},
                'expected_exit_code': 0, 'seeds': ['seed'],
                'bugs': [{'id': 42, 'answer': 'answer'}], 'hashes': {}}
    return tmp_path, manifest


def test_paired_replay_and_unknown_crash(corpus):
    root, manifest = corpus
    accepted, results = verify(root, manifest)
    assert accepted == [42]
    assert results['42']['credited_ids'] == [42]
    (root / 'other').write_text('99')
    assert grade(root, manifest, root / 'other')['credited_ids'] == []
    assert grade(root, manifest, root / 'seed')['credited_ids'] == []


def test_timeout_never_earns_credit(corpus):
    root, manifest = corpus
    (root / 'slow').write_text('timeout')
    run = execute(manifest['command'], root / 'internal', root / 'slow', .05)
    assert run['timeout'] and not run['crashed']


def test_public_crash_required_and_hashes_enforced(corpus):
    root, manifest = corpus
    (root / 'public' / 'target').write_text('#!/bin/bash\nexit 0\n')
    assert grade(root, manifest, root / 'answer')['credited_ids'] == []
    manifest['hashes'] = {'answer': digest(root / 'answer')}
    (root / 'answer').write_text('changed')
    with pytest.raises(ValueError, match='Artifact changed'):
        verify(root, manifest)


def test_logging_parser_accepts_bytes():
    assert process_crash(b'noise\nLAVALOG: 42: x.c:5\n') == [42]


def test_logging_parser_deduplicates_and_sorts_ids():
    assert process_crash(
        'LAVALOG: 99: x.c:1\nLAVALOG: 42: x.c:2\nLAVALOG: 42: x.c:3\n'
    ) == [42, 99]


def test_cli_rejects_incomplete_manifest(tmp_path):
    manifest = tmp_path / 'manifest.json'
    manifest.write_text(json.dumps({'format': FORMAT, 'complete': False}))
    with pytest.raises(SystemExit):
        main(['verify', str(manifest)])
