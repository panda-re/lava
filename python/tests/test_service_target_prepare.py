"""Artifact integrity and adapter-preservation checks for build-only service targets."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]


def load_target(target, name):
    path = ROOT / 'target_configs' / target / (name + '.py')
    spec = importlib.util.spec_from_file_location(f'{target}_{name}', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_media_setup_preserves_instrumented_adapter_and_source_manifest(tmp_path, monkeypatch):
    prepare = load_target('deathstar_media', 'prepare')
    root = tmp_path / 'source'
    files = ['LICENSE', 'socialNetwork/social_network.thrift',
             'socialNetwork/gen-cpp/MediaService.h', 'socialNetwork/gen-cpp/MediaService.cpp',
             'socialNetwork/gen-cpp/social_network_types.h', 'socialNetwork/gen-cpp/social_network_types.cpp',
             'socialNetwork/src/MediaService/MediaHandler.h']
    for name in files:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('unchanged upstream source\n')
    tracing = root/'socialNetwork/src/tracing.h'
    classes = 'class TextMapReader {};\nclass TextMapWriter {};\n'
    tracing.write_text('namespace social_network {\n' + classes + 'void SetUpTracer() {}\n}\n')
    deps = {name: str(tmp_path/name) for name in
            ('prefix', 'boost_headers', 'thrift_library', 'opentracing_library')}
    monkeypatch.setattr(prepare, 'dependencies', lambda jobs: deps)
    prepare.setup_tree(root, root/'install', 1)
    local = root/'lava-media'
    manifest = (local/'source-manifest.json').read_bytes()
    assert classes in (local/'media_tracing_types.h').read_text()
    for name in ('lava_media_driver.cpp', 'media_handler.cpp', 'media_handler.h', 'media_tracing_types.h'):
        (local/name).write_text('// instrumented source\n')
    prepare.setup_tree(root, root/'install', 1)
    assert all((local/name).read_text() == '// instrumented source\n' for name in
               ('lava_media_driver.cpp', 'media_handler.cpp', 'media_handler.h', 'media_tracing_types.h'))
    assert (local/'source-manifest.json').read_bytes() == manifest
    assert (root/'socialNetwork/src/MediaService/MediaHandler.h').read_text() == 'unchanged upstream source\n'


def test_media_seed_frames_and_idempotence(tmp_path, monkeypatch):
    seeds = load_target('deathstar_media', 'make_seeds')
    output = tmp_path/'inputs'
    monkeypatch.setattr(sys, 'argv', ['make_seeds.py', '--output', str(output)])
    seeds.main()
    initial = {p.name: p.read_bytes() for p in output.iterdir()}
    assert len(initial) == 4
    for data in initial.values():
        assert struct.unpack('!I', data[:4])[0] == len(data)-4
        assert struct.unpack('!I', data[4:8])[0] == 0x80010001
    seeds.main()
    assert {p.name: p.read_bytes() for p in output.iterdir()} == initial
    manifest = json.loads((tmp_path/'inputs.manifest.json').read_text())
    assert {p['expected']['status'] for p in manifest['inputs']} == {'ok', 'service_exception'}
    (output/'media.bin').write_bytes(b'user-modified input')
    with pytest.raises(RuntimeError, match='Existing seed differs'):
        seeds.main()
    assert (output/'media.bin').read_bytes() == b'user-modified input'


def test_download_cache_rejects_corruption_without_replacing_it(tmp_path, monkeypatch):
    prepare = load_target('deathstar_media', 'prepare')
    path = tmp_path/'archive'
    path.write_bytes(b'original')
    pin = {'sha256': hashlib.sha256(b'original').hexdigest(), 'url': 'https://unused.invalid'}
    monkeypatch.setattr(prepare.subprocess, 'run', lambda *a, **k: pytest.fail('unexpected network download'))
    assert prepare.fetch(pin, path) == path
    path.write_bytes(b'corrupted')
    with pytest.raises(RuntimeError, match='checksum mismatch'):
        prepare.fetch(pin, path)
    assert path.read_bytes() == b'corrupted'


def test_nginx_prepare_manifest_and_seed_protection(tmp_path, monkeypatch):
    prepare = load_target('nginx_current', 'prepare')
    config = tmp_path/'config'
    (config/'fixtures').mkdir(parents=True)
    (config/'fixtures/minimal.conf').write_text('events {}\n')
    archive = tmp_path/'nginx.tar.gz'
    archive.write_bytes(b'cached archive')
    monkeypatch.setattr(prepare, 'HERE', config)
    monkeypatch.setattr(prepare, 'SHA256', hashlib.sha256(archive.read_bytes()).hexdigest())
    output = config/'inputs'
    monkeypatch.setattr(sys, 'argv', ['prepare.py', '--tarfile', str(archive), '--inputs-dir', str(output)])
    prepare.main()
    manifest = json.loads((config/'inputs.manifest.json').read_text())
    assert manifest['inputs'][0]['sha256'] == hashlib.sha256(b'events {}\n').hexdigest()
    (output/'minimal.conf').write_text('user modifications\n')
    with pytest.raises(RuntimeError, match='Existing seed differs'):
        prepare.main()
    assert (output/'minimal.conf').read_text() == 'user modifications\n'
