"""Prepare the real MediaService handler target, without modifying upstream code.

Source provenance: pins.json identifies a raw GitHub archive of DeathStarBench
6ecb09706140f8730b5385c08f1386c654c3c526. Its generated MediaService files say
Thrift compiler 0.12.0; socialNetwork/docker/openresty-thrift/xenial/Dockerfile
pins OpenTracing C++ 1.5.1. We build these runtimes as static dependencies, using
Boost 1.69 headers for Thrift. No RPC code is regenerated. The handler remains
unchanged; the local adapter selects OpenTracing's no-op tracer instead of
Jaeger/network telemetry, and copies the upstream TextMapReader/Writer classes.

Automatic prepare.sh calls verify/download the raw archive, build/cache local
dependencies, and generate the authored input fixtures. --setup-tree adds local
build support to an extracted working tree, preserving existing source adapters
so subsequent configure calls cannot overwrite instrumented code. The source
archive is never repacked. All auxiliary files live in this configuration folder.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile

HERE = Path(__file__).resolve().parent
PINS = json.loads((HERE / 'pins.json').read_text())
CACHE = HERE / '.target-prepare'


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def fetch(pin, destination):
    """Verify cached bytes or publish a verified download atomically."""
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if sha256(destination) != pin['sha256']:
            raise RuntimeError(f'Archive checksum mismatch: {destination}; move it aside explicitly')
        return destination
    partial = destination.with_name(destination.name + '.partial')
    try:
        subprocess.run(['curl', '-fL', '--retry', '2', '-o', str(partial), pin['url']], check=True)
        if sha256(partial) != pin['sha256']:
            raise RuntimeError(f'Download checksum mismatch: {destination}')
        os.replace(partial, destination)
    finally:
        partial.unlink(missing_ok=True)
    return destination


def unpack(pin, archive, parent):
    root = parent / pin['root']
    if not root.exists():
        with tarfile.open(archive) as source:
            source.extractall(parent, filter='data')
    if not root.is_dir():
        raise RuntimeError(f'Expected source directory is absent: {root}')
    return root


def dependencies(jobs):
    """Build native x86-64 dependencies separately from the instrumentable tree."""
    cc, cxx = shutil.which('clang-14'), shutil.which('clang++-14')
    if not cc or not cxx or not shutil.which('cmake'):
        raise RuntimeError('Install clang-14, cmake, make and a C++ development toolchain first')
    identity = {'pins': PINS, 'recipe_sha256': sha256(__file__),
                'compiler': subprocess.check_output([cxx, '--version'], text=True).splitlines()[0]}
    marker = CACHE / 'dependencies.json'
    if marker.exists():
        recorded = json.loads(marker.read_text())
        if recorded['identity'] == identity and all(Path(recorded[k]).is_file()
                                                    for k in ('thrift_library', 'opentracing_library')):
            print('MediaService dependencies already prepared', flush=True)
            return recorded
    prefix = CACHE / 'prefix'
    sources = CACHE / 'sources'
    sources.mkdir(parents=True, exist_ok=True)
    roots = {}
    for name in ('boost', 'thrift', 'opentracing'):
        pin = PINS[name]
        archive = fetch(pin, CACHE / 'downloads' / pin['archive'])
        roots[name] = unpack(pin, archive, sources)
    common = ['-DCMAKE_BUILD_TYPE=Debug', f'-DCMAKE_C_COMPILER={cc}',
              f'-DCMAKE_CXX_COMPILER={cxx}', f'-DCMAKE_INSTALL_PREFIX={prefix}',
              '-DCMAKE_INSTALL_LIBDIR=lib', '-DCMAKE_CXX_FLAGS_DEBUG=-O0 -g -gdwarf-2 -fno-omit-frame-pointer',
              '-DCMAKE_C_FLAGS_DEBUG=-O0 -g -gdwarf-2', '-DBUILD_TESTING=OFF']
    flags = {
        'thrift': ['-DBUILD_COMPILER=OFF', '-DBUILD_LIBRARIES=ON', '-DBUILD_EXAMPLES=OFF',
                   '-DBUILD_TUTORIALS=OFF', '-DWITH_CPP=ON', '-DWITH_C_GLIB=OFF',
                   '-DWITH_JAVA=OFF', '-DWITH_PYTHON=OFF', '-DWITH_HASKELL=OFF',
                   '-DWITH_ZLIB=OFF', '-DWITH_OPENSSL=OFF', '-DWITH_LIBEVENT=OFF',
                   '-DWITH_QT4=OFF', '-DWITH_QT5=OFF', '-DWITH_STDTHREADS=ON',
                   '-DWITH_BOOSTTHREADS=OFF', '-DBUILD_SHARED_LIBS=OFF',
                   '-DBUILD_STATIC_LIBS=ON', '-DWITH_SHARED_LIB=OFF', '-DWITH_STATIC_LIB=ON',
                   f'-DBOOST_ROOT={roots["boost"]}'],
        'opentracing': ['-DBUILD_SHARED_LIBS=OFF', '-DBUILD_STATIC_LIBS=ON',
                        '-DBUILD_MOCKTRACER=OFF', '-DBUILD_DYNAMIC_LOADING=OFF', '-DENABLE_LINTING=OFF'],
    }
    for name in ('thrift', 'opentracing'):
        build = CACHE / ('build-' + name)
        subprocess.run(['cmake', '-S', str(roots[name]), '-B', str(build)] + common + flags[name], check=True)
        subprocess.run(['cmake', '--build', str(build), '--parallel', str(jobs)], check=True)
        subprocess.run(['cmake', '--install', str(build)], check=True)
    def library(name):
        # Thrift's Debug configuration adds a 'd' postfix to its archive name.
        candidates = sorted(prefix.rglob('lib' + name + ('d.a' if name == 'thrift' else '.a')))
        if len(candidates) != 1:
            raise RuntimeError(f'Expected one static {name} archive, got {candidates}')
        return str(candidates[0])
    result = {'identity': identity, 'prefix': str(prefix), 'boost_headers': str(roots['boost']),
              'thrift_library': library('thrift'), 'opentracing_library': library('opentracing')}
    marker.write_text(json.dumps(result, indent=2) + '\n')
    return result


def setup_tree(root, install_dir, jobs):
    root = Path(root).resolve()
    handler = root / 'socialNetwork/src/MediaService/MediaHandler.h'
    tracing = root / 'socialNetwork/src/tracing.h'
    if not handler.is_file() or not tracing.is_file():
        raise RuntimeError('Expected the full pinned DeathStarBench source tree')
    deps = dependencies(jobs)
    local = root / 'lava-media'
    local.mkdir(exist_ok=True)
    # Preserve existing adapters, including query/injection edits.
    for name in ('lava_media_driver.cpp', 'media_handler.cpp', 'media_handler.h'):
        destination = local / name
        if not destination.exists():
            shutil.copyfile(HERE / name, destination)
    types = local / 'media_tracing_types.h'
    if not types.exists():
        original = tracing.read_text()
        classes = original[original.index('class TextMapReader'):original.index('void SetUpTracer(')]
        types.write_text('#pragma once\n#include <map>\n#include <string>\n'
                         '#include <opentracing/propagation.h>\nnamespace social_network {\n'
                         'using opentracing::expected; using opentracing::string_view;\n' + classes + '\n}\n')
    def make_path(value):
        return str(value).replace('$', '$$').replace(' ', '\\ ')
    values = {'DEPS': deps['prefix'], 'BOOST_HEADERS': deps['boost_headers'],
              'THRIFT_LIBRARY': deps['thrift_library'], 'OPENTRACING_LIBRARY': deps['opentracing_library'],
              'PREFIX': Path(install_dir).resolve()}
    (root / 'Makefile').write_text(''.join(f'{k} := {make_path(v)}\n' for k,v in values.items())
                                 + (HERE / 'Makefile.lava').read_text())
    files = ['LICENSE', 'socialNetwork/social_network.thrift',
             'socialNetwork/gen-cpp/MediaService.h', 'socialNetwork/gen-cpp/MediaService.cpp',
             'socialNetwork/gen-cpp/social_network_types.h', 'socialNetwork/gen-cpp/social_network_types.cpp',
             'socialNetwork/src/MediaService/MediaHandler.h', 'socialNetwork/src/tracing.h',
             'lava-media/lava_media_driver.cpp', 'lava-media/media_handler.cpp',
             'lava-media/media_handler.h', 'lava-media/media_tracing_types.h']
    # Freeze the initial provenance record; later configure calls preserve it.
    manifest = local / 'source-manifest.json'
    if not manifest.exists():
        manifest.write_text(json.dumps({'source': PINS['deathstar'], 'dependencies': deps,
            'profile': 'upstream MediaServiceProcessor + MediaHandler; OpenTracing no-op telemetry',
            'sha256': {f: sha256(root/f) for f in files}}, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tarfile', type=Path)
    parser.add_argument('--tar-dir', type=Path)
    parser.add_argument('--inputs-dir', type=Path, default=Path(os.environ.get('LAVA_INPUTS_DIR', HERE/'inputs')))
    parser.add_argument('--source-only', action='store_true')
    parser.add_argument('--deps-only', action='store_true')
    parser.add_argument('--setup-tree', type=Path)
    parser.add_argument('--install-dir', type=Path)
    parser.add_argument('--jobs', type=int, default=4)
    args = parser.parse_args()
    if args.jobs < 1: parser.error('--jobs must be positive')
    CACHE.mkdir(exist_ok=True)
    with (CACHE/'prepare.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if args.setup_tree:
            if not args.install_dir: parser.error('--setup-tree requires --install-dir')
            setup_tree(args.setup_tree, args.install_dir, args.jobs)
            return
        if args.deps_only:
            dependencies(args.jobs)
            return
        archive = args.tarfile or (args.tar_dir / PINS['deathstar']['archive'] if args.tar_dir else None)
        if archive is None and os.environ.get('LAVA_TARFILE'):
            archive = Path(os.environ['LAVA_TARFILE'])
        if archive is None: parser.error('supply --tar-dir or --tarfile outside LAVA')
        fetch(PINS['deathstar'], archive)
        print(f'Verified raw DeathStarBench archive: {archive}', flush=True)
        if not args.source_only:
            dependencies(args.jobs)
            subprocess.run([os.sys.executable, str(HERE/'make_seeds.py'), '--output', str(args.inputs_dir)], check=True)


if __name__ == '__main__':
    main()
