"""Historical decoder-only packager; the active real-handler target uses prepare.py.

Package a small pinned DeathStarBench decoder target without editing its checkout.

This only prepares source. It does not fix LAVA's C-only staging, install Thrift,
regenerate RPC code, or promote the draft JSON to a supported target.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile

PIN = '6ecb09706140f8730b5385c08f1386c654c3c526'
FILES = ('LICENSE', 'socialNetwork/social_network.thrift',
         'socialNetwork/gen-cpp/MediaService.h', 'socialNetwork/gen-cpp/MediaService.cpp',
         'socialNetwork/gen-cpp/social_network_types.h',
         'socialNetwork/gen-cpp/social_network_types.cpp')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkout', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists():
        parser.error('output already exists; choose a new archive path')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='lava-deathstar-source-') as temporary:
        root = Path(temporary) / ('deathstar-media-' + PIN[:12])
        root.mkdir()
        manifest = {'repository': 'https://github.com/delimitrou/DeathStarBench',
                    'revision': PIN, 'profile': 'MediaService generated decoder only',
                    'sha256': {}}
        for name in FILES:
            result = subprocess.run(['git', '-C', str(args.checkout), 'show', f'{PIN}:{name}'],
                                    check=True, capture_output=True)
            relative = name.removeprefix('socialNetwork/')
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(result.stdout)
            manifest['sha256'][relative] = hashlib.sha256(result.stdout).hexdigest()
        for name in ('lava_media_driver.cpp', 'Makefile.lava'):
            data = (Path(__file__).parent / 'draft' / name).read_bytes()
            (root / name).write_bytes(data)
            manifest['sha256'][name] = hashlib.sha256(data).hexdigest()
        (root / 'LAVA_SOURCE.json').write_text(json.dumps(manifest, indent=2) + '\n')
        def stable_metadata(member):
            member.uid = member.gid = member.mtime = 0
            member.uname = member.gname = ''
            member.mode = 0o755 if member.isdir() else 0o644
            return member

        with output.open('xb') as stream:
            with gzip.GzipFile(fileobj=stream, mode='wb', filename='', mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode='w') as archive:
                    archive.add(root, arcname=root.name, filter=stable_metadata)
    print(output)


if __name__ == '__main__':
    main()
