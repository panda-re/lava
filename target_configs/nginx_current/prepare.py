"""Prepare the pinned modern nginx configuration-parser target.

The raw 1.30.6 release comes directly from nginx.org; its full SHA-256 below was
also recorded by the existing native validation in docs/nginx-native-validation.
The archive is never repacked. Inputs are the three locally authored fixture
configurations in fixtures/, not an official nginx fuzzing corpus. These exercise
nginx -t and do not represent HTTP request bytes. Their identities and hashes
are recorded beside inputs/. This script uses only its own target directory.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
VERSION = '1.30.6'
ARCHIVE = 'nginx-1.30.6.tar.gz'
URL = 'https://nginx.org/download/' + ARCHIVE
SHA256 = '3cf46f5ed7504d460125866b7bea99fb357f31d887e2e63b35503310e9b8b6c8'


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''): h.update(block)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tar-dir', type=Path)
    parser.add_argument('--tarfile', type=Path)
    parser.add_argument('--inputs-dir', type=Path, default=Path(os.environ.get('LAVA_INPUTS_DIR', HERE/'inputs')))
    parser.add_argument('--source-only', action='store_true')
    args = parser.parse_args()
    archive = args.tarfile or (args.tar_dir/ARCHIVE if args.tar_dir else None)
    if archive is None and os.environ.get('LAVA_TARFILE'): archive = Path(os.environ['LAVA_TARFILE'])
    if archive is None: parser.error('supply --tar-dir or --tarfile outside LAVA')
    cache = HERE / '.target-prepare'
    cache.mkdir(exist_ok=True)
    with (cache/'prepare.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        archive.parent.mkdir(parents=True, exist_ok=True)
        if not archive.exists():
            partial = archive.with_name(archive.name + '.partial')
            try:
                subprocess.run(['curl','-fL','--retry','2','-o',str(partial),URL],check=True)
                if digest(partial) != SHA256: raise RuntimeError('Downloaded nginx archive checksum mismatch')
                os.replace(partial, archive)
            finally: partial.unlink(missing_ok=True)
        if digest(archive) != SHA256: raise RuntimeError(f'Archive checksum mismatch: {archive}; move it aside')
        print(f'Verified raw nginx {VERSION}: {archive}', flush=True)
        if args.source_only: return
        args.inputs_dir.mkdir(parents=True, exist_ok=True)
        records = []
        for fixture in sorted((HERE/'fixtures').glob('*.conf')):
            output = args.inputs_dir/fixture.name
            data = fixture.read_bytes()
            if output.exists() and output.read_bytes() != data:
                raise RuntimeError(f'Existing seed differs from fixture; move it aside: {output}')
            if not output.exists(): output.write_bytes(data)
            records.append({'file': output.name, 'fixture': 'fixtures/'+fixture.name,
                            'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
        manifest = {'source': {'version': VERSION, 'url': URL, 'sha256': SHA256},
                    'origin': 'locally authored nginx configuration fixtures',
                    'command_scope': 'nginx -t configuration parsing; not HTTP input', 'inputs': records}
        args.inputs_dir.with_name(args.inputs_dir.name+'.manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
        print(f'Verified {len(records)} configuration seeds: {args.inputs_dir}', flush=True)


if __name__ == '__main__': main()
