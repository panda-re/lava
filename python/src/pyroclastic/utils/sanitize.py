"""Run static DUA checks against the source coordinates used by the query pass.

Preview directly with an installed package (or execute this file by path):
    python -m pyroclastic.utils.sanitize SOURCE --db DATABASE --host localhost

The CLI always enables DUASan's --dry-run: database updates are rolled back and
bug cleanup is skipped. POSTGRES_USER and POSTGRES_PASSWORD supply credentials.
The source directory must contain its Git history and compile_commands.json.
"""

import argparse
from contextlib import contextmanager
import json
from pathlib import Path
import re
import subprocess
import tempfile

QUERY_SOURCE_REVISION = '.lava-query-source-revision'


@contextmanager
def sanitizer_sources(source_directory, exclude_dirs=''):
    """Snapshot pristine preprocessed sources without checking out the live tree.

    Query insertion changes line/column coordinates. Database ASTLocs refer to
    the revision immediately before insertion, not the files PANDA executes.
    Older projects have no revision marker; their HEAD is the preprocessed
    snapshot. Refuse an instrumented snapshot rather than delete candidates
    using coordinates from the wrong source.
    """
    source = Path(source_directory).resolve()
    marker = source / QUERY_SOURCE_REVISION
    revision = marker.read_text().strip() if marker.exists() else 'HEAD'
    entries = json.loads((source / 'compile_commands.json').read_text())
    files = {str((Path(entry['directory']) / entry['file']).resolve())
             for entry in entries}
    if exclude_dirs:
        excluded = re.compile(r'/(' + exclude_dirs + r')(/|$)')
        files = {f for f in files if not excluded.search(f)}

    with tempfile.TemporaryDirectory(prefix='lava-duasan-') as temporary:
        root = Path(temporary)
        snapshot = root / 'source'
        snapshot.mkdir()
        archive = root / 'source.tar'
        with archive.open('wb') as stream:
            subprocess.run(['git', 'archive', revision], cwd=source,
                           stdout=stream, check=True)
        subprocess.run(['tar', '-xf', str(archive), '-C', str(snapshot)], check=True)

        snapshot_files = []
        for filename in sorted(files):
            relative = Path(filename).resolve().relative_to(source)
            copied = snapshot / relative
            text = copied.read_text()
            if ('vm_lava_pri_query_point(' in text or
                    '#include <lava/pirate_mark_lava.h>' in text):
                raise RuntimeError(f'DUASan requires pre-query source: {relative}')
            snapshot_files.append(str(copied))

        # Retain each compilation unit's flags and working directory, but point
        # all project paths at the pristine snapshot, including absolute -I's.
        def relocate(value):
            if isinstance(value, str):
                return value.replace(str(source), str(snapshot))
            if isinstance(value, list):
                return [relocate(item) for item in value]
            if isinstance(value, dict):
                return {key: relocate(item) for key, item in value.items()}
            return value

        entries = relocate(entries)
        for entry in entries:
            Path(entry['directory']).mkdir(parents=True, exist_ok=True)
        (snapshot / 'compile_commands.json').write_text(json.dumps(entries))
        yield snapshot, snapshot_files


def main(argv=None):
    """Preview DUASan decisions on a pristine snapshot and forward its exit code.

    The temporary snapshot exists until the subprocess finishes and is removed
    even when DUASan fails. This entry point deliberately offers no write mode;
    the existing pipeline owns mutating sanitization runs.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source_directory', type=Path,
                        help='Git source tree containing compile_commands.json')
    parser.add_argument('--db', required=True, help='LAVA PostgreSQL database name')
    parser.add_argument('--host', default='database', help='PostgreSQL host or socket directory')
    parser.add_argument('--port', type=int, default=5432, help='PostgreSQL port (default: 5432)')
    parser.add_argument('--exclude-dirs', default='',
                        help='Source exclusion regex, as used by the sanitize pipeline')
    parser.add_argument('--duasan', default='duasan', help='DUASan executable path')
    args = parser.parse_args(argv)

    with sanitizer_sources(args.source_directory, args.exclude_dirs) as (snapshot, files):
        if not files:
            parser.error('No source files remain after exclusions')
        command = [args.duasan, '--dry-run', f'-p={snapshot}/compile_commands.json',
                   f'-src-prefix={snapshot}', f'-db={args.db}',
                   f'-host={args.host}', f'-port={args.port}', *files]
        return subprocess.run(command, check=False).returncode


if __name__ == '__main__':
    raise SystemExit(main())
