"""Read-only architecture comparisons of observed source sites and DUA data.

Run ``python -m pyroclastic.utils.compare_architectures -p toy`` or provide
``--snapshot export.json`` repeatedly to compare existing table snapshots offline.
This is a semantic diagnostic, not a backup, migration, or execution-equivalence
checker. Candidate bugs and machine-level liveness are not compared yet.
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
from itertools import combinations
import json
from pathlib import Path

from sqlalchemy import select

from .database_types import (AttackPoint, AtpExecution, Dua, DuaViableByte,
                             FileTaint, LabelSet, LavaDatabase, SourceLval)
from .vars import parse_vars


TABLES = ('filetaint', 'dua', 'dua_viable_bytes', 'labelset', 'sourcelval',
          'attackpoint', 'atp_execution')


def read_snapshot(filename):
    """Load a lossless table export, rejecting missing tables or target metadata."""
    snapshot = json.loads(Path(filename).read_text())
    missing = set(TABLES) - snapshot.get('tables', {}).keys()
    if missing:
        raise ValueError(f'{filename}: missing tables {sorted(missing)}')
    fallback = snapshot.get('manifest', {}).get('architecture')
    for row in snapshot['tables']['filetaint']:
        if not row.get('architecture'):
            if not fallback:
                raise ValueError(f'{filename}: FileTaint architecture is unknown')
            # Old exports can supply explicit provenance in their manifest.
            row['architecture'] = fallback
    snapshot['source'] = str(filename)
    return snapshot


def read_database(project):
    """Read relevant tables in one PostgreSQL repeatable-read, read-only transaction.

    Scalar rows avoid ORM lazy loads. Results are materialized in memory; this
    initial helper targets small/medium analyses, not millions of candidates.
    """
    db = LavaDatabase(project)
    try:
        with db.engine.connect().execution_options(isolation_level='REPEATABLE READ') as connection:
            with connection.begin():
                connection.exec_driver_sql('SET TRANSACTION READ ONLY')
                queries = {model.__tablename__: select(model.__table__) for model in
                           (FileTaint, Dua, DuaViableByte, LabelSet, SourceLval,
                            AttackPoint, AtpExecution)}
                tables = {name: [dict(row) for row in connection.execute(statement).mappings()]
                          for name, statement in queries.items()}
        return dict(tables=tables, source=project['db'], manifest=dict(
            database=project['db'], exported_utc=datetime.now(timezone.utc).isoformat()))
    finally:
        db.close()
        db.engine.dispose()


def location(row):
    """Return the full stored source range without guessing path equivalence."""
    return [row['loc_filename'], row['loc_begin_line'], row['loc_begin_column'],
            row['loc_end_line'], row['loc_end_column']]


def encoded(value):
    """Produce a deterministic JSON identity suitable for maps and report output."""
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def load_site_map(filename):
    """Read explicit {architecture, location, site} mappings; reject duplicate keys.

    The JSON file is a list of records. ``location`` is [file, bl, bc, el, ec];
    ``site`` is a user-verified common site name. Unmapped ranges stay exact.
    """
    result = {}
    if filename:
        for row in json.loads(Path(filename).read_text()):
            if (len(row['location']) != 5 or not isinstance(row['site'], str)
                    or not row['site']):
                raise ValueError('Source mappings require a five-part location and nonempty site name')
            key = (row['architecture'], encoded(row['location']))
            if key in result:
                raise ValueError(f'Duplicate source mapping: {key}')
            result[key] = row['site']
    return result


def normalize(snapshot, architecture, command, site_map=None, input_root=None):
    """Resolve one target into semantic populations, retaining ambiguous identities.

    Input identity uses content hash and relative path when a root is supplied,
    otherwise basename. Collisions are excluded and reported. DUA occurrences
    use source-trace index; matching indices are a correspondence assumption,
    not proof that control flow is equivalent.
    """
    tables = snapshot['tables']
    maps = site_map or {}
    issues = []
    inputs = defaultdict(list)
    for row in tables['filetaint']:
        if row['architecture'] != architecture or row['command'] != command:
            continue
        path = Path(row['filename'])
        if input_root:
            try:
                name = str(path.relative_to(input_root))
            except ValueError as error:
                raise ValueError(f'{path} is outside input root {input_root}') from error
        else:
            name = path.name
        inputs[encoded([row['sha256'], name])].append(row)
    file_keys = {}
    coverage = {}
    for key, rows in inputs.items():
        coverage[key] = dict(rows=len(rows), complete=sum(bool(r['complete']) for r in rows))
        if len(rows) != 1:
            issues.append(dict(kind='ambiguous_input', identity=key, count=len(rows)))
        elif rows[0]['complete']:
            file_keys[rows[0]['id']] = key

    def site(row):
        """Resolve a verified site mapping or retain its exact stored range."""
        loc = location(row)
        key = (architecture, encoded(loc))
        return ['mapped', maps[key]] if key in maps else ['exact', loc]

    lvals = {row['id']: [site(row), row['ast_name']] for row in tables['sourcelval']}
    atps = {row['id']: [site(row), row['type']] for row in tables['attackpoint']}
    labels = {row['id']: (row['inputfile'], sorted(row['labels'])) for row in tables['labelset']}
    viable = defaultdict(dict)
    for row in tables['dua_viable_bytes']:
        viable[row['object_id']][row['index']] = row['value']
    source_counts = Counter()
    atp_counts = Counter()
    observations = defaultdict(list)
    used_lvals = set()
    for row in tables['dua']:
        if row['inputfile'] not in file_keys:
            continue
        if row['lval'] not in lvals:
            issues.append(dict(kind='missing_source_lval', dua=row['id']))
            continue
        used_lvals.add(row['lval'])
        identity = encoded([file_keys[row['inputfile']], lvals[row['lval']],
                            row['trace_index'], row['fake_dua']])
        byte_labels = []
        # Legacy snapshots have zero Dua.length; byte_tcn records observed width.
        length = row.get('length') or len(row['byte_tcn'])
        for index in range(length):
            label_id = viable[row['id']].get(index)
            if label_id is None:
                byte_labels.append(None)
            elif label_id not in labels or labels[label_id][0] != row['inputfile']:
                issues.append(dict(kind='invalid_labelset_owner', dua=row['id'], index=index))
                byte_labels.append(['invalid_labelset'])
            else:
                byte_labels.append(labels[label_id][1])
        observations[identity].append(dict(length=length, byte_tcn=row['byte_tcn'],
            all_labels=sorted(row['all_labels']), max_tcn=row['max_tcn'],
            max_cardinality=row['max_cardinality'], viable_bytes=byte_labels))
    for lval_id in used_lvals:
        source_counts[encoded(lvals[lval_id])] += 1
    used_atps = set()
    executions = Counter()
    for row in tables['atp_execution']:
        if row['inputfile'] not in file_keys:
            continue
        if row['atp'] not in atps:
            issues.append(dict(kind='missing_attackpoint', execution=row['id']))
            continue
        used_atps.add(row['atp'])
        executions[encoded([file_keys[row['inputfile']], atps[row['atp']], row['trace_index']])] += 1
    for atp_id in used_atps:
        atp_counts[encoded(atps[atp_id])] += 1
    for kind, counts in [('duplicate_source_identity', source_counts),
                         ('duplicate_attackpoint_identity', atp_counts)]:
        for key, count in counts.items():
            if count > 1:
                issues.append(dict(kind=kind, identity=key, count=count))
    for key, rows in observations.items():
        if len(rows) > 1:
            issues.append(dict(kind='ambiguous_dua', identity=key, count=len(rows)))
    return dict(architecture=architecture, source=snapshot.get('source'), command=command,
                snapshot_time=snapshot.get('manifest', {}).get('exported_utc'),
                inputs=coverage, source_lvals=dict(source_counts), attackpoints=dict(atp_counts),
                executions=dict(executions), duas=dict(observations), issues=issues)


def compare(left, right):
    """Compare semantic membership and unambiguous DUA payloads between targets."""
    result = dict(left=left['architecture'], right=right['architecture'],
                  left_source=left.get('source'), right_source=right.get('source'), populations={})
    for name in ('inputs', 'source_lvals', 'attackpoints', 'executions', 'duas'):
        a, b = left[name], right[name]
        shared = a.keys() & b.keys()
        changed = []
        ambiguous = []
        for key in sorted(shared):
            if name == 'duas' and (len(a[key]) != 1 or len(b[key]) != 1):
                ambiguous.append(key)
            elif a[key] != b[key]:
                changed.append(dict(identity=key, left=a[key], right=b[key]))
        result['populations'][name] = dict(shared=len(shared),
            left_only=sorted(a.keys() - b.keys()), right_only=sorted(b.keys() - a.keys()),
            changed=changed, ambiguous=ambiguous)
    return result


def write_report(output, populations, comparisons):
    """Write complete JSON and a bounded Markdown summary without modifying inputs."""
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    report = dict(format=1, created_utc=datetime.now(timezone.utc).isoformat(),
        assumptions=['Exact source ranges unless explicitly mapped.',
                     'DUA occurrence correspondence uses source-trace index.',
                     'No candidate-bug, liveness, or execution-equivalence comparison.'],
        populations=populations, comparisons=comparisons)
    (output / 'comparison.json').write_text(json.dumps(report, indent=2) + '\n')
    lines = ['# Architecture comparison', '', *report['assumptions'], '',
             '| Pair | Population | Shared keys | Left only | Right only | Changed | Ambiguous |',
             '|---|---|---:|---:|---:|---:|---:|']
    for comparison in comparisons:
        pair = f"{comparison['left']} / {comparison['right']}"
        for name, counts in comparison['populations'].items():
            lines.append(f"| {pair} | {name} | {counts['shared']} | {len(counts['left_only'])} | "
                         f"{len(counts['right_only'])} | {len(counts['changed'])} | {len(counts['ambiguous'])} |")
    lines += ['', 'Inspect comparison.json for full identities, payloads, and integrity issues.']
    for population in populations:
        lines.append(f"- {population['architecture']}: {len(population['issues'])} integrity/ambiguity issues.")
    (output / 'report.md').write_text('\n'.join(lines) + '\n')


def main(argv=None):
    """Discover targets in live databases or exports and compare each selected pair."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-p', '--project', help='Project resolved through host.json')
    parser.add_argument('--database', action='append', help='Exact database name; repeat for separate runs')
    parser.add_argument('--snapshot', action='append', help='Offline table export JSON; repeat for separate runs')
    parser.add_argument('--arches', nargs='+', help='Architectures to compare; default: all discovered')
    parser.add_argument('--command', help='Invocation to compare; required if multiple are present')
    parser.add_argument('--input-root', help='Common original input root; otherwise match SHA256 + basename')
    parser.add_argument('--site-map', help='JSON list of verified architecture/location/site correspondences')
    parser.add_argument('-o', '--output', default='architecture-comparison')
    args = parser.parse_args(argv)
    if args.snapshot and (args.database or args.project):
        parser.error('Choose offline --snapshot or live --project/--database mode')
    if not args.snapshot and not args.project:
        parser.error('Live mode requires --project')
    if args.snapshot:
        snapshots = [read_snapshot(path) for path in args.snapshot]
    else:
        project = parse_vars(args.project)
        snapshots = [read_database(dict(project, db=name))
                     for name in (args.database or [project['db']])]
    commands = {r['command'] for s in snapshots for r in s['tables']['filetaint']}
    if args.command is None and len(commands) != 1:
        parser.error('Select --command; found ' + repr(sorted(commands)))
    command = args.command if args.command is not None else next(iter(commands))
    site_map = load_site_map(args.site_map)
    populations = []
    for snapshot in snapshots:
        discovered = {r['architecture'] for r in snapshot['tables']['filetaint'] if r['command'] == command}
        for arch in sorted(discovered):
            if args.arches is None or arch in args.arches:
                populations.append(normalize(snapshot, arch, command, site_map, args.input_root))
    if len(populations) < 2:
        parser.error('Need at least two target populations for comparison')
    if args.arches and set(args.arches) - {p['architecture'] for p in populations}:
        parser.error('One or more requested architectures are absent')
    comparisons = [compare(a, b) for a, b in combinations(populations, 2)]
    write_report(args.output, populations, comparisons)
    print(f'Compared {len(populations)} populations; report: {Path(args.output) / "report.md"}')


if __name__ == '__main__':
    main()
