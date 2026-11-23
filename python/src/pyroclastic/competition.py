"""Offline, binary-first competition corpora. No service or exploit tooling."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import posixpath
import random
import re
import resource
import shlex
import shutil
import signal
import subprocess
import tarfile
import tempfile

FORMAT = 'lava-competition-1'


def write_json(path, value):
    path = Path(path)
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(path)


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def select_candidates(bugs, count, seed, max_per_line=1):
    """Sample distinct full file/attack lines, without SQL random ordering."""
    if count < 1:
        raise ValueError('Candidate count must be positive')
    rng = random.Random(seed)
    reservoir, seen = [], {}
    eligible = 0
    for bug in bugs:
        loc = bug.atp_relationship.loc
        key = (posixpath.normpath(loc.filename), loc.begin.line)
        if seen.get(key, 0) >= max_per_line:
            continue
        seen[key] = seen.get(key, 0) + 1
        eligible += 1
        if len(reservoir) < count:
            reservoir.append(bug.id)
        else:
            slot = rng.randrange(eligible)
            if slot < count:
                reservoir[slot] = bug.id
    rng.shuffle(reservoir)
    return reservoir


def execute(command, install, input_file, timeout, library_path=''):
    """Run configured shell invocation with a process-group timeout."""
    command = command.format(install_dir=shlex.quote(str(Path(install).resolve())),
                             input_file=shlex.quote(str(Path(input_file).resolve())))
    env = os.environ.copy()
    if library_path:
        env['LD_LIBRARY_PATH'] = library_path.format(install_dir=str(Path(install).resolve()))
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        proc = subprocess.Popen(['/bin/bash', '-c', command], cwd=install,
                                env=env, stdout=out, stderr=err, start_new_session=True,
                                preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_CORE, (0, 0)))
        timed_out = False
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
        err.seek(0)
        # Logging is small for accepted answers; bound diagnostics for arbitrary inputs.
        stderr = err.read(4 * 1024 * 1024).decode('utf-8', errors='replace')
    ids = sorted({int(x) for x in re.findall(r'^LAVALOG: (\d+):', stderr, re.M)})
    return {'exit_code': proc.returncode, 'timeout': timed_out, 'observed_ids': ids,
            'stderr': stderr, 'crashed': not timed_out and (proc.returncode < 0 or 129 <= proc.returncode <= 192)}


def grade(root, manifest, input_file):
    runs = {mode: execute(manifest['command'], root / spec['install'], input_file,
                          manifest['timeout'], manifest.get('library_path', ''))
            for mode, spec in manifest['variants'].items()}
    known = {bug['id'] for bug in manifest['bugs']}
    observed = runs['internal']['observed_ids']
    credited = observed if (runs['public']['crashed'] and runs['internal']['crashed']
                            and len(observed) == 1 and set(observed) <= known) else []
    return {'input_sha256': digest(input_file), 'runs': runs, 'credited_ids': credited}


def verify(root, manifest):
    if manifest.get('format') != FORMAT:
        raise ValueError('Unsupported competition manifest')
    for name, expected in manifest['hashes'].items():
        if digest(root / name) != expected:
            raise ValueError(f'Artifact changed: {name}')
    results, accepted = {}, []
    for seed in manifest['seeds']:
        for mode, spec in manifest['variants'].items():
            run = execute(manifest['command'], root / spec['install'], root / seed,
                          manifest['timeout'], manifest.get('library_path', ''))
            if run['timeout'] or run['exit_code'] != manifest['expected_exit_code'] or run['observed_ids']:
                raise RuntimeError(f'Clean seed failed: {seed} ({mode}): {run}')
    for bug in manifest['bugs']:
        result = grade(root, manifest, root / bug['answer'])
        results[str(bug['id'])] = result
        if result['credited_ids'] == [bug['id']]:
            accepted.append(bug['id'])
    return accepted, results


def build_variant(lp, source_tar, dest, logging):
    from .utils.funcs import configure_project, make_and_install
    dest.mkdir(parents=True)
    with tarfile.open(source_tar) as archive:
        archive.extractall(dest, filter='data')
    src = dest / lp.tar_source_root
    local = copy.copy(lp)
    local.config = copy.deepcopy(lp.config)
    for environment in ('env_var', 'inject'):
        for flag in ('CFLAGS', 'CXXFLAGS'):
            value = local.config[environment].get(flag, '')
            if any(marker in value for marker in ('LAVA_LOGGING', 'DUA_LOGGING')):
                raise ValueError('Base build flags must not enable grading logs')
            if logging:
                local.config[environment][flag] = value + ' -DLAVA_LOGGING'
    configure_project(local, main_directory=str(src), environment='env_var')
    rv, _ = make_and_install(local, main_directory=str(src), environment='inject', capture_build=True)
    if rv:
        raise RuntimeError(f'Build failed: {dest}')
    return src / 'lava-install'


def generate(args):
    from .inject import inject as inj
    from .inject.dataflow import genFnTraceHelper
    from .utils.database_types import LavaDatabase, Bug, Dua, DuaBytes, BugKind
    from .utils.vars import LavaPaths

    if args.candidate_count < 1 or args.min_validated < 1 or args.max_attempts < 1 or args.timeout <= 0:
        raise ValueError('Counts, minimum yield, attempts and timeout must be positive')
    if args.min_validated > args.candidate_count:
        raise ValueError('Minimum yield exceeds candidate count')
    lp = LavaPaths(argparse.Namespace(project_name=args.project))
    if not inj.check_architecture_compatibility(lp.config['qemu']):
        raise ValueError('Generation requires a host capable of running the target architecture')
    if lp.config.get('force_div_zero'):
        raise ValueError('Competition generation requires real payloads, not debug traps')
    options = argparse.Namespace(bugtypes=args.bugtypes, knobTrigger=0, checkStacktrace=False,
                                 exitCode=args.exit_code, competition=True)
    allowed = inj.get_allowed_bugtype_num(options)
    supported = {BugKind.BUG_PTR_ADD, BugKind.BUG_REL_WRITE, BugKind.BUG_RET_BUFFER}
    if not allowed or not set(allowed) <= supported:
        raise ValueError('Crash grading currently supports ptr_add, rel_write and ret_buffer')
    # Seed zero has meaning to lavaTool; the legacy wrapper omits zero-valued seeds.
    if args.seed < 1:
        raise ValueError('--seed must be positive')
    output = Path(args.output_dir).resolve()
    output.mkdir(parents=True, exist_ok=False)
    private = output / 'private'
    private.mkdir()
    manifest = {'format': FORMAT, 'complete': False, 'project': lp.name,
                'command': lp.config['command'], 'architecture': lp.config['qemu'],
                'library_path': lp.config.get('library_path', ''), 'timeout': args.timeout,
                'expected_exit_code': args.exit_code, 'seed': args.seed, 'attempts': [],
                'minimum_validated': args.min_validated, 'bugs': [], 'hashes': {},
                'build_env': {k: lp.config['inject'].get(k) for k in
                              ('CC', 'CXX', 'CFLAGS', 'CXXFLAGS', 'LDFLAGS')},
                'target_tar_sha256': digest(lp.config['tarfile']),
                'config_sha256': hashlib.sha256(json.dumps(lp.config, sort_keys=True, default=str).encode()).hexdigest(),
                'lava_revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()}
    write_json(private / 'manifest.json', manifest)
    try:
        with LavaDatabase(lp.config) as db:
            query = db.scoped_bugs().join(DuaBytes, Bug.trigger == DuaBytes.id).join(Dua, DuaBytes.dua == Dua.id).filter(
                Dua.fake_dua.is_(False), Bug.type.in_(allowed)).order_by(Bug.id)
            if args.bug_ids:
                explicit = json.loads(args.bug_ids)
                if not isinstance(explicit, list) or any(type(x) is not int for x in explicit):
                    raise ValueError('--bug-ids must be a JSON array of integers')
                query = query.filter(Bug.id.in_(explicit))
                found = query.all()
                if {b.id for b in found} != set(explicit):
                    raise ValueError('Explicit IDs include unavailable, fake or unsupported bugs')
                selected = [bug_id for bug_id in explicit]
            else:
                selected = select_candidates(query.yield_per(500), args.candidate_count, args.seed, max_per_line=50)
            manifest['requested_ids'] = selected.copy()
            if len(selected) < args.min_validated:
                raise RuntimeError('Insufficient candidate bugs')
            inj.validate_bug_targets(db, selected)
            lp.bugs_top_dir = str(private / 'work')
            lp.set_bugs_parent(str(private / 'work' / 'injection'))
            for attempt in range(args.max_attempts):
                genFnTraceHelper(db, selected, str(lp.project_dir / 'fninstr'), str(lp.project_dir / 'getfns.json'))
                build, _, solutions = inj.inject_bugs(selected, db, lp, lp.config, options,
                    dataflow=lp.config.get('dataflow', False), competition=True, lavatoolseed=args.seed)
                attempt_dir = private / f'attempt-{attempt + 1}'
                attempt_dir.mkdir()
                source_tar = attempt_dir / 'source.tar.gz'
                subprocess.run(['git', 'archive', '--format=tar.gz', f'--prefix={lp.tar_source_root}/',
                                '-o', str(source_tar), f'build{build.id}'], cwd=lp.bugs_build, check=True)
                manifest['source'] = str(source_tar.relative_to(output))
                manifest['build'] = build.id
                manifest['solutions'] = {str(k): [v.hex() for v in values] for k, values in solutions.items()}
                manifest['variants'] = {}
                for mode in ('public', 'internal'):
                    install = build_variant(lp, source_tar, attempt_dir / mode, mode == 'internal')
                    manifest['variants'][mode] = {'install': str(install.relative_to(output))}
                manifest['seeds'] = []
                seed_dir = attempt_dir / 'seeds'
                seed_dir.mkdir()
                seeds = sorted((lp.config_dir / 'inputs').rglob('*'))
                for index, seed in enumerate(p for p in seeds if p.is_file()):
                    target = seed_dir / f'{index:05d}{seed.suffix}'
                    shutil.copy2(seed, target)
                    manifest['seeds'].append(str(target.relative_to(output)))
                if not manifest['seeds']:
                    raise ValueError('No public fuzzing seeds available')
                # The same mutation and internal validation machinery used by inject.py.
                validation = {}
                validation_paths = copy.copy(lp)
                validation_paths.bugs_install = str(output / manifest['variants']['internal']['install'])

                def runner(project, install, input_file, shell=False, command=None):
                    run = execute(command or project['command'], install, input_file,
                                  args.timeout, project.get('library_path', ''))
                    rv = -9 if run['timeout'] else run['exit_code']
                    return rv, (b'', run['stderr'].encode())

                inj.validate_bugs(selected, db, validation_paths, lp.config, [], build,
                    options, competition=True, bug_solutions=solutions,
                    bug_results=validation, runner=runner, require_validated=False)
                manifest['bugs'] = []
                answers = attempt_dir / 'answers'
                answers.mkdir()
                for bug in inj.validate_bug_targets(db, selected):
                    result = validation[bug.id]
                    generated = inj.get_build_dir(lp, build) / result['input']
                    answer = answers / f'{bug.id}.input'
                    shutil.copy2(generated, answer)
                    entry = inj.bug_manifest_entry(bug, result)
                    entry.update(answer=str(answer.relative_to(output)))
                    manifest['bugs'].append(entry)
                accepted, results = verify(output, manifest)
                manifest['attempts'].append({'build': build.id, 'selected': selected.copy(), 'results': results})
                write_json(private / 'manifest.json', manifest)
                # Only the final challenge must be unique per file/ATP line.
                accepted_bugs = [bug for bug in inj.get_bugs(db, selected) if bug.id in accepted]
                accepted = select_candidates(accepted_bugs, max(1, len(accepted_bugs)), args.seed)
                if len(accepted) < args.min_validated:
                    raise RuntimeError(f'Final paired yield {len(accepted)} < {args.min_validated}')
                if set(accepted) == set(selected):
                    build.compile = True
                    db.session.commit()
                    break
                selected = accepted
            else:
                raise RuntimeError('Subset reinjection did not converge within --max-attempts')
        # Explicit public allowlist: installed binaries/libraries and normal seeds only.
        public = output / 'public'
        public.mkdir()
        shutil.copytree(output / manifest['variants']['public']['install'], public / 'lava-install', symlinks=False)
        shutil.copytree(seed_dir, public / 'seeds')
        manifest['variants']['public']['install'] = 'public/lava-install'
        write_json(public / 'challenge.json', {k: manifest[k] for k in
                   ('format', 'project', 'command', 'architecture', 'library_path', 'timeout', 'expected_exit_code')})
        manifest['hashes'] = {str(p.relative_to(output)): digest(p)
            for folder in (public, output / manifest['variants']['internal']['install'], answers, seed_dir)
            for p in sorted(folder.rglob('*')) if p.is_file()}
        accepted, results = verify(output, manifest)
        if set(accepted) != set(selected):
            raise RuntimeError('Exported challenge failed paired replay')
        manifest['final_results'] = results
        manifest['complete'] = True
        write_json(private / 'manifest.json', manifest)
        print(f'Competition ready: {output} ({len(accepted)} validated bugs)')
    except BaseException as error:
        manifest['error'] = str(error)
        manifest['complete'] = False
        write_json(private / 'manifest.json', manifest)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    gen = commands.add_parser('generate', help='Generate a corpus after taint/mining')
    gen.add_argument('-p', '--project', required=True)
    gen.add_argument('--output-dir', required=True)
    gen.add_argument('--candidate-count', '-m', type=int, default=200)
    gen.add_argument('--min-validated', '-n', type=int, default=1)
    gen.add_argument('--bugtypes', default='ptr_add,rel_write')
    gen.add_argument('--bug-ids', help='Explicit JSON array of candidate IDs')
    gen.add_argument('--seed', type=int, default=1)
    gen.add_argument('--max-attempts', type=int, default=3)
    gen.add_argument('--timeout', type=float, default=5)
    gen.add_argument('--exit-code', type=int, default=0)
    for action in ('verify', 'grade'):
        cmd = commands.add_parser(action)
        cmd.add_argument('manifest', type=Path)
        if action == 'grade':
            cmd.add_argument('--input', type=Path, required=True)
    args = parser.parse_args(argv)
    if args.action == 'generate':
        generate(args)
    else:
        manifest = json.loads(args.manifest.read_text())
        root = args.manifest.resolve().parent.parent
        if manifest.get('format') != FORMAT or not manifest.get('complete'):
            parser.error('Manifest is unsupported or generation is incomplete')
        if args.action == 'grade':
            # Refuse grading against changed binaries.
            for name, expected in manifest['hashes'].items():
                if digest(root / name) != expected:
                    raise ValueError(f'Artifact changed: {name}')
            print(json.dumps(grade(root, manifest, args.input), indent=2))
        else:
            accepted, results = verify(root, manifest)
            print(json.dumps(results, indent=2))
            if set(accepted) != {bug['id'] for bug in manifest['bugs']}:
                raise SystemExit(1)


if __name__ == '__main__':
    main()
