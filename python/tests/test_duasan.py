"""Regression decisions for DUASan, using its actual C++ implementation.

Run: pytest -q python/tests/test_duasan.py
Requires a C++17 compiler, LLVM/Clang development libraries, generated LAVA
ODB/Protobuf sources and their libraries, and PostgreSQL server binaries.
LLVM_CONFIG and CXX select a toolchain. Missing compiler/LLVM or PostgreSQL
server tools skip the corresponding tests; compilation errors fail the suite.
The C++ driver includes duasan.cpp and renames its main; AST tests invoke its
helpers, and database tests invoke its real CLI against a disposable server.
The driver is compiled with -DNDEBUG to verify that production checks survive
Release-style builds with assert() disabled.
No application database or credentials are used. Set DUASAN_REQUIRE_DEPS=1 in
CI to turn missing-prerequisite skips into failures.

Why these decisions exist (maintenance map)
------------------------------------------
* test_expression_reads covers the old "Pointer? '&'?" TODO: forming &x must
  not qualify as reading x. Address computation can still read a pointer/index;
  *&x reads x, and indirect calls read their callee and argument expressions.
* The old array/'&' TODO is addressed for stored address-wrapped base names and
  index reads, NOT for arbitrary array-element identity. The same expression
  tests pin that boundary: &array[index] reads index, not the array's contents;
  array[index] can qualify the recorded base name &(array).
* test_scope_search covers non-VarDecl declarations (typedefs/records formerly
  caused null dereferences), empty names, and sibling/conditional block reads.
  The comment drift was in scopeCheck's nested-CompoundStmt branch: it said the
  recursive call checked locInScope, while the implementation did not. The guard
  at scopeCheck entry now enforces that check, with a positive containing-block
  test so the fix cannot merely reject every nested block.
* test_parameter_availability rejects empty names and excludes references as
  well as pointers from the by-value shortcut: neither initializes target bytes.
* test_source_prefix_boundary prevents /src/project-other from being mistaken
  for /src/project and covers exact-prefix/trailing-slash edge cases.
* test_sparse_ids_and_dry_run records why batching uses ordered IDs after the
  last loaded ID: an empty numeric ID window must not hide later candidates.
* The remaining database tests verify trace-index selection, transaction rollback
  after a later parse failure, dry-run persistence, and cleanup exemptions for
  bugs referenced by builds/runs and CHAFF_STACK_UNUSED extra DUAs.

Coverage tripwire
-----------------
Unmatched stored coordinates used to pass silently. The CLI now fails and rolls
back before cleanup if any loaded DUA never matched a parsed function, including
in dry runs. test_incomplete_coverage_rolls_back checks missing-file and shifted
line coordinates, preserves earlier updates and dependent bugs, and asserts that
errors identify an unchecked ID. test_partial_coverage_requires_explicit_override
pins the explicit opt-out for intentional subset runs. These are runtime checks,
not C++ assertions. A missing match suggests drift or incomplete input, but cannot
diagnose the cause; a shifted coordinate still inside a valid function can pass.
Removing -E needs source provenance/location validation beyond this count check.

C++ parsing/coverage errors throw internally. Owning the transaction with
unique_ptr makes unwinding roll it back before main catches std::exception,
prints the cause and exits 1. This is not a cross-language exception: Python's
check=True raises CalledProcessError for that exit. test_coverage_failure_stops_python
exercises both subprocess.run(check=True) and the pipeline's real run_local()
logging path (which catches CalledProcessError and raises SystemExit). The test
compiles that exact function and its standard-library imports from funcs.py's AST,
avoiding its unrelated ORM compatibility import without copying or mocking the
runner logic. run_local's capture_output=True path instead returns a code; it is
not the sanitization path.

Paper connection and limits
---------------------------
Hu, Hu and Dolan-Gavitt, Chaff Bugs (2018), IV-A1 states the initialization
requirement; V-B3 describes same/enclosing-scope references and the danger of
conditional initialization. See https://arxiv.org/html/1808.00659v1#S5.SS2.SSS3
DUASan filters previously discovered candidates; it does not discover taint or
prove initialization. Tests document implemented placement rules, not a formal
proof of the paper's guarantees. Name matching still loses declaration and
pointer/pointee identity; it has no full alias, lifetime, or control-flow analysis
and no per-element array matching. Conditional-expression conditions, return
expressions, switch cases and unbraced bodies are not fully searched. Runtime
pointer/string bounds checks described in V-B3 belong outside this file.

TestCallMatcher was an unregistered AST-dump helper, unused by production. It
was deleted along with its diagnostic-only test; indirect-call matching remains
covered by test_expression_reads. Do not restore dead production code just to
preserve a test count.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import pytest


ROOT = Path(__file__).resolve().parents[2]


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True,
                          timeout=120, **kwargs)


def missing_dependency(reason):
    """CI must execute these regressions rather than silently skip prerequisites."""
    if os.environ.get('DUASAN_REQUIRE_DEPS') == '1':
        pytest.fail(reason)
    pytest.skip(reason)


@pytest.fixture(scope='session')
def duasan_driver(tmp_path_factory):
    compiler = shutil.which(os.environ.get('CXX', 'g++'))
    llvm_config = shutil.which(os.environ.get('LLVM_CONFIG', 'llvm-config'))
    if not llvm_config:
        llvm_config = next((shutil.which(f'llvm-config-{version}')
                            for version in range(22, 10, -1)
                            if shutil.which(f'llvm-config-{version}')), None)
    if not compiler or not llvm_config:
        missing_dependency('DUASan tests require a C++ compiler and llvm-config')
    include = Path(run(llvm_config, '--includedir').stdout.strip())
    lib = Path(run(llvm_config, '--libdir').stdout.strip())
    clang_libs = sorted(lib.glob('libclang-cpp.so*'))
    if not clang_libs or not (include / 'clang/Tooling/Tooling.h').exists():
        missing_dependency('DUASan tests require Clang development headers and libclang-cpp')
    binary = tmp_path_factory.mktemp('duasan-build') / 'duasan-test'
    includes = [include, ROOT / 'tools/lavaDB/include',
                ROOT / 'tools/lavaODB/generated', ROOT / 'tools/lavaODB/include',
                ROOT / 'tools/include']
    command = [compiler, '-std=c++17', '-O0', '-DNDEBUG',
               f'-DDUASAN_SOURCE="{ROOT / "tools/duasan/src/duasan.cpp"}"',
               *(f'-I{directory}' for directory in includes),
               str(ROOT / 'python/tests/duasan/driver.cpp'),
               str(ROOT / 'tools/lavaODB/generated/lava-odb.cxx'),
               str(ROOT / 'tools/lavaODB/generated/lava.pb.cc'),
               str(clang_libs[0]), f'-L{lib}', f'-Wl,-rpath,{lib}',
               *run(llvm_config, '--libs', '--system-libs').stdout.split(),
               '-lodb-pgsql', '-lodb', '-lprotobuf', '-o', str(binary)]
    result = subprocess.run(command, text=True, capture_output=True, timeout=180)
    assert result.returncode == 0, result.stdout + result.stderr
    return binary


def analyze(binary, tmp_path, mode, code, lvalue):
    source = tmp_path / 'case.cpp'
    source.write_text(code)
    return int(run(str(binary), '--ast', mode, str(source), lvalue).stdout)


@pytest.mark.parametrize('expression,lvalue,expected', [
    ('read(x)', '(x)', 1),
    ('write(&x)', '(x)', 0),  # Taking an address does not read the object's bytes.
    ('indirect(x)', '(x)', 1),  # Arguments of indirect calls are still inspected.
    ('indirect(0)', '(indirect)', 1),
    ('read(*&x)', '(x)', 1),  # Dereferencing the taken address reads x.
    ('write(&object.field)', '((object).field)', 0),
    ('read(object.field)', '((object).field)', 1),
    ('read(object.field)', '(object)', 0),  # Preserve exact member-chain matching.
    ('read(object.field)', '((object).other)', 0),
    ('read(array[index])', '(index)', 1),  # Subscript evaluation reads the index.
    ('write(&array[index])', '(index)', 1),
    ('write(&array[index])', '(array)', 0),
    ('write(&pointer[index])', '(pointer)', 1),
    ('write(&pointer[index])', '(index)', 1),
    ('write(&*pointer)', '(pointer)', 1),
    ('read(array[index])', '&(array)', 1),  # Stored address wrapper around the root.
    ('read(array[index])', '', 0),
])
def test_expression_reads(duasan_driver, tmp_path, expression, lvalue, expected):
    code = '''
int read(int); int write(int *);
void subject(int x, int index, int *pointer, int (*indirect)(int)) {
  struct { int field; int other; } object;
  int array[4];
  int probe = (EXPRESSION, 0);
}
'''.replace('EXPRESSION', expression)
    assert analyze(duasan_driver, tmp_path, 'expr', code, lvalue) == expected


@pytest.mark.parametrize('parameter,lvalue,expected', [
    ('int x', '(x)', 1),
    ('int *x', '(x)', 0),
    ('int &x', '(x)', 0),  # A reference does not initialize the referred object.
    ('int &&x', '(x)', 0),
    ('int x', '', 0),
])
def test_parameter_availability(duasan_driver, tmp_path, parameter, lvalue, expected):
    assert analyze(duasan_driver, tmp_path, 'param',
                   f'void subject({parameter}) {{}}', lvalue) == expected


@pytest.mark.parametrize('code,lvalue,expected_line', [
    ('void subject(int x) {\n typedef int alias;\n int probe = x;\n /*DUA*/;\n}', '(x)', 3),
    ('void subject(int x) {\n struct Local {};\n int probe = x;\n /*DUA*/;\n}', '(x)', 3),
    ('void subject(int x) {\n int probe = x;\n /*DUA*/;\n}', '', 0),
    # A same-named object in a sibling block is not the DUA's object.
    ('void subject() {\n { int x; int other = x; }\n { int x; /*DUA*/; }\n}', '(x)', 0),
    # Paper V-B3: a read only inside a conditional block cannot justify a
    # siphon in its enclosing block (the other branch might never read pointer).
    ('void consume(int); void subject(int cond, int *pointer) {\n'
     ' if (cond) { consume(*pointer); ; }\n /*DUA*/;\n}', '(pointer)', 0),
    # Restricting recursion must still find reads inside the containing block.
    ('void subject(int x) {\n { int probe = x;\n /*DUA*/; }\n}', '(x)', 2),
])
def test_scope_search(duasan_driver, tmp_path, code, lvalue, expected_line):
    assert analyze(duasan_driver, tmp_path, 'scope', code, lvalue) == expected_line


@pytest.mark.parametrize('filename,prefix,expected', [
    ('/src/project/file.c', '/src/project', 'file.c'),
    ('/src/project-other/file.c', '/src/project', ''),
    ('/src/project', '/src/project', ''),
    ('/src/project///', '/src/project', ''),
    ('/src/file.c', '/', 'src/file.c'),
])
def test_source_prefix_boundary(duasan_driver, filename, prefix, expected):
    assert run(str(duasan_driver), '--prefix', filename, prefix).stdout == expected


@pytest.fixture(scope='session')
def postgres():
    config = shutil.which('pg_config')
    if not config or not shutil.which('psql'):
        missing_dependency('PostgreSQL tools are required for DUASan integration tests')
    bindir = Path(run(config, '--bindir').stdout.strip())
    if not (bindir / 'initdb').exists() or os.geteuid() == 0:
        missing_dependency('A non-root user and PostgreSQL server binaries are required')
    # Keep Unix socket paths short and isolate the server from TCP/network clients.
    with tempfile.TemporaryDirectory(prefix='duasan-pg-') as directory:
        root = Path(directory)
        data = root / 'data'
        run(str(bindir / 'initdb'), '-D', str(data), '-A', 'trust', '-U', 'duasan_test')
        run(str(bindir / 'pg_ctl'), '-D', str(data), '-l', str(root / 'server.log'),
            '-o', f"-F -k {root} -c listen_addresses=''", '-w', 'start')
        def sql(query):
            return run('psql', '-X', '-h', str(root), '-U', 'duasan_test',
                       '-d', 'postgres', '-v', 'ON_ERROR_STOP=1', '-At',
                       input=query).stdout.strip()
        try:
            yield root, sql
        finally:
            run(str(bindir / 'pg_ctl'), '-D', str(data), '-m', 'immediate', '-w', 'stop')


@pytest.fixture
def database(postgres):
    socket, sql = postgres
    sql((ROOT / 'tools/lavaODB/generated/lava.sql').read_text())
    sql("INSERT INTO filetaint VALUES (1, 'seed', 'digest', '', 'x86_64', true)")
    return socket, sql


def seed_dua(sql, dua_id, lvalue, line, column=3, trace_index=10):
    sql(f"""
INSERT INTO sourcelval VALUES
  ({dua_id}, 'input.cpp', {line}, {column}, {line}, {column}, '{lvalue}');
INSERT INTO dua (id,lval,byte_tcn,all_labels,inputfile,max_tcn,max_cardinality,
                 instr,fake_dua,trace_index,length)
VALUES ({dua_id},{dua_id},'{{}}','{{}}',1,0,0,{dua_id},false,{trace_index},4);
""")


def invoke(binary, tmp_path, socket, source, dry_run=False, bad_source=False,
           allow_unmatched=False):
    path = tmp_path / 'input.cpp'
    path.write_text(source)
    files = [str(path)]
    if bad_source:
        bad = tmp_path / 'bad.cpp'
        bad.write_text('void broken( {')
        files.append(str(bad))
    env = dict(os.environ, POSTGRES_USER='duasan_test', POSTGRES_PASSWORD='unused')
    command = [str(binary), '--db=postgres', f'--host={socket}',
               f'--src-prefix={tmp_path}', *(['--dry-run'] if dry_run else []),
               *(['--allow-unmatched-duas'] if allow_unmatched else []),
               *files, '--', '-std=c++17']
    return subprocess.run(command, env=env, text=True, capture_output=True, timeout=60)


@pytest.mark.parametrize('dry_run', [False, True])
def test_sparse_ids_and_dry_run(duasan_driver, tmp_path, database, dry_run):
    socket, sql = database
    seed_dua(sql, 1, '(x)', 3)
    seed_dua(sql, 200005, '(y)', 4)  # Beyond an entirely empty old ID window.
    result = invoke(duasan_driver, tmp_path, socket,
                    'void subject(int x) {\n  int y;\n  x++;\n  y = 1;\n}', dry_run)
    assert result.returncode == 0, result.stderr
    if dry_run:
        assert 'checked 2 DUAs; rejected 1' in result.stderr
    assert sql('SELECT id,fake_dua FROM dua ORDER BY id') == (
        '1|f\n200005|f' if dry_run else '1|f\n200005|t')


@pytest.mark.parametrize('has_trace', [False, True])
def test_trace_relocation_requires_later_matching_trace(duasan_driver, tmp_path, database, has_trace):
    socket, sql = database
    seed_dua(sql, 1, '*(p)', 3)
    if has_trace:
        # Earlier matches are ineligible; choose the first matching later index.
        for index in [5, 20, 30]:
            sql(f"INSERT INTO sourcetrace VALUES ({index},{index},1,'input.cpp',5,3,5,3)")
    result = invoke(duasan_driver, tmp_path, socket,
                    'void use(int);\nvoid subject(int *p) {\n  ;\n  use(*p);\n  ;\n}')
    assert result.returncode == 0, result.stderr
    assert sql('SELECT trace_index,fake_dua FROM dua') == ('20|f' if has_trace else '10|t')


def test_parse_failure_rolls_back_earlier_dua_updates(duasan_driver, tmp_path, database):
    socket, sql = database
    seed_dua(sql, 1, '(y)', 3)
    result = invoke(duasan_driver, tmp_path, socket,
                    'void subject() {\n  int y;\n  y = 1;\n}', bad_source=True)
    assert result.returncode == 1
    assert 'rolling back DUA changes' in result.stderr
    assert sql('SELECT fake_dua FROM dua') == 'f'


@pytest.mark.parametrize('dry_run', [False, True])
def test_cleanup_preserves_referenced_bugs_and_unused_chaff_extras(
        duasan_driver, tmp_path, database, dry_run):
    socket, sql = database
    seed_dua(sql, 1, '(y)', 3)
    seed_dua(sql, 2, '(x)', 4)
    sql("""
INSERT INTO duabytes VALUES (1,1,0,4,'{}'), (2,2,0,4,'{}');
INSERT INTO attackpoint VALUES (1,'input.cpp',4,3,4,3,0);
INSERT INTO bug VALUES
 (1,0,1,1,1,NULL,0,'{}',0,0),
 (2,0,2,2,1,NULL,0,'{1}',0,0),
 (3,5,2,2,1,NULL,0,'{1}',0,0),
 (4,0,1,1,1,NULL,0,'{2}',0,0),
 (5,0,1,1,1,NULL,0,'{1}',0,0),
 (6,5,1,1,1,NULL,0,'{}',0,0),
 (7,0,2,2,1,NULL,0,'{}',0,0);
INSERT INTO build VALUES (1,'',true);
INSERT INTO build_bugs VALUES (1,0,4);
INSERT INTO run VALUES (1,1,5,0,'',true,true);
""")
    result = invoke(duasan_driver, tmp_path, socket,
                    'void subject(int x) {\n  int y;\n  y = 1;\n  x++;\n}', dry_run)
    assert result.returncode == 0, result.stderr
    # 1/2 use fake trigger/extra bytes. Type 5 exempts extras, never triggers (6).
    # 4/5 are protected by build/run references; 7 uses only accepted bytes.
    assert sql('SELECT id FROM bug ORDER BY id') == (
        '1\n2\n3\n4\n5\n6\n7' if dry_run else '3\n4\n5\n7')


def test_standalone_sanitizer_preview_preserves_database_and_live_source(
        duasan_driver, tmp_path, database):
    """Exercise the snapshot CLI with real C++/PostgreSQL, not only a stub tool."""
    socket, sql = database
    seed_dua(sql, 1, '(x)', 3)
    seed_dua(sql, 200005, '(y)', 4)
    baseline = 'void subject(int x) {\n  int y;\n  x++;\n  y = 1;\n}'
    source = tmp_path / 'input.cpp'
    source.write_text(baseline)
    run('git', '-C', str(tmp_path), 'init', '-q')
    run('git', '-C', str(tmp_path), 'add', 'input.cpp')
    run('git', '-C', str(tmp_path), '-c', 'user.name=Test',
        '-c', 'user.email=test@example.com', 'commit', '-qm', 'Pre-query source')
    (tmp_path / 'compile_commands.json').write_text(json.dumps([
        dict(directory=str(tmp_path), file=str(source),
             arguments=['clang++', '-std=c++17', '-c', str(source)])]))
    instrumented = '#include <lava/pirate_mark_lava.h>\n' + baseline
    source.write_text(instrumented)
    env = dict(os.environ, POSTGRES_USER='duasan_test', POSTGRES_PASSWORD='unused')
    result = subprocess.run(
        [sys.executable, str(ROOT / 'python/src/pyroclastic/utils/sanitize.py'),
         str(tmp_path), '--db', 'postgres', '--host', str(socket),
         '--duasan', str(duasan_driver)],
        env=env, text=True, capture_output=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert 'checked 2 DUAs; rejected 1' in result.stderr
    assert sql('SELECT id,fake_dua FROM dua ORDER BY id') == '1|f\n200005|f'
    assert source.read_text() == instrumented


@pytest.mark.parametrize('dry_run', [False, True])
@pytest.mark.parametrize('mismatch', ['line', 'file'])
def test_incomplete_coverage_rolls_back(duasan_driver, tmp_path, database, dry_run, mismatch):
    """Never commit a partially checked batch or delete bugs after coverage loss."""
    socket, sql = database
    seed_dua(sql, 1, '(y)', 3)  # Rejection occurs before the audit discovers ID 2.
    seed_dua(sql, 2, '(x)', 999 if mismatch == 'line' else 3)
    if mismatch == 'file':
        sql("UPDATE sourcelval SET loc_filename='missing.cpp' WHERE id=2")
    sql("""
INSERT INTO duabytes VALUES (1,1,0,4,'{}');
INSERT INTO attackpoint VALUES (1,'input.cpp',3,3,3,3,0);
INSERT INTO bug VALUES (1,0,1,1,1,NULL,0,'{}',0,0);
""")
    result = invoke(duasan_driver, tmp_path, socket,
                    'void subject(int x) {\n  int y;\n  y = 1;\n}', dry_run)
    assert result.returncode == 1
    assert 'Unchecked DUA 2 at' in result.stderr
    assert '1 of 2 DUAs in this batch' in result.stderr
    assert 'source-coordinate drift' in result.stderr
    assert 'rolling back DUA changes without deleting bugs' in result.stderr
    assert sql('SELECT id,fake_dua FROM dua ORDER BY id') == '1|f\n2|f'
    assert sql('SELECT id FROM bug') == '1'


def test_partial_coverage_requires_explicit_override(duasan_driver, tmp_path, database):
    """Partial-source users may opt out, but skipped coverage must stay visible."""
    socket, sql = database
    seed_dua(sql, 1, '(x)', 3)
    seed_dua(sql, 2, '(x)', 999)
    result = invoke(duasan_driver, tmp_path, socket,
                    'void subject(int x) {\n  ;\n  x++;\n}',
                    dry_run=True, allow_unmatched=True)
    assert result.returncode == 0, result.stderr
    assert 'coverage mismatch' in result.stderr
    assert 'checked 1 of 2 loaded DUAs; unmatched 1' in result.stderr
    assert sql('SELECT id,fake_dua FROM dua ORDER BY id') == '1|f\n2|f'


@pytest.mark.parametrize('caller', ['subprocess', 'run_local'])
def test_coverage_failure_stops_python(duasan_driver, tmp_path, database, caller):
    """C++ exception -> rollback -> exit 1 -> Python failure, without assertions."""
    socket, sql = database
    seed_dua(sql, 1, '(y)', 3)
    seed_dua(sql, 2, '(x)', 999)
    source = tmp_path / 'input.cpp'
    source.write_text('void subject(int x) {\n  int y;\n  y = 1;\n}')
    command = [str(duasan_driver), '--db=postgres', f'--host={socket}',
               f'--src-prefix={tmp_path}', str(source), '--', '-std=c++17']
    credentials = dict(POSTGRES_USER='duasan_test', POSTGRES_PASSWORD='unused')
    if caller == 'subprocess':
        with pytest.raises(subprocess.CalledProcessError) as failure:
            subprocess.run(command, env=dict(os.environ, **credentials),
                           check=True, text=True, capture_output=True, timeout=60)
        assert failure.value.returncode == 1
        diagnostics = failure.value.stderr
    else:
        import ast

        # Execute the real runner without the module's unrelated ORM re-export.
        # Its standard-library imports supply all globals used by run_local.
        runner_path = ROOT / 'python/src/pyroclastic/utils/funcs.py'
        module = ast.parse(runner_path.read_text())
        module.body = [node for node in module.body
                       if (isinstance(node, (ast.Import, ast.ImportFrom))
                           and getattr(node, 'level', 0) == 0)
                       or (isinstance(node, ast.FunctionDef) and node.name == 'run_local')]
        namespace = {}
        exec(compile(module, str(runner_path), 'exec'), namespace)
        run_local = namespace['run_local']

        log = tmp_path / 'duasan.log'
        with pytest.raises(SystemExit) as failure:
            run_local(command, logfile=str(log), env=credentials)
        assert failure.value.code == 1
        diagnostics = log.read_text()
    assert 'DUASan failed: DUASan refuses incomplete coverage' in diagnostics
    assert sql('SELECT id,fake_dua FROM dua ORDER BY id') == '1|f\n2|f'
