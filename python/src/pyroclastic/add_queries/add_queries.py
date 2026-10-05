import os
import re
import sys
# LAVA
from ..utils.funcs import read_compile_db, configure_project, run_local, preprocess, unpack_tar, make_and_install, apply_replacements
from ..utils.vars import LavaPaths
from .fninstr import analysis


def step_add_queries(lava_path: LavaPaths, atp_type=None):
    # 1. Setup Directories
    if not lava_path.project_dir.exists():
        lava_path.project_dir.mkdir(parents=True)

    os.chdir(lava_path.project_dir)

    # 2. Extract Tarball, configure, and preprocess
    unpack_tar(lava_path)

    print(f"Changing to source directory to {lava_path.source_directory}")
    os.chdir(lava_path.source_directory)

    configure_project(lava_path)
    # preprocess() does its own throwaway build internally (to learn each
    # file's real compile flags from compile_commands.json) before macro-
    # flattening anything -- this is the SECOND, real build, whose
    # compile_commands.json is what everything below actually instruments.
    preprocess(lava_path)

    # 4. Make with compiledb and make install
    make_and_install(lava_path)

    # 5. Get C files and Insert Headers
    os.chdir(lava_path.project_dir)

    c_dirs, c_files = read_compile_db(lava_path.source_directory)

    # compiledb traces the whole dependency chain of the "make" target, which
    # can include host-side build tools (parser generators, etc.) or codegen
    # templates that happen to have their own single-file compile_commands.json
    # entry but were never meant to be parsed as standalone, real C (e.g.
    # libpng's pnglibconf.c is a template consumed by an awk script after -E,
    # not compilable source -- lavaFnTool trying to parse it directly hits
    # "unknown type name 'PNG_DFN'", a marker token dfn.awk expects, not a
    # real macro). Matches either a directory component (.../tool/...) or an
    # exact trailing filename (.../pnglibconf.c) so one setting covers both.
    exclude_dirs = lava_path.config['instrument_exclude_dirs']
    if exclude_dirs:
        junk = re.compile(r'/(' + exclude_dirs + r')(/|$)')
        c_files = {f for f in c_files if not junk.search(f)}
        c_dirs = {os.path.dirname(f) for f in c_files}

    # 7. lavaFnTool & fninstr.py
    for file in c_files:
        run_local(["lavaFnTool", file])

    fn_files = [file + ".fn" for file in c_files]
    fninstr_path = lava_path.project_dir / "fninstr"

    # 8. Call fninstr.py analysis
    analysis(str(fninstr_path), fn_files, lava_path.config)

    # 9. lavaTool Injection
    atp_flag = f"-{atp_type}" if atp_type else ""

    for file in c_files:
        lt_cmd = [
            "lavaTool", "-action=query",
            f"-lava-db={lava_path.project_dir}/lavadb",
            f"-lava-wl={fninstr_path}",
            f"-p={lava_path.source_directory}/compile_commands.json",
            f"-src-prefix={lava_path.source_directory.resolve()}",
            f"-host={lava_path.config['database']}",
            f"-db={lava_path.config['db']}",
            file
        ]
        if atp_flag:
            lt_cmd.append(atp_flag)
        if lava_path.config.get('dataflow', False):
            lt_cmd.append("-arg_dataflow")

        run_local(lt_cmd)

    # 10. Apply Replacements
    apply_replacements(lava_path.source_directory, c_files, str(lava_path.llvm_path / "bin" / "clang-apply-replacements"))

    # 11. Verification
    for file in c_files:
        with open(file, 'r') as content:
            if "pirate_mark_lava.h" not in content.read():
                print(f"FATAL ERROR: LAVA queries missing from {file}")
                sys.exit(1)
