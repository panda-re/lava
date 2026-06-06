import os
import sys
import shutil
from pathlib import Path
# LAVA
from ..utils.funcs import read_compile_db, configure_project, run_local, preprocess, unpack_tar, make_and_install
from ..utils.vars import LavaPaths
from .fninstr import analysis


def step_add_queries(lava_path: LavaPaths, atp_type=None):
    # 1. Setup Directories
    if not lava_path.project_dir.exists():
        lava_path.project_dir.mkdir(parents=True)

    os.chdir(lava_path.project_dir)

    # 2. Extract Tarball
    unpack_tar(lava_path)

    print(f"Changing to source directory to {lava_path.source_directory}")
    os.chdir(lava_path.source_directory)

    # 3. Git Initialization
    run_local("rm -rf .git || true", shell=True)
    run_local(["git", "init"])
    run_local(["git", "config", "user.name", "LAVA"])
    run_local(["git", "config", "user.email", "nobody@nowhere"])
    run_local(["git", "add", "-A", "."])
    run_local(["git", "commit", "-m", "Unmodified source."])

    configure_project(lava_path)
    preprocess(lava_path)

    # 4. Make with compiledb and make install
    make_and_install(lava_path)

    # 5. Get C files and Insert Headers
    os.chdir(lava_path.project_dir)

    c_dirs, c_files = read_compile_db(lava_path.source_directory)

    # 6. Given the Debian package installed in /usr/include, we now copy it to LAVA project.
    include_dir = Path("/usr/include")
    headers = ["pirate_mark_lava.h"]
    for directory in c_dirs:
        dir_path = Path(directory)
        if dir_path.is_dir():
            for name in headers:
                src = include_dir / name
                if src.is_file():
                    shutil.copy2(src, dir_path)
                else:
                    print(f"Warning: {src} not found, skipping.")

    # 7. lavaFnTool & fninstr.py
    for file in c_files:
        run_local(["lavaFnTool", file])

    fn_files = [file + ".fn" for file in c_files]
    fninstr_path = lava_path.project_dir / "fninstr"

    # 8. Call fninstr.py analysis
    analysis(lava_path.config['name'], str(fninstr_path), fn_files)

    # 9. lavaTool Injection
    atp_flag = f"-{atp_type}" if atp_type else ""

    for file in c_files:
        lt_cmd = [
            "lavaTool", "-action=query",
            f"-lava-db={lava_path.project_dir}/lavadb",
            f"-lava-wl={fninstr_path}",
            f"-p={lava_path.source_directory}/compile_commands.json",
            f"-src-prefix={lava_path.source_directory.resolve()}",
            f"-db={lava_path.config['db']}",
            file
        ]
        if atp_flag:
            lt_cmd.append(atp_flag)
        if lava_path.config.get('dataflow', False):
            lt_cmd.append("-arg_dataflow")

        run_local(lt_cmd)

    # 10. Apply Replacements
    for directory in c_dirs:
        run_local([str(lava_path.llvm_path / "bin" / "clang-apply-replacements"), "."], cwd=directory)

    # 11. Verification
    for file in c_files:
        with open(file, 'r') as content:
            if "pirate_mark_lava.h" not in content.read():
                print(f"FATAL ERROR: LAVA queries missing from {file}")
                sys.exit(1)
