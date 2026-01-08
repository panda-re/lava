import os
import sys
import tarfile
import subprocess
import shlex
import shutil
from pathlib import Path
import argparse
import json
# LAVA
from ..utils.vars import parse_vars
from ..utils.sw_btrace_to_compiledb import main as sw_btrace_to_compiledb
from .get_c_files import process_compile_commands
from .fninstr import analysis


def run_cmd(cmd, cwd=None, env=None, shell=False):
    """Helper to run shell commands and exit on error."""
    print(f"Executing: {cmd if isinstance(cmd, str) else ' '.join(cmd)}, with env: {env}")
    full_env = os.environ.copy()
    if env:
        # Merge your CC, CXX, CFLAGS
        full_env.update({key: str(value) for key, value in env.items()})
    try:
        subprocess.check_call(cmd, cwd=cwd, env=full_env, shell=shell)
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        sys.exit(1)


class QueryManager:
    def __init__(self, args: argparse.Namespace):
        self.config = parse_vars(args.project_name)
        self.name = self.config['name']
        self.directory = Path(self.config['directory'])
        self.project_dir = self.directory / self.name
        self.tarfile_path = Path(self.config['tarfile'])
        self.llvm_path = Path(self.config.get('llvm', '/usr/lib/llvm-14'))


    def step_add_queries(self, atp_type=None):
        # 1. Setup Directories
        if not self.project_dir.exists():
            self.project_dir.mkdir(parents=True)

        os.chdir(self.project_dir)

        # 2. Extract Tarball
        with tarfile.open(self.tarfile_path) as tar:
            # Get top level directory name of the tar-ball
            source_dirname = tar.getnames()[0].split(os.path.sep)[0]
            source_path = self.project_dir / source_dirname

            if source_path.exists():
                print(f"Deleting existing source: {source_path}")
                shutil.rmtree(source_path)

            print(f"Extracting {self.tarfile_path}...")
            tar.extractall(path=self.project_dir)

        print(f"Changing to source directory to {source_path}")
        os.chdir(source_path)

        # 3. Git Initialization
        run_cmd("rm -rf .git || true", shell=True)
        run_cmd(["git", "init"])
        run_cmd(["git", "config", "user.name", "LAVA"])
        run_cmd(["git", "config", "user.email", "nobody@nowhere"])
        run_cmd(["git", "add", "-A", "."])
        run_cmd(["git", "commit", "-m", "Unmodified source."])

        # 4. Configure
        install_dir = source_path / "lava-install"
        install_dir.mkdir(exist_ok=True)

        env = self.config['env_var']
        # First pre-process, append the makefile.fixup to Makefile for easy pre-processing.
        if not self.config.get('preprocessed', False):
            print("Preprocessing Source code...")
            with open(Path(__file__).parent.parent / "data/makefile.fixup", "r") as mf:
                modified_make = mf.read()

            with open(source_path / "Makefile", "a+") as mf:
                mf.write("\n" + modified_make + "\n")

            run_cmd(shlex.split("make lava_preprocess"), env=env)
            run_cmd(["git", "add", "."])
            run_cmd(["git", "commit", "-m", "Pre-processed source."])

        configure_command = self.config.get('configure', '')
        if configure_command != '':
            full_config = f"{configure_command} --prefix={install_dir}"
            run_cmd(shlex.split(full_config), env=env)

        # 5. Make with Btrace
        # Handling the '&&' split logic from bash
        make_commands = [c.strip() for c in self.config['make'].split('&&')]
        env["LD_PRELOAD"] = "libsw-btrace.so"
        env["BTRACE_LOG"] = "btrace.log"

        for m_cmd in make_commands:
            run_cmd(shlex.split(m_cmd), env=env)

        # 6. Install
        run_cmd(self.config['install'], shell=True)

        # 7. Create compile_commands.json
        # Logic for clang include path
        clang_include = self.llvm_path / "lib/clang" / self.config["llvm-version"] / "include"

        # Call sw_btrace_to_compiledb main
        sw_btrace_to_compiledb(str(clang_include))

        # Handle extra_compile_commands.json if exists
        extra_json = self.project_dir / "extra_compile_commands.json"
        if extra_json.exists():
            # Standard Python JSON merge would be safer, but mimicking sed/tail logic:
            with open("compile_commands.json", "r") as f:
                base = json.load(f)
            with open(extra_json, "r") as f:
                extra = json.load(f)
            base.extend(extra)
            with open("compile_commands.json", "w") as f:
                json.dump(base, f, indent=4)

        run_cmd(["git", "add", "compile_commands.json"])
        run_cmd(["git", "commit", "-m", "Add compile_commands.json."])

        # 8. Get C files and Insert Headers
        os.chdir(self.project_dir)

        c_files = []
        c_dirs = []
        for entry in process_compile_commands(source_dirname):
            c_files.append(os.path.join(entry['directory'], entry['file']))
            c_dirs.append(entry['directory'])

        # Given the Debian package installed in /usr/include, we now copy it to LAVA project.
        # TODO: Once PANDA puts hypercall in its include path, we can likely remove all but pirate file.
        include_dir = Path("/usr/include")
        headers = ["hypercall.h", "pirate_mark_lava.h", "panda_hypercall_struct.h"]
        for directory in c_dirs:
            dir_path = Path(directory)
            if dir_path.is_dir():
                for name in headers:
                    src = include_dir / name
                    if src.is_file():
                        shutil.copy2(src, dir_path)
                    else:
                        print(f"Warning: {src} not found, skipping.")

        # 9. lavaFnTool & fninstr.py
        for file in c_files:
            run_cmd(["lavaFnTool", file])

        fn_files = [file + ".fn" for file in c_files]
        fninstr_path = self.project_dir / "fninstr"

        # Call fninstr.py analysis
        analysis(self.config['name'], str(fninstr_path), fn_files)

        # 10. lavaTool Injection
        atp_flag = f"-{atp_type}" if atp_type else ""

        for file in c_files:
            lt_cmd = [
                "lavaTool", "-action=query",
                f"-lava-db={self.project_dir}/lavadb",
                f"-lava-wl={fninstr_path}",
                f"-p={source_path}/compile_commands.json",
                f"-src-prefix={source_path.resolve()}",
                f"-db={self.config['db']}",
                file
            ]
            if atp_flag:
                lt_cmd.append(atp_flag)
            if self.config.get('dataflow', False):
                lt_cmd.append("-arg_dataflow")

            run_cmd(lt_cmd)

        # 11. Apply Replacements
        for directory in c_dirs:
            run_cmd([str(self.llvm_path / "bin/clang-apply-replacements"), "."], cwd=directory)

        # 12. Verification
        for file in c_files:
            with open(file, 'r') as content:
                if "pirate_mark_lava.h" not in content.read():
                    print(f"FATAL ERROR: LAVA queries missing from {file}")
                    sys.exit(1)
