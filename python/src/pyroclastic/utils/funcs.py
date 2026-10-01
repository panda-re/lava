import datetime
import sys
from collections import deque
import subprocess
import os
import shutil
import time
import argparse
import json
import tarfile
import shlex
import tempfile
from typing import Tuple, Set, Optional, Union, List
from contextlib import nullcontext
from pathlib import Path
from ..utils.vars import LavaPaths


def get_inject_parser():
    """
    Returns a parser with all arguments needed for inject.py
    """
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-b', '--bugid', action="store", default=-1,
                        help='Bug id (otherwise, highest scored will be chosen)')
    parser.add_argument('--randomize', action='store_true',
                        help='Choose the next bug randomly rather than by score')
    parser.add_argument('-l', '--buglist', action="store",
                        help='Inject this list of bugs')
    parser.add_argument('--knobTrigger', metavar='int', type=int, action="store", default=0,
                        help='specify a knob trigger style bug, eg -k [sizeof knob offset]')
    parser.add_argument('-s', '--skipInject', action="store_true",
                        help='skip the inject phase and just run the bugged binary on fuzzed inputs')
    parser.add_argument('--checkStacktrace', action="store_true",
                        help='When validating a bug, make sure it manifests at same line as lava-inserted trigger')
    parser.add_argument('-e', '--exitCode', action="store", default=0, type=int,
                        help='Expected exit code when program exits without crashing. Default 0')
    parser.add_argument('-bb', '--balance', action="store_true",
                        help='Attempt to balance bug types, i.e. inject as many of each type')
    parser.add_argument('--competition', action="store_true",
                        help='Inject in competition mode where logging will be added in #IFDEFs')
    # Was from the original common parser
    parser.add_argument("-n", "--count", type=int, default=100,
                        help="Number of bugs to inject at once")
    parser.add_argument("-y", "--bugtypes", type=str,
                        default="ptr_add,rel_write,malloc_off_by_one,ret_buffer",
                        help="Comma separated list of bug types")
    return parser


def print_tail(logfile, n: int = 22):
    if os.path.exists(logfile):
        with open(logfile, "r") as f:
            for line in deque(f, n):
                print(line.strip())


def read_compile_db(compile_directory: str) -> Tuple[Set[str], Set[str]]:
    """
    Reads a compile_commands.json file and returns its contents as a list of dictionaries.

    :param compile_directory: Path to the compile_commands.json file
    :return: A tuple containing:
             - A set of directories where C files are located
             - A set of full paths to C files
    """
    with open(os.path.join(compile_directory, 'compile_commands.json'), 'r') as f:
        compile_commands = json.load(f)

    c_files = set()
    c_dirs = set()
    for entry in compile_commands:
        real_file = os.path.realpath(os.path.join(entry['directory'], entry['file']))
        c_files.add(real_file)
        c_dirs.add(os.path.dirname(real_file))
    return c_dirs, c_files


def progress(step_name: str, show_date: int | bool, message: str):
    """
    Python port of the Bash progress function.

    :param step_name: The string to show in green brackets (e.g., "queries")
    :param show_date: Integer or Boolean. If 1/True, prints the current timestamp.
    :param message: The main progress message to display in bold.
    """
    if show_date == 1 or show_date is True:
        print(datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Z %Y"))

    # ANSI Escape Codes:
    # \033[32m = Green
    # \033[1m  = Bold
    # \033[0m  = Reset
    print(f"\033[32m[{step_name}]\033[0m \033[1m{message}\033[0m")


def run_local(
    command: Union[str, List[str]], 
    logfile: Optional[str] = None,
    cwd: Optional[str] = None, 
    env: Optional[dict] = None, 
    shell: bool = False,
    capture_output: bool = False,
    debug: bool = False
) -> Union[subprocess.CompletedProcess, Tuple[int, Tuple[bytes, bytes]]]:
    """
    Unified, industrial-grade command runner for LAVA/FuzzBench orchestration.
    Replaces both old legacy variants, supporting stream logging and memory capture.
    """
    # 1. Sanitize string commands when shell=False (ported from old debt)
    if isinstance(command, str) and not shell:
        command = shlex.split(command)

    cmd_str = command if isinstance(command, str) else ' '.join(command)
    env_string = " ".join([f"{k}='{v}'" for k, v in env.items()]) if env else ""
    
    # 2. Debug print optimization (ported from old debt)
    if debug:
        print(f"[DEBUG] run_local({env_string} {subprocess.list2cmdline(command) if isinstance(command, list) else command})")
    else:
        log_display = logfile if logfile else ("Memory Capture" if capture_output else "Terminal Screen")
        print(f"[*] Running: {cmd_str} (Log: {log_display})")

    # 3. Re-create and merge execution environments safely
    full_env = os.environ.copy()
    if env:
        full_env.update({key: str(value) for key, value in env.items()})

    # 4. Safely configure shell-specific parameters
    extra_args = {"executable": "/bin/bash"} if shell else {}

    # 5. EXECUTION ROUTE A: Memory Capture (Drop-in replacement for the old tuple return)
    if capture_output:
        try:
            # We use subprocess.run without check=True here because the old function
            # manually returns the code instead of raising an exception.
            result = subprocess.run(
                command,
                shell=shell,
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=full_env,
                check=False,
                **extra_args
            )
            return result.returncode, (result.stdout, result.stderr)
        except Exception as e:
            print(f"\n[!] Critical capture failure: {e}")
            sys.exit(1)

    # 6. EXECUTION ROUTE B: Standard Logging Stream (Your master context-manager architecture)
    if logfile and logfile not in ["/dev/stdout", "sys.stdout"]:
        log_path = Path(logfile)
        if log_path.parent:
            log_path.parent.mkdir(parents=True, exist_ok=True)
        log_ctx = open(log_path, "a")
        stderr_stream = subprocess.STDOUT
    else:
        log_ctx = nullcontext(None)
        stderr_stream = None

    with log_ctx as log_fd:
        if log_fd:
            log_fd.write(f"\n--- [PYROCLASTIC EXEC] {cmd_str} and envv: [{env_string}] ---\n")
            log_fd.flush()

        try:
            return subprocess.run(
                command,
                shell=shell,
                cwd=cwd,
                stdout=log_fd,
                stderr=stderr_stream,
                env=full_env,
                check=True,
                **extra_args
            )

        except subprocess.CalledProcessError as e:
            print(f"\n[!] Command failed! exit code: {e.returncode}")
            if log_fd:
                log_fd.flush()
                if os.path.exists(logfile):
                    print(f"========== last 30 lines of {logfile}: ==========")
                    with open(logfile, "r") as f:
                        for line in deque(f, 30):
                            print(line.strip())
                    print("==================================================")
            sys.exit(e.returncode)


def delete_directory(target_dir: str, force: bool = False):
    """
    Python port of the delete_directory Bash function.

    :param target_dir: Path to the directory to delete
    :param force: If True, skips the 'ok' prompt (replaces $ok logic)
    """
    path = Path(target_dir)

    if not path.exists():
        return

    if not force:
        # Replicating the "Type ok to go ahead" prompt
        msg = f"Deleting {path}. Type 'ok' to go ahead."
        progress("delete_directory", 0, msg)

        try:
            ans = input().strip().lower()
        except EOFError:
            # Handle cases where input isn't possible (like some CI environments)
            ans = "no"
    else:
        # If force=True, we behave as if the user typed 'ok'
        progress("delete_directory", 0, f"Deleting {path}.")
        ans = "ok"

    if ans == "ok":
        try:
            # shutil.rmtree is the Python version of rm -rf
            if path.is_dir():
                shutil.rmtree(path)
            # This is the Python equivalent of 'rm' for files
            else:
                path.unlink()
        except Exception as e:
            # Mimic '|| true' by catching errors, but print a warning
            print(f"[!] Warning: Could not fully delete {path}: {e}")
    else:
        print("Exiting.")
        sys.exit(0)


def tick() -> float:
    """
    Returns the current high-resolution timestamp.
    Replaces: ns=$(date +%s%N)
    """
    return time.perf_counter()


def truncate_file(filepath: str):
    """
    Python equivalent of Bash: > filepath
    """
    path = Path(filepath)
    if path.exists():
        # Using 'w' mode effectively wipes the file contents
        with path.open('w') as f:
            f.write("")
        print(f"[*] Truncated {path.name}")


def tock(start_time: float, decimal_places: int = 2) -> float:
    """
    Calculates the difference between now and the provided start_time.
    Returns the elapsed time as a float (seconds).

    Args:
        start_time: The timestamp returned by tick()
        decimal_places: Number of decimal places to round the result to.
    """
    end_time = time.perf_counter()
    elapsed = end_time - start_time
    return round(elapsed, decimal_places)


def unpack_tar(lava_path: LavaPaths, main_directory: str = ""):
    if main_directory == "":
        main_directory = Path.cwd()
    else:
        main_directory = Path(main_directory)
    
    with tarfile.open(lava_path.tar_to_unzip_path) as tar:
        # Get top level directory name of the tar-ball
        unpacked_tar_directory = main_directory / lava_path.tar_source_root

        if unpacked_tar_directory.exists():
            print(f"Deleting existing source: {unpacked_tar_directory}")
            shutil.rmtree(unpacked_tar_directory)

        print(f"Extracting {lava_path.tar_to_unzip_path} to {main_directory}...")
        tar.extractall(path=main_directory)


def configure_project(lava_path: LavaPaths, main_directory: str = "", environment: str = "env_var", lf: Optional[str] = None) -> Path:
    """
    This function first creates the install directory. If there is a configure, it will run it 
    and set install to the install path in the current working directory

    Also, it runs any pre_make steps, steps that should be done before lava_preprocessing and the make process itself.

    Args:
        :param lava_path: The class used to track all paths for the specific project and configs
        :param main_directory: the working directory
        :param lf:
        :param environment:
    """
    if main_directory == "":
        main_directory = Path.cwd()
    else:
        main_directory = Path(main_directory)
    install_dir = main_directory / "lava-install"
    install_dir.mkdir(exist_ok=True)

    if not os.path.isdir(os.path.join(main_directory, '.git')):
        run_local(["git", "init"], cwd=str(main_directory), logfile=lf)
        run_local(["git", "config", "user.name", "LAVA"], cwd=str(main_directory), logfile=lf)
        run_local(["git", "config", "user.email", "nobody@nowhere"], cwd=str(main_directory), logfile=lf)
        run_local(["git", "add", "-A", "."], cwd=str(main_directory), logfile=lf)
        run_local(["git", "commit", "-m", "Unmodified source."], cwd=str(main_directory), logfile=lf)

    configure_command = lava_path.config.get('configure', '')
    envv = lava_path.config[environment]

    if configure_command != '':
        if "{install_dir}" in configure_command:
            full_config = configure_command.replace("{install_dir}", str(install_dir))
        else:
            full_config = f"{configure_command} --prefix={install_dir}"
            
        print(f'Configuring... {full_config}')
        run_local(full_config, env=envv, cwd=str(main_directory), shell=True, logfile=lf)
        # For old GNU projects
        neuter_autotools_completely(str(main_directory))

    makefile_append = lava_path.config.get("makefile_append", "")
    if makefile_append != "":
        # The rules go in a GNUmakefile that includes Makefile, NOT appended to
        # Makefile itself: GNU make reads GNUmakefile first, and compiledb's
        # dry run (make -Bnwk) force-remakes Makefile from Makefile.in via
        # config.status (make remakes makefiles even under -n), which would
        # silently drop anything appended to it. A GNUmakefile the project
        # ships itself (not ours) is appended to instead.
        makefile_path = os.path.join(main_directory, 'Makefile')
        gnumakefile_path = os.path.join(main_directory, 'GNUmakefile')
        marker = "# Generated by LAVA (makefile_append)\n"
        if not os.path.isfile(makefile_path):
            print(f"Warning: makefile_append set but no Makefile found at {main_directory}")
            sys.exit(1)
        if os.path.isfile(gnumakefile_path):
            with open(gnumakefile_path, "r") as mf:
                ours = mf.read().startswith(marker)
        else:
            ours = True
        if ours:
            with open(gnumakefile_path, "w") as mf:
                mf.write(marker + "include Makefile\n\n" + makefile_append + "\n")
        else:
            with open(gnumakefile_path, "a+") as mf:
                mf.write("\n" + makefile_append + "\n")

    # "{config_dir}" lets pre_make copy target-specific files (e.g. a CLI driver
    # like freetype2's ftlava.c) from target_configs/<project>/ into the tree.
    pre_make = lava_path.config.get("pre_make", "").replace("{config_dir}", str(lava_path.config["config_dir"]))
    if pre_make != "":
        if os.path.isfile(os.path.join(main_directory, 'Makefile')):
            blindfolds = {
                "ACLOCAL": "true",
                "AUTOCONF": "true",
                "AUTOMAKE": "true",
                "AUTOHEADER": "true",
                "MAKEINFO": "true"
            }
            # Safely merge into your existing environment configuration
            envv.update(blindfolds)
        run_local(f"{pre_make}", env=envv, shell=True, cwd=str(main_directory), logfile=lf)

    return install_dir


def apply_replacements(source_directory, c_files, clang_apply: str, extra_args: Optional[List[str]] = None,
                       remove_yaml: bool = False) -> List[int]:
    """
    Apply lavaTool's <file>.yaml replacements for c_files, each exactly once.
    lavaTool writes FilePath as compile_commands.json gave the file, i.e.
    RELATIVE to that entry's "directory", and clang-apply-replacements resolves
    it relative to its own cwd. So: group files by entry directory, copy each
    group's yamls into a temp dir, and run clang-apply-replacements on it with
    cwd = that directory. (Running it per source dir instead broke openssl, which
    compiles "ssl/x.c" from the root: "Described file ... doesn't exist", nothing
    applied. Its search is also recursive, so overlapping dirs applied twice.)
    Returns one return code per group.
    """
    entry_dir = {}
    with open(os.path.join(source_directory, 'compile_commands.json'), 'r') as f:
        for entry in json.load(f):
            entry_dir[os.path.realpath(os.path.join(entry['directory'], entry['file']))] = entry['directory']

    groups = {}
    for c_file in c_files:
        real = os.path.realpath(c_file)
        groups.setdefault(entry_dir.get(real, os.path.dirname(real)), []).append(real)

    rcs = []
    for directory, files in groups.items():
        yamls = [f + '.yaml' for f in files if os.path.isfile(f + '.yaml')]
        if not yamls:
            continue
        with tempfile.TemporaryDirectory() as tmp:
            # Indexed names: basenames can repeat across subdirectories.
            for i, y in enumerate(yamls):
                shutil.copy(y, os.path.join(tmp, f"{i}.yaml"))
            rv, _ = run_local([clang_apply] + (extra_args or []) + [tmp], cwd=directory, capture_output=True)
        rcs.append(rv)
        if remove_yaml and rv == 0:
            for y in yamls:
                os.remove(y)
    return rcs


def git_addable_c_files(repo_dir) -> List[str]:
    """
    Every .c file under repo_dir (relative paths), minus files inside a git
    submodule. Tarballs that are git checkouts (e.g. freetype2's
    subprojects/dlg) record submodules as gitlinks, and naming a file inside
    one makes "git add" fail with "Pathspec ... is in submodule".
    """
    repo_dir = Path(repo_dir)
    _, (out, _) = run_local(["git", "ls-files", "-s"], cwd=str(repo_dir), capture_output=True)
    submodules = [line.split('\t', 1)[1] + '/' for line in (out or b'').decode(errors='replace').splitlines()
                  if line.startswith('160000 ')]
    c_files = [p.relative_to(repo_dir).as_posix() for p in repo_dir.rglob("*.c")]
    return [f for f in c_files if not any(f.startswith(s) for s in submodules)]


def _to_preprocess_args(arguments: List[str], real_file: str) -> List[str]:
    """
    Turn a compile_commands.json entry's real compile invocation into the
    equivalent -E (preprocess-only) invocation for real_file: strip -c and
    -o <out>, drop any OTHER bare positional file this same command also
    happens to reference (e.g. a link line naming two .c files at once, or
    .o/.a inputs), keep every other flag verbatim (defines, includes, warning
    flags -- whatever the project's own build system actually computed), and
    force output to <real_file>_pre.
    """
    cc = arguments[0]
    real_file = os.path.realpath(real_file)
    # Dependency-file bookkeeping flags (automake's per-object compile rules
    # always add these). Irrelevant to -E output and, worse, -MT/-MF/-MQ take
    # their value as a SEPARATE argv token that usually doesn't start with
    # '-' -- if not consumed together with the flag here, the generic bare-
    # positional-argument rule below mistakes that value for a source file
    # and drops it alone, leaving the flag dangling with no argument, which
    # clang rejects outright. Simplest correct fix: drop all of it.
    dep_flags_with_value = {'-MT', '-MF', '-MQ'}
    dep_flags_no_value = {'-MD', '-MMD', '-MP', '-MG', '-MM'}

    flags = []
    i = 1
    while i < len(arguments):
        arg = arguments[i]
        if arg == '-c' or arg in dep_flags_no_value:
            i += 1
            continue
        if arg == '-o' or arg in dep_flags_with_value:
            i += 2
            continue
        if arg.startswith('-o') and arg != '-o' and len(arg) > 2:
            i += 1
            continue
        if not arg.startswith('-'):
            # A bare positional argument in a compile/link line is always
            # either the file being compiled or some other input (another
            # source file, an object, a library) -- either way we don't want
            # it echoed back; real_file gets appended explicitly below.
            i += 1
            continue
        flags.append(arg)
        i += 1
    return [cc, '-P', '-include', 'stdio.h'] + flags + ['-E', real_file, '-o', real_file + '_pre']


def preprocess(lava_path: LavaPaths, main_directory: str = "", environment: str = "env_var",
                lf: Optional[str] = None):
    """
    Macro-flatten (-E) every file LAVA will instrument, using each file's OWN
    real compile flags -- not a guessed/shared set. There's no way to know in
    advance which -D/-I flags a given project's build actually needs (feature
    macros like -DHAVE_FUNC_ATTRIBUTE_VISIBILITY=1 change what the source
    even MEANS, not just whether headers resolve), so this runs the project's
    real build once first purely to learn each file's correct command from
    compile_commands.json, then re-issues that exact command with -c/-o
    swapped for -E. The caller is expected to do the REAL, final build (its
    own compile_commands.json, reflecting the now-preprocessed source) right
    after this returns -- this function deletes the throwaway
    compile_commands.json so nothing downstream mistakes it for that.

    Args:
        lava_path: The class used to track all paths for the specific project and configs
        main_directory: the working directory
        environment: which lava_path.config CFLAGS/env set to build with
        lf: optional log file path to write outputs to
    """
    if main_directory == "":
        main_directory = Path.cwd()
    else:
        main_directory = Path(main_directory)

    if lava_path.config.get('preprocessed', False):
        return

    print("Preprocessing Source code (learning each file's real flags first)...")
    make_and_install(lava_path, main_directory=str(main_directory), environment=environment, lf=lf)

    compile_db_path = main_directory / 'compile_commands.json'
    with open(compile_db_path, 'r') as f:
        entries = json.load(f)

    seen_files = set()
    succeeded = []
    failed = []  # (real_file, stderr_tail)
    for entry in entries:
        real_file = os.path.realpath(os.path.join(entry['directory'], entry['file']))
        if real_file in seen_files:
            continue
        seen_files.add(real_file)

        arguments = entry.get('arguments')
        if arguments is None:
            arguments = shlex.split(entry['command'])

        pre_args = _to_preprocess_args(arguments, real_file)
        pre_out = real_file + '_pre'
        # Run from THIS entry's own compile-time directory, not a shared one --
        # its flags can include relative -I paths (e.g. "-I../../include")
        # that only resolve correctly relative to where the real build ran it.
        rv, (out, err) = run_local(pre_args, cwd=entry['directory'], capture_output=True)
        if rv == 0 and os.path.exists(pre_out):
            shutil.copy(real_file, real_file + '.bak')
            shutil.move(pre_out, real_file)
            succeeded.append(real_file)
        else:
            # Surface WHY, not just that it failed -- this is what would have
            # made the -MT/-MF dependency-flag bug immediately obvious instead
            # of needing a manual trace through the compile_commands.json entry.
            err_text = (err or b'').decode(errors='replace').strip()
            err_tail = '\n    '.join(err_text.splitlines()[-5:]) if err_text else '(no stderr captured)'
            print(f"Warning: Skipping {real_file} (preprocessing failed)\n    {err_tail}")
            failed.append((real_file, err_tail))
            if os.path.exists(pre_out):
                os.remove(pre_out)

    # Loud, single-place summary instead of warnings scattered across a huge
    # log -- a partial failure like "every file under one directory silently
    # never got preprocessed" is otherwise invisible until something ELSE
    # breaks, much later, for reasons that look unrelated.
    total = len(succeeded) + len(failed)
    print(f"Preprocessing summary: {len(succeeded)}/{total} files preprocessed successfully.")
    if failed:
        print(f"  {len(failed)} FAILED:")
        for f, _ in failed:
            print(f"    - {f}")
        # A directory where EVERY file failed is a much stronger signal of a
        # systemic bug (wrong flags, a parsing bug like the one above) than
        # scattered individual failures (some files legitimately can't be
        # preprocessed in isolation) -- call those out specifically.
        by_dir_total: dict = {}
        by_dir_failed: dict = {}
        for f in succeeded:
            d = os.path.dirname(f)
            by_dir_total[d] = by_dir_total.get(d, 0) + 1
        for f, _ in failed:
            d = os.path.dirname(f)
            by_dir_total[d] = by_dir_total.get(d, 0) + 1
            by_dir_failed[d] = by_dir_failed.get(d, 0) + 1
        all_failed_dirs = [d for d, n in by_dir_failed.items() if n == by_dir_total[d]]
        if all_failed_dirs:
            print("  WARNING: every file failed in these directories (likely a systemic bug, not per-file quirks):")
            for d in all_failed_dirs:
                print(f"    - {d} ({by_dir_total[d]} file(s))")

    # This compile_commands.json describes the PRE-preprocessing source; the
    # caller's own real build (right after this returns) must regenerate it.
    if compile_db_path.exists():
        compile_db_path.unlink()

    if os.path.isdir(os.path.join(main_directory, '.git')):
        c_files = git_addable_c_files(main_directory)

        if not c_files:
            raise AssertionError("No .c files found in the project directory for Pre-process!")

        # Pass the exact file list to Git safely. -f: naming a file explicitly
        # (unlike "git add -A .") makes git refuse outright if the project's
        # OWN .gitignore excludes it (e.g. libpng's committed .gitignore
        # excludes its generated pnglibconf.c) -- we're using git purely as
        # LAVA's own change-tracking, not honoring the target's gitignore.
        run_local(["git", "add", "-f"] + c_files, cwd=str(main_directory))

        # Confirm that Pre-process actually modified tracked files
        rv_status, _ = run_local(["git", "diff", "--cached", "--quiet"], cwd=str(main_directory), capture_output=True)

        # If rv_status == 0, the staging area is empty. Trigger the assert.
        assert rv_status != 0, "Pre-process failed to modify any C source files!"
        run_local(["git", "commit", "-m", "Pre-processed source."], cwd=str(main_directory), logfile=lf)


def make_and_install(lava_path: LavaPaths, main_directory: str = "", environment: str = "env_var",
                     lf: Optional[str] = None, competition: bool = False,
                     capture_build: bool = False) -> Union[subprocess.CompletedProcess, Tuple[int, Tuple[bytes, bytes]]]:
    if main_directory == "":
        main_directory = Path.cwd()
    else:
        main_directory = Path(main_directory)

    env = lava_path.config[environment]
    if competition:
        env["CFLAGS"] += " -DLAVA_LOGGING"

    # Check if existing Makefile exists to blind it 
    makefile_path = os.path.join(main_directory, "Makefile")
    if os.path.isfile(makefile_path):
        # Heavy recursive GNU target: aggressively blindfold Autotools to block timestamp collisions
        blindfolds = {
            "ACLOCAL": "true",
            "AUTOCONF": "true",
            "AUTOMAKE": "true",
            "AUTOHEADER": "true",
            "MAKEINFO": "true"
        }
        # Safely merge into your existing environment configuration
        env.update(blindfolds)

    # Run make. "{install_dir}" is honored here too (e.g. a target that links its
    # LAVA driver binary against the just-built lib with -Wl,-rpath,{install_dir}/lib
    # as part of its make step, not its install step).
    install_dir = os.path.join(main_directory, "lava-install")
    make_command = lava_path.config['make'].replace("{install_dir}", str(install_dir))
    build_output = run_local(f"compiledb -- {make_command}", env=env, shell=True, cwd=str(main_directory), logfile=lf, capture_output=capture_build, debug=True)

    # 3. Determine compilation success based on the return type
    if capture_build:
        # In capture mode, build_output is a tuple: (returncode, (stdout, stderr))
        compile_success = build_output[0] == 0
    else:
        # In streaming mode, build_output is a subprocess.CompletedProcess
        compile_success = build_output.returncode == 0

    # IF COMPILATION FAILED: Bail out immediately!
    if not compile_success:
        print("[!] Compilation failed. Bypassing version control tracking and installation phases.")
        return build_output

    # 5. IF COMPILATION SUCCEEDED: Complete downstream asset management
    print("[*] Compilation succeeded. Proceeding with installation and tracking.")
    
    if os.path.isdir(os.path.join(main_directory, '.git')):
        # Only run git steps if compile_commands.json was safely generated
        if os.path.exists(os.path.join(main_directory, "compile_commands.json")):
            # -f: some projects' .gitignore templates exclude compile_commands.json
            # by convention (an IDE/tooling artifact from their point of view).
            run_local(["git", "add", "-f", "compile_commands.json"], cwd=str(main_directory), logfile=lf)
            rv_status, _ = run_local(["git", "diff", "--cached", "--quiet"], cwd=str(main_directory), capture_output=True)
            if rv_status != 0:
                run_local(["git", "commit", "-m", "Update compile_commands.json."], cwd=str(main_directory), logfile=lf)
                print("Added/Updated the compile_commands.json in git tracking.")
            else:
                print("compile_commands.json has not changed. Skipping commit to keep git history clean.")

    # Execute final installation step cleanly, have some flags, just in case we have to run make before processing, this avoids extra compiling.
    # In the rare case that the 'install' commands needs an install directory, here it is
    install_command = lava_path.config["install"].replace("{install_dir}", str(install_dir))

    run_local(f"{install_command}", env=env, shell=True, debug=True, cwd=str(main_directory), logfile=lf)
    print("Install has completed")
    return build_output


def deep_clean_target(source_directory: Path, lf: Optional[str] = None):
    """
    Tries to run 'make distclean' natively, then aggressively scrubs out 
    all remaining compiled assets, configuration caches, and shared objects (.so).
    """
    print(f"[*] Executing deep structural scrub on: {source_directory.name}")
    
    # Step 1: Try running official clean routines safely with defensive blindfolds
    # We pass the Autotools override variables to stop it from trying to invoke aclocal-1.15

    blindfolds = {
        "ACLOCAL": "true",
        "AUTOCONF": "true",
        "AUTOMAKE": "true",
        "AUTOHEADER": "true",
        "MAKEINFO": "true"
    }
    full_env = os.environ.copy()
    if full_env:
        full_env.update(blindfolds)

    env_string = " ".join([f"{k}='{v}'" for k, v in blindfolds.items()]) if blindfolds else ""
    
    for clean_cmd in [f"make distclean", f"make clean"]:
        print(f"[*] Attempting native cleanup: {clean_cmd}...env=[{env_string}]")
        
        # We manually use subprocess.run with check=False here to bypass run_local's aggressive sys.exit() trap
        # This guarantees our fallback loop actually works!
        if lf:
            # Safely open and close the log file automatically
            with open(lf, "a") as log_file:
                result = subprocess.run(
                    clean_cmd,
                    shell=True,
                    cwd=str(source_directory),
                    stdout=log_file,
                    stderr=subprocess.STDOUT, # Merges stderr into the log_file automatically
                    executable="/bin/bash",
                    env=full_env
                )
        else:
            # Fallback if no logfile path was passed
            result = subprocess.run(
                clean_cmd,
                shell=True,
                cwd=str(source_directory),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                executable="/bin/bash",
                env=full_env
            )
        
        if result.returncode == 0:
            print(f"[+] Native '{clean_cmd}' executed successfully.")
            break
        else:
            print(f"[!] Native '{clean_cmd}' failed or wasn't supported. Moving to next strategy...")

    # Step 2: The Brute-Force Fallback (Catch whatever the Makefile missed)
    # Expand your extensions list to catch shared objects (.so) and dynamic links
    compiled_extensions = ["*.o", "*.a", "*.la", "*.lo", "*.so", "*.so.*", "*.dylib"]
    
    for ext in compiled_extensions:
        # rglob handles the deep recursive search across all subdirectories automatically
        for file in source_directory.rglob(ext):
            file.unlink(missing_ok=True)
            
    # Step 3: Obliterate Autotools state files so configure is forced to rebuild config.h
    config_state_files = ["config.h", "config.status", "config.cache", "config.log", "stamp-h1"]
    for state_file in config_state_files:
        for file in source_directory.rglob(state_file):
            file.unlink(missing_ok=True)

    print(f"[+] Deep scrub complete. {source_directory.name} is back to a pristine state.")


def neuter_autotools_completely(main_directory: str):
    """
    Completely neutralizes Autotools timestamp panics by hijacking the 'missing' 
    script and forcing it to always return success.
    """
    main_path = Path(main_directory)
    
    # SAFEGUARD: Only run this on actual Autotools trees
    is_autotools = (main_path / "configure.ac").exists() or (main_path / "configure.in").exists()
    if not is_autotools:
        return

    print("[***] Autotools detected. Disarming the 'missing' script trap...")
    
    missing_script_path = main_path / "build-aux" / "missing"
    
    if missing_script_path.exists():
        try:
            # Overwrite the 'missing' script with a perfect bash dummy that always succeeds
            with open(missing_script_path, "w") as f:
                f.write("#!/bin/sh\nexit 0\n")
            
            # Ensure it remains executable
            os.chmod(str(missing_script_path), 0o755)
            print("[+] Successfully neutralized build-aux/missing.")
        except Exception as e:
            print(f"[-] Warning: Failed to hijack missing script: {e}")


def dump_table(title: str, rows: list, attributes: list):
    """attributes: attribute names, or (label, getter) pairs for computed columns,
    e.g. to print a foreign key's resolved row instead of its insertion-order id."""
    print(f"\n==================================================")
    print(f"=== {title} (Row Count: {len(rows)}) ===")
    print(f"==================================================")
    for idx, row in enumerate(rows):
        print(f"  [{idx}] Row Instance Entry:")
        for attr in attributes:
            getter = None
            if isinstance(attr, tuple):
                attr, getter = attr
            if getter is not None or hasattr(row, attr):
                val = getter(row) if getter is not None else getattr(row, attr)

                # Track list inner types cleanly for your surgical debugging verification
                if isinstance(val, list):
                    inner_type = f"list of {type(val[0]).__name__}" if val else "empty list"
                    # Limit output size to prevent terminal buffer spam on giant label lists
                    display_val = val if len(val) <= 12 else f"{val[:10]}... (+{len(val) - 10} more)"
                    # FIX: Coerce the array token to a string BEFORE passing alignment modifiers
                    str_val = str(display_val)
                else:
                    inner_type = type(val).__name__
                    str_val = str(val)

                print(f"    - {attr:<16}: {str_val:<55} | Type: {inner_type}")
            else:
                print(f"    - {attr:<16}: [NOT FOUND ON OBJECT VALUE]")