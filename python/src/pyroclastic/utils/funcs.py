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
from typing import Tuple, Set, Optional, Union, List
from contextlib import nullcontext
from pathlib import Path
from pyroclastic.utils.vars import LavaPaths


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
    parser.add_argument("-n", "--count", type=int, default=50,
                        help="Number of bugs to inject at once")
    parser.add_argument("-y", "--bugtypes", type=str,
                        default="ptr_add,rel_write,malloc_off_by_one",
                        help="Comma separated list of bug types")
    return parser


def print_tail(logfile, n=9):
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
        c_files.add(os.path.join(entry['directory'], entry['file']))
        c_dirs.add(entry['directory'])
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
            log_fd.write(f"\n--- [PYROCLASTIC EXEC] {cmd_str} and envv {env_string} ---\n")
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


def delete_directory(target_dir: str, force=False):
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
    Args:
        lava_path: The class used to track all paths for the specific project and configs
        main_directory: the working directory
        coverage: whether to use code coverage flags or not
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
    return install_dir


def preprocess(lava_path: LavaPaths, main_directory : str = ""):
    env = lava_path.config['env_var']
    if main_directory == "":
        main_directory = Path.cwd()
    else:
        main_directory = Path(main_directory)

    if not lava_path.config.get('preprocessed', False):
        print("Preprocessing Source code...")
        with open(Path(__file__).parent.parent / "data" / "makefile.fixup", "r") as mf:
            modified_make = mf.read()

        if os.path.isfile(main_directory / "Makefile"):
            with open(main_directory / "Makefile", "a+") as mf:
                mf.write("\n" + modified_make + "\n")
        else:
            print(f"Warning: Makefile not found for preprocessing at directory: {main_directory}")
            sys.exit(1)

        run_local("make lava_preprocess SHELL=/bin/bash", env=env, cwd=str(main_directory), shell=True)
        if os.path.isdir(os.path.join(main_directory, '.git')):
            run_local(["git", "add", "."], cwd=str(main_directory))
            run_local(["git", "commit", "-m", "Pre-processed source."], cwd=str(main_directory))


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

    # Use pre-make, sometimes you need to do a few things after configure but before `make`
    configure_str = lava_path.config.get("configure", "")
    pre_make = lava_path.config.get("pre_make", "")

    if pre_make != "":
        run_local(f"f{pre_make}", env=env, shell=True, cwd=str(main_directory), logfile=lf)

    # Check if a 'make' operation occurs during either the configuration or pre-make steps
    has_prior_make = "make" in configure_str or "make" in pre_make
    # Formulate your build and shell modifiers dynamically
    if has_prior_make:
        # Heavy recursive GNU target: aggressively blindfold Autotools to block timestamp collisions
        build_modifiers = "ACLOCAL=true AUTOCONF=true AUTOMAKE=true AUTOHEADER=true"
    else:
        # Pure standalone target (e.g., toy): compile naturally and cleanly
        build_modifiers = ""

    # Run make
    build_output = run_local(f"compiledb -- {lava_path.config['make']} {build_modifiers}", env=env, shell=True, cwd=str(main_directory), logfile=lf, capture_output=capture_build, debug=True)

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
            run_local(["git", "add", "compile_commands.json"], cwd=str(main_directory), logfile=lf)
            run_local(["git", "commit", "--allow-empty", "-m", "Add compile_commands.json."], cwd=str(main_directory), logfile=lf)
            print("Added the compile_commands.json to git tracking.")

    # Execute final installation step cleanly, have some flags, just in case we have to run make before processing, this avoids extra compiling.
    run_local(f"{lava_path.config['install']} {build_modifiers}", env=env, shell=True, debug=True, cwd=str(main_directory), logfile=lf)
    print("Install has completed")
    return build_output