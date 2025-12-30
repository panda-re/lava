import datetime
import sys
from collections import deque
from pathlib import Path
import subprocess
import os
import shutil
import time
import argparse


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


def print_tail(logfile, n=8):
    if os.path.exists(logfile):
        with open(logfile, "r") as f:
            for line in deque(f, n):
                print(line.strip())


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


def run_local(command, logfile, env=None):
    """
    Python port of run_remote.
    logfile is mandatory. Use os.devnull or /dev/stdout for 'no log'.
    """
    log_path = Path(logfile)

    # Ensure the directory for the log exists (e.g., /tmp/lava/logs/)
    if log_path.parent:
        log_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"[*] Running: {command} (Log: {logfile})")

    full_env = os.environ.copy()
    if env:
        # Merge your CC, CXX, CFLAGS
        full_env.update({key: str(value) for key, value in env.items()})

    # Use 'a' to preserve the '>>' append behavior from Bash
    with open(log_path, "a") as log_fd:
        log_fd.write(f"\n--- [PYROCLASTIC EXEC] {command} ---\n")
        log_fd.flush()

        try:
            subprocess.run(
                command,
                shell=True,
                stdout=log_fd,
                stderr=subprocess.STDOUT,  # Merges stderr into the log file
                env=full_env,
                check=True,
                executable="/bin/bash"
            )
        except subprocess.CalledProcessError as e:
            print(f"\n[!] Command failed! exit code: {e.returncode}")
            print(f"========== last 30 lines of {logfile}: ==========")

            # Efficiently grab the end of the file
            with open(logfile, "r") as f:
                for line in deque(f, 30):
                    print(line.strip())

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