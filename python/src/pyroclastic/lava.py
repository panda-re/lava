from pathlib import Path
import argparse
import sys
from contextlib import contextmanager
import subprocess
import os
from collections import deque
# All LAVA steps are imported here
from .inject import inject
from .taint import bug_mining
from .add_queries.add_queries import QueryManager
from .utils.vars import parse_vars
from .utils.funcs import progress, run_local, delete_directory, tick, tock, truncate_file, get_inject_parser, print_tail


def parse_lava_args() -> argparse.Namespace:
    inject_parent = get_inject_parser()
    parser = argparse.ArgumentParser(
        description="LAVA: Large-scale Automated Vulnerability Addition",
        usage="%(prog)s [options] [ProjectConfig]",
        parents=[inject_parent],
        add_help=False
    )

    # --- Common Options ---
    common = parser.add_argument_group("Common Options")
    common.add_argument("-h", "--help", action="store_true")
    common.add_argument("-a", "--all", action="store_true", help="Run all lava steps")
    common.add_argument("-k", "--force", action="store_true", help="Delete old data without confirmation")
    # TODO: Tie this with the ATP Enum Types...
    common.add_argument("--atp-type", choices=["mem_read", "fn_arg", "mem_write"], help="Specify a single ATP type")

    # --- Step Flags ---
    steps = parser.add_argument_group("Specify Steps to Run")
    steps.add_argument("-r", "--reset", action="store_true", help="Run reset step")
    steps.add_argument("-c", "--clean", action="store_true", help="Run clean step (DB only)")
    steps.add_argument("-q", "--add-queries", action="store_true", help="Run add queries step")
    steps.add_argument("-m", "--make", action="store_true", help="Run make step")
    steps.add_argument("-t", "--taint", action="store_true", help="Run taint step")
    steps.add_argument("-i", "--inject", type=int, metavar="NUM_TRIALS",
                       help="Run inject step with specified number of trials")

    # --- Expert/Dev Options ---
    expert = parser.add_argument_group("Expert only options")
    expert.add_argument("--test-data-flow", action="store_true", help="Inject data-flow only, 0 bugs")
    expert.add_argument("--curtail", type=int, default=0, help="Curtail bug-finding after count bugs")

    # --- Backwards Compatibility / Combined Flags ---
    # Argparse doesn't natively do '-ak', so we check sys.argv for it later
    # or define it as a hidden action.
    expert.add_argument("-ak", action="store_true", help=argparse.SUPPRESS)

    # --- Positional ---
    parser.add_argument("project_name", nargs='?', help="Name of the project or path to JSON")

    # If no args, show help
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    # Handle the help flag manually to match your exit behavior
    if args.help:
        parser.print_help()
        sys.exit(0)

    # --- Custom Logic Mapping (Replacing the 'case' logic in Bash) ---

    # Handle -ak and --all shortcuts
    if args.ak or args.all:
        args.reset = True
        args.clean = True
        args.add_queries = True
        args.make = True
        args.taint = True
        args.inject = 3 if args.inject is None else args.inject
        if args.ak:
            args.force = True

    # Handle positional project_name shorthand (lava.sh ProjectName)
    # Your bash script allowed: lava.sh myproject (with no flags)
    if len(sys.argv) == 2 and not sys.argv[1].startswith("-"):
        args.reset = True
        args.clean = True
        args.add_queries = True
        args.make = True
        args.taint = True
        args.inject = 3
        args.project_name = sys.argv[1]

    # Handle --test-data-flow logic
    if args.test_data_flow:
        args.inject = 1
        args.count = 0

    return args


class Paths(object):
    def __init__(self, config: dict):
        self.directory = Path(config['directory'])
        self.bugs_directory = self.directory / config['name'] / "bugs"
        self.logs_directory = self.directory / config['name'] / "logs"
        self.sql_file = Path(__file__).parent / "data/lava.sql"
        tar_files = subprocess.check_output(['tar', 'tf', config['tarfile']], stderr=sys.stderr)
        self.tar_source_root = tar_files.decode().splitlines()[0].split(os.path.sep)[0]
        self.source_directory = self.directory / config['name'] / self.tar_source_root


@contextmanager
def log_to_file(logfile: str):
    if not logfile:
        yield
        return

    Path(logfile).parent.mkdir(parents=True, exist_ok=True)

    with open(logfile, "a") as f:
        old_stdout_fd = os.dup(sys.stdout.fileno())
        old_stderr_fd = os.dup(sys.stderr.fileno())

        try:
            os.dup2(f.fileno(), sys.stdout.fileno())
            os.dup2(f.fileno(), sys.stderr.fileno())
            yield
        except Exception as e:
            # 1. Flush the logs before we restore descriptors
            sys.stdout.flush()
            sys.stderr.flush()

            # 2. Restore descriptors immediately so we can print to terminal
            os.dup2(old_stdout_fd, sys.stdout.fileno())
            os.dup2(old_stderr_fd, sys.stderr.fileno())

            print(f"\n[!] Step failed: {e}")

            # 3. Read and print the last 30 lines of the log
            if os.path.exists(logfile):
                print(f"========== last 30 lines of {logfile}: ==========")
                with open(logfile, "r") as log_read:
                    last_lines = deque(log_read, 30)
                    for line in last_lines:
                        sys.__stdout__.write(line)
                print("==================================================")

            # Re-raise so the master script (lava.py) knows to stop
            raise
        finally:
            # Standard cleanup for successful runs
            sys.stdout.flush()
            sys.stderr.flush()
            os.dup2(old_stdout_fd, sys.stdout.fileno())
            os.dup2(old_stderr_fd, sys.stderr.fileno())
            os.close(old_stdout_fd)
            os.close(old_stderr_fd)


def reset(lava_paths: Paths, config: dict, force: bool = False):
    """
    This function resets the LAVA environment by deleting generated files and resetting the database.
    Args:
        lava_paths: The Paths object containing relevant directories.
        config: The configuration dictionary.
        force: boolean indicating whether to force deletion without confirmation.
    """
    start = tick()
    delete_directory(lava_paths.source_directory, force)
    delete_directory(lava_paths.bugs_directory, force)
    delete_directory(lava_paths.directory / config['name'] / "inputs", force)
    delete_directory(lava_paths.directory / config['name'] / "recording-rr-nondet.log", force)
    delete_directory(lava_paths.directory / config['name'] / "recording-rr-snp", force)
    # remove all plog files in the directory
    delete_directory(lava_paths.directory / config['name'] / f"queries-{config['name']}.plog", force)
    delete_directory(lava_paths.directory / config['name'] / f"queries-{config['name']}.json", force)
    progress("everything", 0, "Truncating logs...")
    for log_path in Path(lava_paths.logs_directory).glob("*.log"):
        truncate_file(str(log_path.resolve()))
    reset_database(lava_paths, config)
    total_time = tock(start)
    progress("everything", 1, f"reset complete {total_time} seconds")


def reset_database(lava_paths: Paths, config: dict):
    """
    This function resets the LAVA database to a clean state.
    This is only trigger upon a --clean flag, or other flags that force a --clean.
    """
    log_file = lava_paths.logs_directory / "dbwipe.log"
    sql_file = lava_paths.sql_file
    progress("everything", 1, f"Resetting lava db -- logging to {log_file}")
    run_local(f"dropdb -U {config['database_user']} -h {config['database']} {config['db']} || true", log_file)
    run_local(f"createdb -U {config['database_user']} -h {config['database']} {config['db']} || true", log_file)
    run_local(f"psql -U {config['database_user']} -h {config['database']} -d {config['db']} -f {sql_file} ", log_file)
    run_local("echo 'dbwipe complete'", log_file)


def make(lava_paths: Paths, config: dict):
    """
    This compiles the target program with LAVA taint queries added.
    This requires static compiling as the generic PANDA QCows might not have all libraries for dynamic linking.
    The binary will be in ./target_injections/<project>/<tar-directory>/
    Then, during the "make install" step, the binary should be in
    ./target_injections/<project>/<tar-directory>/lava-install/bin/ folder
    Eventually, in the taint step, we will copy the input folders to go with the binary for dynamic analysis.
    """
    start_time = tick()
    progress("everything", 1,"Make step -- making 64-bit version with queries")
    lf = lava_paths.logs_directory / "make.log"
    truncate_file(str(lf))
    # Note, adding the static flag is important. We are running the binaries on a PANDA VM, so we have no idea if it will have any libraries we need.
    env_var = config['panda_compile']
    make_command = config['make']
    run_local(f"cd {lava_paths.source_directory} && {make_command}", lf, env=env_var)
    run_local(f"cd {lava_paths.source_directory} && rm -rf lava-install", lf)

    install_command = config.get('install', 'make install')
    install_simple = config.get('install_simple', '')
    if install_simple == "":
        run_local(f"cd {lava_paths.source_directory} && {install_command}", lf)
    else:
        run_local(f"cd {lava_paths.source_directory} && {install_simple}", lf)

    post_install_command = config.get("post_install", "")
    if post_install_command != "":
        run_local(f"cd {lava_paths.source_directory} && {post_install_command}", lf)

    duration = tock(start_time)
    progress("everything", 1, f"make complete {duration} seconds")


def main():
    # 1. Parse arguments using the logic we refactored
    args = parse_lava_args()

    # Confirm environment variables to access the DB are set
    if 'POSTGRES_USER' not in os.environ or 'POSTGRES_PASSWORD' not in os.environ:
        print("[!] Please set the POSTGRES_USER and POSTGRES_PASSWORD environment variables to access the database.")
        sys.exit(1)

    config = parse_vars(args.project_name)
    manager = QueryManager(args)
    path_manager = Paths(config)

    # 2. Handle the "Can of Worms": Remote/Docker logic
    # Since you're sticking to local CI/CD for now, we just verify
    if args.force:
        print(f"DEBUG: Force flag detected. Proceeding with deletions...")

    # 3. Step Dispatcher
    # This replaces the 'if [ $add_queries -eq 1 ]' blocks in lava.sh

    if args.reset:
        reset(path_manager, config, args.force)

    if args.add_queries:
        start = tick()
        lf = str(path_manager.logs_directory / "add_queries.log")
        with log_to_file(lf):
            progress("everything", 1, f"Adding Taint Queries to Source code -- logging to {lf}")
            manager.step_add_queries(atp_type=args.atp_type)

        fixup_script = config.get('fixupscript', "")
        if fixup_script != "":
            lf = str(path_manager.logs_directory / "fixups.log")
            truncate_file(lf)
            progress("everything", 1, f"Fixups -- logging to {lf}")
            run_local(fixup_script, lf)
        else:
            progress("everything", 1, "No fixups")
        time_diff = tock(start)
        progress("everything", 1, f"add queries complete {time_diff} seconds")

    if args.make:
        make(path_manager, config)

    if args.clean:
        reset_database(path_manager, config)

    if args.taint:
        start = tick()
        progress("everything", 1, "Taint step -- running panda and fbi")
        if not args.clean:
            lf = path_manager.logs_directory / "dbwipe_taint.log"
            run_local(f"psql -U {config['database_user']} -h {config['database']} -c \"delete from dua_viable_bytes; delete from labelset;\" {config['db']}", lf)

        lf = str(path_manager.logs_directory / "bug_mining.log")
        progress("everything", 1, f"PANDA taint analysis prospective bug mining -- logging to {lf}")
        with log_to_file(lf):
            bug_mining.run_taint_pipeline(config['name'])
        time_diff = tock(start)
        progress("everything", 1, f"bug_mining complete {time_diff} seconds")
        # Default print last 8 lines of the log, which should have the summary of bug_injection
        # Number might increase with more bug types or debug messages
        print_tail(lf)

    if args.inject:
        progress("everything", 1, f"Injecting step -- {args.inject} trials")
        for i in range(1, args.inject + 1):
            lf = str(path_manager.logs_directory / f"inject-{i}.log")
            progress("everything", 1, f"Trial {i} -- injecting {args.count} bugs logging to {lf}")
            with log_to_file(lf):
                inject.main(args)
            # Print the stats of number of validated bugs vs total bugs, search for string "real bugs" in log file
            subprocess.run(f"grep 'yield' {lf} | grep 'real bugs' || true", shell=True)

    progress("everything", 1, "Everything finished.")


if __name__ == "__main__":
    main()
