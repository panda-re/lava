"""
This script assumes you have already done src-to-src transformation with
lavaTool to add taint and attack point queries to a program, AND managed to
JSON project file.

Second arg is an input file you want to run, under panda, to get taint info.
"""

import os
import hashlib
from pathlib import Path
from ..utils.database_types import FileTaint, LavaDatabase
import sys
import shlex
import shutil
import subprocess
import json
from pandare import Panda
import argparse
from typing import Optional

# LAVA
from . import dwarfdump
from ..taint.find_bug_injection import parse_panda_log
from ..utils.database_types import print_bug_stats, print_phase2_stats
from ..utils.vars import parse_vars
from ..utils.funcs import tick, tock, progress
from ..taint.generate_bugs import record_injectable_bugs_offline


def pandalog_conversion_env():
    """Require native protobuf for pandalog conversion."""
    env = os.environ.copy()
    env['PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION'] = 'upb'
    probe = subprocess.run(
        [sys.executable, '-c',
         'import pandare.plog_pb2; '
         'from google.protobuf.internal import api_implementation; '
         'assert api_implementation.Type() == "upb"'],
        env=env, capture_output=True, text=True, timeout=30)
    if probe.returncode:
        raise RuntimeError(
            'Native protobuf (upb) is required for pandalog conversion. '
            'Rebuild/reinstall PyPANDA with modern plog_pb2.py bindings '
            'and install a protobuf runtime with upb support.\n'
            + probe.stderr.strip())
    print('[*] Using native protobuf (upb) for pandalog conversion.')
    return env


def check_dwarf_json_files(install_dir: str) -> None:
    """
    Recursively find and validate the four DWARF JSON files.

    All four must:
      - Exist in the same directory beneath install_dir
      - Share the same filename prefix
      - Be non-empty
      - Contain valid JSON

    Raises RuntimeError if validation fails.
    """
    expected_suffixes = (
        "_funcinfo.json",
        "_globvar.json",
        "_lineinfo.json",
        "_typeinfo.json",
    )

    if not os.path.isdir(install_dir):
        raise RuntimeError(
            f"Install directory does not exist: {install_dir}"
        )

    errors = []

    for root, _, files in os.walk(install_dir):
        for filename in files:
            if not filename.endswith("_funcinfo.json"):
                continue

            prefix = filename[:-len("_funcinfo.json")]

            paths = [
                os.path.join(root, prefix + suffix)
                for suffix in expected_suffixes
            ]

            if not all(os.path.isfile(path) for path in paths):
                continue

            try:
                for path in paths:
                    if os.path.getsize(path) == 0:
                        raise RuntimeError(f"Empty JSON file: {path}")

                    with open(path, "r", encoding="utf-8") as f:
                        json.load(f)

                return  # All four JSON files are valid

            except (OSError, UnicodeError, ValueError) as exc:
                errors.append(str(exc))

    raise RuntimeError(
        f"DWARF JSON validation failed under {install_dir}. "
        "Could not find four valid JSON files sharing "
        "the same prefix and directory."
        + (f"\nErrors: {'; '.join(errors)}" if errors else "")
    )


def run_taint_pipeline(project_data: dict, raw_command: Optional[str] = None, steps: Optional[list] = None):
    """
    Initializes the project and PANDA object based on arguments.
    """
    pending = []
    if raw_command is None:
        input_root = Path(project_data["config_dir"]).resolve() / "inputs"
        if not input_root.is_dir():
            raise FileNotFoundError(input_root)
        with LavaDatabase(project_data) as db:
            for source in sorted(input_root.rglob("*")):
                if not source.is_file():
                    continue
                hasher = hashlib.sha256()
                with source.open("rb") as input_stream:
                    for chunk in iter(lambda: input_stream.read(1024 * 1024), b""):
                        hasher.update(chunk)
                digest = hasher.hexdigest()
                identity = dict(filename=str(source), sha256=digest, command=project_data["command"])
                existing = db.session.query(FileTaint).filter_by(**identity).first()
                if existing and existing.complete:
                    continue
                # Database identity only: input bytes remain in the configured corpus.
                input_key = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
                if existing is None:
                    db.session.add(FileTaint(**identity, input_key=input_key, complete=False))
                pending.append((source.relative_to(input_root), source, input_key))
            db.session.commit()
        if not pending:
            progress("bug_mining", 0, "All inputs have already been mined with this command")
            return

    # Stable across --record/--replay/--parse invocations, distinct for new inputs.
    batch_key = hashlib.sha256(json.dumps([key for _, _, key in pending]).encode()).hexdigest()
    if pending:
        project_data["recording"] = batch_key
    log_stem = Path(project_data['output_dir']).resolve() / f"queries-{project_data['name']}-{batch_key}"
    panda_log = str(log_stem) + ".plog"
    pandalog_json = str(log_stem) + ".json"

    class State:
        guest_command = ""
        install_directory = ""
        tar_directory = ""
    state = State()
    os.chdir(project_data["output_dir"])
    tar_files = subprocess.check_output(['tar', 'tf', project_data['tarfile']]).decode('utf-8')
    state.tar_directory = os.path.abspath(tar_files.splitlines()[0].split(os.path.sep)[0])
    state.install_directory = os.path.join(state.tar_directory, 'lava-install')
    # recording_timeout = project_data["recording_timeout"]
    # Parsing existing JSON must not initialize PANDA or open its QCOW.
    needs_panda = raw_command is not None or steps is None or any(
        step in steps for step in ('record', 'replay'))
    panda = Panda(generic=project_data['qemu']) if needs_panda else None
    project_data["mining_inputs"] = {
        os.path.join(state.install_directory, 'inputs', str(relative)): key
        for relative, _, key in pending
    }

    def create_recording_wrapper():
        """
        Create a recording in PANDA with the given command arguments.
        This function reverts to the 'root' snapshot, copies the installation directory
        to the guest, and starts recording the specified command.
        1. Revert to 'root' snapshot
        2. Copy install_directory to guest
        3. Start recording the command specified in guest_command, this runs the program on a folder of inputs
        4. Stop the recording after the command completes
        """
        # Use absolute paths for BOTH arguments!
        guest_command = state.guest_command
        # Technically the first two steps of record_cmd
        # but running executable ONLY works with absolute paths
        panda.revert_sync('root')
        panda.copy_to_guest(state.install_directory, absolute_paths=True)

        # Pass in None for snap_name since I already did the revert_sync already
        # TODO: We need to add recording_timeout once PyPanda is updated
        panda.record_cmd(
            guest_command=guest_command,
            snap_name=None,
        )
        panda.stop_run()

    def record():
        start = tick()
        input_file_directory = os.path.abspath(os.path.join(project_data["config_dir"], "inputs"))
        progress("bug_mining", 0, "Entering {}".format(project_data['output_dir']))
        os.chdir(project_data['output_dir'])

        # When you unpack a tarfile, it usually creates a subdirectory.
        guest_directory_inputs_path = os.path.join(state.install_directory, 'inputs')

        progress("bug_mining", 0, f"Copying directory {input_file_directory} to {guest_directory_inputs_path}")
        # copytree requires the destination to NOT exist
        if os.path.exists(guest_directory_inputs_path):
            progress("bug_mining", 0, "Deleting existing inputs/ directory in guest install")
            shutil.rmtree(guest_directory_inputs_path)

        # 2. BUILD THE PER-FILE COMMAND, WITH A REAL SHELL VARIABLE DROPPED IN
        if raw_command is not None:
            shutil.copytree(input_file_directory, guest_directory_inputs_path)
            state.guest_command = raw_command
        else:
            os.makedirs(guest_directory_inputs_path)
            commands = []
            for relative, source, input_key in pending:
                guest_input = os.path.join(guest_directory_inputs_path, str(relative))
                os.makedirs(os.path.dirname(guest_input), exist_ok=True)
                shutil.copyfile(source, guest_input)
                commands.append(project_data['command'].format(
                    install_dir=shlex.quote(state.install_directory),
                    input_file=shlex.quote(guest_input)))
            batch_shell_command = "; ".join(commands)
            progress("bug_mining", 0, f"Generated Guest Command: {batch_shell_command}")
            state.guest_command = batch_shell_command

        # In CI/CD, we should try to use complete record and replay
        # Also, please avoid using debug prints in CI/CD, it can cause issues.
        if project_data["complete_rr"]:
            progress("bug_mining", 0, "Using complete record and replay, likely in GitHub CI/CD")
            panda.set_complete_rr_snapshot()

        panda.queue_blocking(create_recording_wrapper)
        panda.run()

        record_time = tock(start)
        progress("bug_mining", 1, f"panda record complete {record_time} seconds")
        sys.stdout.flush()

    def replay():
        """
        Replay the recording in PANDA with taint analysis enabled. Activate the plugins to obtain the taint data
        from the PANDA log.
        """
        debug = project_data["debug"]
        start = tick()
        guest_executable = project_data['command'].format(
            install_dir=state.install_directory,
            input_file=""
        ).split()[0].strip()

        if not os.path.exists(guest_executable):
            raise RuntimeError(f"Critical Error: {guest_executable} not found")

        progress("bug_mining", 1, f"Running Dwarf Dump on {guest_executable} to generate JSON files for taint analysis")
        dwarfdump.dump_binary(guest_executable, project_root=state.tar_directory)
        check_dwarf_json_files(state.tar_directory)

        proc_name = os.path.basename(guest_executable)

        progress("bug_mining", 1, "Starting first and only replay, tainting on file open...")

        progress("bug_mining", 0, f"pandalog = [{panda_log}]" )

        panda.set_pandalog(panda_log)
        panda.load_plugin("pri")
        panda.load_plugin("dwarf2",
                          args={
                              'proc': proc_name,
                              'g_debugpath': state.install_directory,
                              'h_debugpath': state.install_directory,
                              'debug': debug
                          })
        panda.load_plugin("pri_taint", args={
            'hypercall': True,
            'debug': debug
        })
        panda.load_plugin("taint2",
                          args={
                              'no_tp': True,
                              'debug': debug
                          })
        panda.load_plugin('tainted_branch')
        panda.load_plugin("file_taint",
                          args={
                              'filename': os.path.join(state.install_directory, 'inputs', '*'),
                              'pos': True,
                              'verbose': debug
                          })

        # Default name is 'recording'
        # https://github.com/panda-re/panda/blob/dev/panda/python/core/pandare/panda.py#L2595
        panda.run_replay("recording")

        replay_time = tock(start)
        progress("bug_mining", 1, f"taint analysis complete {replay_time} seconds")
        sys.stdout.flush()
        convert_plog_to_json()

    # Technically occurs inside replay, but it is just cleaner here.
    def convert_plog_to_json():
        start = tick()
        conversion_env = pandalog_conversion_env()
        progress("bug_mining", 0, "Converting PANDA Log to JSON...")
        convert_json_args = [sys.executable, '-m', 'pandare.plog_reader', panda_log]
        # TODO: Once Panda PR is in, using -c should avoid the warning
        #convert_json_args = [
        #    'python3',
        #    '-c',
        #    'import pandare.plog_reader; pandare.plog_reader.main()',
        #    pandalog
        #]
        print(f"panda log JSON invocation: [{subprocess.list2cmdline(convert_json_args)} > {pandalog_json}]")
        try:
            with open(pandalog_json, 'wb') as fd:
                subprocess.check_call(convert_json_args, stdout=fd, stderr=sys.stderr, env=conversion_env)
        except subprocess.CalledProcessError as e:
            print("The script to convert the panda log into JSON has failed")
            raise e

        convert_time = tock(start)
        progress("bug_mining", 1, f"Converted JSON in {convert_time} seconds")

    def parse_replay_output():
        """
        Now call find_bug_injection (FBI) on the JSON log to populate the
        database with attack points, DUAs, etc.
        """
        print("Calling fbi - Mining PANDA log and populating database...")
        start = tick()
        lava_mode = project_data["lava_mode"]
        parse_panda_log(pandalog_json, project_data)
        record_injectable_bugs_offline(project_data, lava_mode)
        # Print all states from both Mining and Bug Creation
        print_bug_stats(project_data, debug=False)
        print_phase2_stats(project_data, debug=False)

        fib_time = tock(start)
        progress("bug_mining", 1, f"FBI complete {fib_time} seconds")
        sys.stdout.flush()

    if raw_command is not None:
        # pandare.panda's own "debug" name is a plain module-level bool that
        # record_cmd() checks to decide whether to print the guest's raw
        # output -- it's a separate copy from pandare.utils.debug (panda.py
        # does "from .utils import debug", which copies the value at import
        # time, so setting pandare.utils.debug here would silently do
        # nothing). This is the one record_cmd() actually reads.
        import pandare.panda
        pandare.panda.debug = True
        record()
        progress("bug_mining", 0, "SMOKE TEST complete -- stopping before replay/FBI. "
                                   "Check the '[PYPANDA] Result of ...' output above for what the guest actually printed.")
        return

    # Check if there is already a PANDA log...
    # If there is, skip straight to parsing the replay output, otherwise do the whole pipeline
    if steps is None and os.path.exists(pandalog_json):
        progress("bug_mining", 0, f"PANDA log json already exists at {pandalog_json}, skipping straight to parsing replay output")
        parse_replay_output()
        return
    if steps is None or "record" in steps:
        record()
    if steps is None or "replay" in steps:
        replay()
    if steps is None or "parse" in steps:
        parse_replay_output()


def main():
    parser = argparse.ArgumentParser(prog='This program is used to record and replay on PANDA '
                                              'to determine bug injection points using taint analysis.')
    parser.add_argument('-p', '--project', dest='project', action='store',
                        help="The name of the project, this contains project specific data", required=True,
                        type=str)
    # Select your steps you want to do:
    parser.add_argument("-a", "--all", action="store_true", help="Run all taint steps")
    parser.add_argument("--record", action="store_true", help="Record the taint information from the PANDA log")
    parser.add_argument("--replay", action="store_true", help="Replay the taint information to determine bug injection points")
    parser.add_argument("--parse", action="store_true", help="Parse the replay output to determine bug injection points")
    # Have a smoke test for debugging PANDA commands
    parser.add_argument('--smoke-test', dest='smoke_test',
                        action='store', default=None, type=str,
                        help="Skip the normal per-file batch command; revert/copy-to-guest as usual but "
                             "record exactly this raw shell command once instead, with Pypanda's verbose "
                             "logging on so you see the real guest output. Stops after recording -- no "
                             "replay, no FBI. E.g.: --smoke-test 'echo hello_from_guest'")
    args = parser.parse_args()
    project = parse_vars(args.project)
    steps = [
        step for step in ('record', 'replay', 'parse')
        if getattr(args, step)
    ]
    run_taint_pipeline(project, raw_command=args.smoke_test, steps=None if args.all or not steps else steps)

if __name__ == "__main__":
    main()
