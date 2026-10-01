"""
This script assumes you have already done src-to-src transformation with
lavaTool to add taint and attack point queries to a program, AND managed to
JSON project file.

Second arg is an input file you want to run, under panda, to get taint info.
"""

import os
import sys
import shlex
import shutil
import subprocess
from pandare import Panda
import argparse
from typing import Optional

# LAVA
from . import dwarfdump
from ..taint.find_bug_injection import parse_panda_log, print_bug_stats
from ..utils.vars import parse_vars
from ..utils.funcs import tick, tock, progress
from ..taint.generate_bugs import record_injectable_bugs_offline, print_phase2_stats


def run_taint_pipeline(lava_project: str, project_data: dict, raw_command: Optional[str] = None):
    """
    Initializes the project and PANDA object based on arguments.

    raw_command: smoke-test mode. When set, skip the normal per-file batch
    command entirely and record this exact string once instead, with
    pypanda's own verbose logging turned on so you see the real guest
    output (record_cmd() doesn't return its result normally -- only prints
    it if pandare.panda.debug is True, which this sets). Stops after
    recording; does not replay or run FBI. Useful for sanity-checking
    pypanda/record_cmd/copy_to_guest against a project's actual install
    directory without wading through the full taint pipeline, e.g. to
    confirm a binary even launches before debugging why no taint appeared.
    """
    panda = Panda(generic=project_data['qemu'])
    panda_log = "{}/queries-{}.plog".format(project_data['output_dir'], project_data['name'])
    pandalog_json = "{}/queries-{}.json".format(project_data['output_dir'], project_data['name'])

    class State:
        guest_command = ""
        install_directory = ""
        tar_directory = ""
    state = State()

    @panda.queue_blocking
    def create_recording_wrapper():
        """
        Create a recording in PANDA with the given command arguments.
        This function reverts to the 'root' snapshot, copies the installation directory
        to the guest, and starts recording the specified command.
        1. Revert to 'root' snapshot
        2. Copy install_directory to guest
        3. Start recording the command in state.guest_command, this runs the program on a folder of inputs
        4. Stop the recording after the command completes
        """
        guest_command = state.guest_command
        # Technically the first two steps of record_cmd
        # but running executable ONLY works with absolute paths
        panda.revert_sync('root')
        panda.copy_to_guest(state.install_directory, absolute_paths=True)

        # Pass in None for snap_name since I already did the revert_sync already
        panda.record_cmd(guest_command=guest_command, snap_name=None)
        panda.stop_run()

    def record():
        start = tick()
        input_file_directory = os.path.abspath(os.path.join(project_data["config_dir"], "inputs"))
        progress("bug_mining", 0, "Entering {}".format(project_data['output_dir']))
        os.chdir(project_data['output_dir'])

        # When you unpack a tarfile, it usually creates a subdirectory.
        tar_files = subprocess.check_output(['tar', 'tf', project_data['tarfile']]).decode('utf-8')
        state.tar_directory = os.path.abspath(tar_files.splitlines()[0].split(os.path.sep)[0])
        state.install_directory = os.path.join(state.tar_directory, 'lava-install')
        guest_directory_inputs_path = os.path.join(state.install_directory, 'inputs')

        progress("bug_mining", 0, f"Copying directory {input_file_directory} to {guest_directory_inputs_path}")
        # copytree requires the destination to NOT exist
        if os.path.exists(guest_directory_inputs_path):
            progress("bug_mining", 0, "Deleting existing inputs/ directory in guest install")
            shutil.rmtree(guest_directory_inputs_path)

        shutil.copytree(input_file_directory, guest_directory_inputs_path)

        # 2. BUILD THE PER-FILE COMMAND, WITH A REAL SHELL VARIABLE DROPPED IN
        if raw_command is not None:
            # Smoke-test mode: skip the whole per-file batch construction and
            # record exactly what was passed on the command line.
            progress("bug_mining", 0, f"SMOKE TEST: recording raw command as-is: {raw_command}")
            state.guest_command = raw_command
        else:
            guest_executable_template = project_data['command'].format(
                install_dir=shlex.quote(state.install_directory),
                input_file='"$f"'
            ).strip()

            # 3. CONSTRUCT THE BATCH COMMAND AS A PLAIN BASH for LOOP.
            # Deliberately not "find | xargs -I {}": that adds a layer of
            # placeholder-substitution indirection on top of the one above, is
            # harder to reproduce by hand when something goes wrong (which it has,
            # twice), and buys nothing a for loop doesn't already give us --
            # "for f in dir/*" is safe for filenames with spaces as long as "$f"
            # stays quoted (glob expansion isn't subject to IFS word-splitting the
            # way command substitution is). Same semantics either way: one
            # continuous PANDA recording, one target process per file, run
            # strictly sequentially.
            batch_shell_command = (
                f"for f in {shlex.quote(guest_directory_inputs_path)}/*; do "
                f"{guest_executable_template}; done"
            )

            progress("bug_mining", 0, f"Generated Guest Command: {batch_shell_command}")

            # Keep the fully-formed shell string as-is -- see the comment in
            # create_recording_wrapper() for why round-tripping this through
            # .split() + subprocess.list2cmdline() (the previous approach) is
            # actively wrong here, not just unnecessary.
            state.guest_command = batch_shell_command

        # In CI/CD, we should try to use complete record and replay
        # Also, please avoid using debug prints in CI/CD, it can cause issues.
        if project_data["complete_rr"]:
            progress("bug_mining", 0, "Using complete record and replay, likely in GitHub CI/CD")
            panda.set_complete_rr_snapshot()

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

        dwarf_cmd = ["dwarfdump", "-dil", guest_executable]
        progress("bug_mining", 1, f"Running Dwarf Dump {subprocess.list2cmdline(dwarf_cmd)}")
        result = subprocess.run(
            dwarf_cmd,
            capture_output=True,
            text=True
        )

        if result.stdout is None:
            raise RuntimeError(f"Critical Error: blank output from dwarfdump!")

        progress("bug_mining", 1, "Converting Dwarf Dump into JSON")
        dwarfdump.parse_dwarfdump(result.stdout, guest_executable, project_root=state.tar_directory)
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

        # I attempted to upgrade the version, but panda had trouble including <protobuf-c/protobuf.h> something
        # for now, we can use the python implementation, although it is slower
        # https://github.com/protocolbuffers/protobuf/releases/tag/v21.0
        # https://stackoverflow.com/questions/52040428/how-to-update-protobuf-runtime-library
        os.environ['PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION'] = 'python'
        progress("bug_mining", 0, "Converting PANDA Log to JSON...")
        convert_json_args = ['python3', '-m', 'pandare.plog_reader', panda_log]
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
                subprocess.check_call(convert_json_args, stdout=fd, stderr=sys.stderr)
        except subprocess.CalledProcessError as e:
            print("The script to convert the panda log into JSON has failed")
            raise e

    def parse_replay_output():
        """
        Now call find_bug_injection (FBI) on the JSON log to populate the
        database with attack points, DUAs, etc.
        """
        print("Calling fbi - Mining PANDA log and populating database...")
        start = tick()

        if project_data["use_c_fbi"]:
            fbi_args = ['fbi',
                        project_data["host_path"],
                        lava_project,
                        pandalog_json]

            print(f"C++ fbi invocation: [{subprocess.list2cmdline(fbi_args)}]")
            sys.stdout.flush()
            try:
                subprocess.check_call(fbi_args, stdout=sys.stdout, stderr=sys.stderr)
            except subprocess.CalledProcessError as e:
                print("FBI Failed. Possible causes: \n" +
                      "\tNo DUAs found because taint analysis failed: \n"
                      "\t\t Ensure PANDA 'saw open of file we want to taint'\n"
                      "\t\t Make sure target has debug symbols (version2): No 'failed DWARF loading' messages\n"
                      "\tFBI crashed (bad arguments, config, or other untested code)")
                raise e
        else:
            print(f"Python fbi invocation")
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
    if os.path.exists(pandalog_json):
        progress("bug_mining", 0, f"PANDA log json already exists at {pandalog_json}, skipping straight to parsing replay output")
        parse_replay_output()
        return
    record()
    replay()
    parse_replay_output()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='This program is used to record and replay on PANDA '
                                          'to determine bug injection points using taint analysis.')
    parser.add_argument('-p', '--project', dest='project', action='store',
                        help="The name of the project, this contains project specific data", required=True,
                        type=str)
    parser.add_argument('--smoke-test', dest='smoke_test',
                        action='store', default=None, type=str,
                        help="Skip the normal per-file batch command; revert/copy-to-guest as usual but "
                             "record exactly this raw shell command once instead, with Pypanda's verbose "
                             "logging on so you see the real guest output. Stops after recording -- no "
                             "replay, no FBI. E.g.: --smoke-test 'echo hello_from_guest'")
    args = parser.parse_args()
    project = parse_vars(args.project)
    run_taint_pipeline(args.project, project, raw_command=args.smoke_test)
