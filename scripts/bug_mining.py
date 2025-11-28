"""
This script assumes you have already done src-to-src transformation with
lavaTool to add taint and attack point queries to a program, AND managed to
json project file.

Second arg is an input file you want to run, under panda, to get taint info.
"""

import os
import sys
import time
import shlex
import shutil
import subprocess
from colorama import Fore, Style
from pandare.extras import dwarfdump
from find_bug_injection import parse_panda_log, print_bug_stats
from vars import parse_vars
from pandare import Panda
from dotenv import load_dotenv
import argparse


load_dotenv()


parser = argparse.ArgumentParser(prog='This program is used to record and replay on PANDA '
                                      'to determine bug injection points using taint analysis.')
parser.add_argument('--host', dest='host', action='store',
                    help="The path to the host.json file", type=str, required=True)
parser.add_argument('-p', '--project', dest='project', action='store',
                    help="The name of the project, this contains project specific data", required=True,
                    type=str)
parser.add_argument('--curtail', '-c', nargs='?', dest='curtail', action='store',
                    help="The curtail value", const=1, default=0, type=int)
args = parser.parse_args()


project = parse_vars(args.host, args.project)
project["curtail"] = args.curtail
qemu_path = project['qemu']
panda = Panda(generic=qemu_path.split('-')[-1])

start_time = 0
command_args = []
install_directory = ""
selected_filename = ""

# Replace create_recording in first link
# https://github.com/panda-re/panda/blob/dev/panda/scripts/run_guest.py#L151-L189
# https://github.com/panda-re/panda/blob/dev/panda/python/core/pandare/panda.py#L2595-L2645
@panda.queue_blocking
def create_recording():
    """
    Create a recording in PANDA with the given command arguments.
    This function reverts to the 'root' snapshot, copies the installation directory
    to the guest, and starts recording the specified command.
    1. Revert to 'root' snapshot
    2. Copy install_directory to guest
    3. Start recording the command specified in command_args, this runs the program on a folder of inputs
    4. Stop the recording after the command completes
    """
    global command_args
    global install_directory
    # Use absolute paths for BOTH arguments!
    print("args", command_args)
    print("install dir", install_directory)
    guest_command = subprocess.list2cmdline(command_args)
    # Technically the first two steps of record_cmd
    # but running executable ONLY works with absolute paths
    panda.revert_sync('root')
    panda.copy_to_guest(install_directory, absolute_paths=True)

    # Pass in None for snap_name since I already did the revert_sync already
    panda.record_cmd(guest_command=guest_command, snap_name=None)
    panda.stop_run()


def tick():
    """
    Start a timer.
    """
    global start_time
    start_time = time.time()


def tock():
    """
    Stop the timer and return elapsed time.
    """
    global start_time
    return time.time() - start_time


def progress(message: str):
    """
    Print a progress message to stdout.
    Args:
        message: message to print
    """
    print()
    if sys.stdout.isatty():
        print(Fore.GREEN + '[bug_mining.py] ' +
              Fore.RESET + Style.BRIGHT + message + Style.RESET_ALL)
    else:
        print('[bug_mining.py] ' + message)


def record():
    global command_args
    global install_directory
    global selected_filename
    tick()
    input_file_directory = os.path.abspath(os.path.join(project["config_dir"], "inputs"))
    progress("Entering {}".format(project['output_dir']))
    os.chdir(project['output_dir'])

    # When you unpack a tarfile, it usually creates a subdirectory.
    tar_files = subprocess.check_output(['tar', 'tf', project['tarfile']]).decode('utf-8')
    tar_directory = tar_files.splitlines()[0].split(os.path.sep)[0]
    tar_directory = os.path.abspath(tar_directory)
    install_directory = os.path.join(tar_directory, 'lava-install')
    guest_directory_inputs_path = os.path.join(install_directory, 'inputs')

    progress(f"Copying directory {input_file_directory} to {guest_directory_inputs_path}")
    # copytree requires the destination to NOT exist
    if os.path.exists(guest_directory_inputs_path):
        progress("Deleting existing inputs/ directory in guest install")
        shutil.rmtree(guest_directory_inputs_path)

    shutil.copytree(input_file_directory, guest_directory_inputs_path)
    print()

    # 2. EXTRACT THE TARGET BINARY PATH
    # We need to know what binary to run. Your JSON has "{install_dir}/bin/toy {input_file}"
    # We format it with an empty input_file to isolate the binary path.
    # TODO: We will use this eventually...
    #guest_executable = project['command'].format(
    #    install_dir=shlex.quote(install_directory),
    #    input_file=""
    #).strip()

    # 3. CONSTRUCT THE BATCH COMMAND
    # We use bash -c so we can use pipes (|) inside the guest command safely.
    # Note: {{}} is how we escape curly braces in Python f-strings so xargs gets "{}".
    # We use -print0 and -0 to handle filenames with spaces correctly.
    # TODO: We will use this eventually...
    # batch_shell_command = (
    #    f"find {shlex.quote(guest_directory_inputs_path)} -type f -print0 | "
    #    f"xargs -0 -I {{}} {guest_executable} {{}}"
    # )

    # pick a file from `guest_directory_inputs_path`, remember, you now have a folder in panda...
    files = [f for f in os.listdir(guest_directory_inputs_path)
             if os.path.isfile(os.path.join(guest_directory_inputs_path, f))]
    if not files:
        raise RuntimeError(f"No input files found in {guest_directory_inputs_path}")

    selected_filename = files[0]
    selected_path = os.path.join(guest_directory_inputs_path, selected_filename)

    # build the guest command using the selected file (quote to handle spaces)
    batch_shell_command = project['command'].format(
        install_dir=shlex.quote(install_directory),
        input_file=shlex.quote(selected_path)
    ).strip()

    print("Selected input:", selected_path)
    progress(f"Generated Guest Command: {batch_shell_command}")

    # PANDA expects a list. We pass bash as the exe, and the whole string as the arg.
    command_args = batch_shell_command.split()

    # In CI/CD, we should try to use complete record and replay
    # Also, please avoid using debug prints in CI/CD, it can cause issues.
    if project["complete_rr"]:
        progress("Using complete record and replay, likely in GitHub CI/CD")
        panda.set_complete_rr_snapshot()

    panda.run()

    # inject.py will use this folder for fuzzing, we likely should update this structure to sort inputs better
    if os.path.exists('inputs/'):
        shutil.rmtree('inputs/')

    shutil.copytree(input_file_directory, 'inputs/')

    record_time = tock()
    print("panda record complete %.2f seconds" % record_time)
    sys.stdout.flush()


def replay():
    """
    Replay the recording in PANDA with taint analysis enabled. Activate the plugins to obtain the taint data
    from the PANDA log.
    """
    global install_directory
    debug = project["debug"]
    tick()
    print()
    progress("Starting first and only replay, tainting on file open...")
    guest_executable = project['command'].format(
        install_dir=shlex.quote(install_directory),
        input_file=""
    ).strip()

    dwarf_cmd = ["dwarfdump", "-dil", guest_executable]
    dwarf_output = subprocess.check_output(dwarf_cmd)
    dwarfdump.parse_dwarfdump(dwarf_output, guest_executable)
    proc_name = os.path.basename(guest_executable)

    pandalog = "{}/queries-{}.plog".format(project['output_dir'], args.project)

    progress("pandalog = [%s] " % pandalog)

    panda.set_pandalog(pandalog)
    panda.load_plugin("pri")
    panda.load_plugin("dwarf2",
                      args={
                          'proc': proc_name,
                          'g_debugpath': install_directory,
                          'h_debugpath': install_directory,
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
                          'filename': os.path.join(install_directory, 'inputs', selected_filename),
                          'pos': True,
                          'verbose': debug
                      })

    # Default name is 'recording'
    # https://github.com/panda-re/panda/blob/dev/panda/python/core/pandare/panda.py#L2595
    panda.run_replay("recording")

    replay_time = tock()
    print("taint analysis complete %.2f seconds" % replay_time)
    sys.stdout.flush()


def parse_replay_output():
    """
    First convert the panda log into JSON. Then call find_bug_injection (FBI) on the JSON log to populate the
    database with attack points, DUAs, etc.
    """
    global selected_filename
    # I attempted to upgrade the version, but panda had trouble including <protobuf-c/protobuf.h> something
    # for now, we can use the python implementation, although it is slower
    # https://github.com/protocolbuffers/protobuf/releases/tag/v21.0
    # https://stackoverflow.com/questions/52040428/how-to-update-protobuf-runtime-library
    tick()
    pandalog = "{}/queries-{}.plog".format(project['output_dir'], args.project)
    pandalog_json = "{}/queries-{}.json".format(project['output_dir'], args.project)
    os.environ['PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION'] = 'python'
    progress("Calling the FBI on queries.plog...")
    convert_json_args = ['python3', '-m', 'pandare.plog_reader', pandalog]
    print("panda log JSON invocation: [%s > %s]" % (subprocess.list2cmdline(convert_json_args), pandalog_json))
    try:
        with open(pandalog_json, 'wb') as fd:
            subprocess.check_call(convert_json_args, stdout=fd, stderr=sys.stderr)
    except subprocess.CalledProcessError as e:
        print("The script to convert the panda log into JSON has failed")
        raise e

    input_file_base = selected_filename
    if project.get("python_fbi", False):
        print("Calling fbi invocation - Python")
        sys.stdout.flush()

        # Set a few variables before you call fbi
        project["max_liveness"] = 100000
        project["max_cardinality"] = 100
        project["max_tcn"] = 100
        project["max_lval_size"] = 100
        project["input"] = input_file_base

        parse_panda_log(pandalog_json, project)
    else:
        fbi_args = ['fbi', args.host, args.project, pandalog_json, input_file_base, str(project["curtail"])]
        print("fbi invocation - C++: [%s]" % subprocess.list2cmdline(fbi_args))
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
        print_bug_stats(project)

    fib_time = tock()
    print("fib complete %.2f seconds" % fib_time)
    sys.stdout.flush()


if __name__ == "__main__":
    record()
    replay()
    parse_replay_output()
