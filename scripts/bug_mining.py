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

from colorama import Fore
from colorama import Style
from os.path import basename

from lava import Dua
from lava import Bug
from lava import AttackPoint
from lava import LavaDatabase

from vars import parse_vars
from os.path import abspath, join
from pandare import Panda
from pandare.extras import dwarfdump
from dotenv import load_dotenv

load_dotenv()

host_json = abspath(sys.argv[1])
project_name = sys.argv[2]

if len(sys.argv) < 3:
    print("Usage: python bug_mining.py host.json project_name", file=sys.stderr)
    sys.exit(1)
elif len(sys.argv) == 3:
    # global curtail
    curtail = int(sys.argv[3])
#else:
#    print("Usage: python bug_mining.py host.json project_name <curtail>", file=sys.stderr)
#    sys.exit(1)

project = parse_vars(host_json, project_name)
qemu_path = project['qemu']
debug = project['debug']

panda = Panda(generic=qemu_path.split('-')[-1])

start_time = 0
curtail = 0


# Replace create_recording in first link
# https://github.com/panda-re/panda/blob/dev/panda/scripts/run_guest.py#L151-L189
# https://github.com/panda-re/panda/blob/dev/panda/python/core/pandare/panda.py#L2595-L2645
@panda.queue_blocking
def create_recording():
    global command_args
    global install_directory
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
    global start_time
    start_time = time.time()


def tock():
    global start_time
    return time.time() - start_time


def dprint(msg: str, debug_bool: bool):
    if debug_bool:
        print(msg)


def progress(msg):
    print()
    if sys.stdout.isatty():
        print(Fore.GREEN + '[bug_mining.py] ' +
              Fore.RESET + Style.BRIGHT + msg + Style.RESET_ALL)
    else:
        print('[bug_mining.py] ' + msg)

tick()

input_file_directory = abspath(join(project["config_dir"], "inputs"))

progress("Entering {}".format(project['output_dir']))
os.chdir(project['output_dir'])

# When you unpack a tarfile, it usually creates a subdirectory.
tar_files = subprocess.check_output(['tar', 'tf', project['tarfile']]).decode('utf-8')
tar_directory = tar_files.splitlines()[0].split(os.path.sep)[0]
tar_directory = abspath(tar_directory)

install_directory = join(tar_directory, 'lava-install')
guest_directory_inputs_path = join(install_directory, 'inputs')

progress(f"Copying directory {input_file_directory} to {guest_directory_inputs_path}")
# copytree requires the destination to NOT exist
if os.path.exists(guest_directory_inputs_path):
    progress("Deleting existing inputs/ directory in guest install")
    shutil.rmtree(guest_directory_inputs_path)

shutil.copytree(input_file_directory, guest_directory_inputs_path)

# TODO: We should swap to use 'fbi' in Debian package instead
lava_directory = project["qcow_dir"]
print()

# 2. EXTRACT THE TARGET BINARY PATH
# We need to know what binary to run. Your JSON has "{install_dir}/bin/toy {input_file}"
# We format it with an empty input_file to isolate the binary path.
guest_executable = project['command'].format(
    install_dir=shlex.quote(install_directory),
    input_file=""
).strip()

# 3. CONSTRUCT THE BATCH COMMAND
# We use bash -c so we can use pipes (|) inside the guest command safely.
# Note: {{}} is how we escape curly braces in Python f-strings so xargs gets "{}".
# We use -print0 and -0 to handle filenames with spaces correctly.
batch_shell_command = (
    f"find {shlex.quote(guest_directory_inputs_path)} -type f -print0 | "
    f"xargs -0 -I {{}} {guest_executable} {{}}"
)

progress(f"Generated Guest Command: {batch_shell_command}")

# PANDA expects a list. We pass bash as the exe, and the whole string as the arg.
command_args = ["/bin/bash", "-c", batch_shell_command]

# In CI/CD, we should try to use complete record and replay
# Also, please avoid using debug prints in CI/CD, it can cause issues.
if project["complete_rr"]:
    progress("Using complete record and replay, likely in GitHub CI/CD")
    panda.set_complete_rr_snapshot()

panda.run()

if os.path.exists('inputs/'):
    shutil.rmtree('inputs/')

shutil.copytree(input_file_directory, 'inputs/')

record_time = tock()
print("panda record complete %.2f seconds" % record_time)
sys.stdout.flush()

tick()
print()
progress("Starting first and only replay, tainting on file open...")

dwarf_cmd = ["dwarfdump", "-dil", guest_executable]
dwarf_output = subprocess.check_output(dwarf_cmd)
dwarfdump.parse_dwarfdump(dwarf_output, guest_executable)
proc_name = basename(guest_executable)

pandalog = "{}/queries-{}.plog".format(project['output_dir'], project_name)
pandalog_json = "{}/queries-{}.json".format(project['output_dir'], project_name)

progress("pandalog = [%s] " % pandalog)

panda.set_pandalog(pandalog)
panda.load_plugin("pri")
panda.load_plugin("dwarf2",
                  args={
                      'proc': proc_name,
                      'g_debugpath': install_directory,
                      'h_debugpath': install_directory,
                      'debug' : debug
                  })
panda.load_plugin("pri_taint", args={
    'hypercall' : True,
    'debug' : debug
})
panda.load_plugin("taint2",
                  args={
                      'no_tp': True,
                      'debug': debug
                  })
panda.load_plugin('tainted_branch')
panda.load_plugin("file_taint",
                    args={
                        'filename': guest_directory_inputs_path + "/*",
                        'pos': True,
                        'verbose': debug
                    })

# Default name is 'recording'
# https://github.com/panda-re/panda/blob/dev/panda/python/core/pandare/panda.py#L2595
panda.run_replay("recording")

replay_time = tock()
print("taint analysis complete %.2f seconds" % replay_time)
sys.stdout.flush()

tick()

# I attempted to upgrade the version, but panda had trouble including <protobuf-c/protobuf.h> something
# for now, we can use the python implementation, although it is slower
# https://github.com/protocolbuffers/protobuf/releases/tag/v21.0
# https://stackoverflow.com/questions/52040428/how-to-update-protobuf-runtime-library
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

fbi_args = [join(lava_directory, 'tools', 'install', 'bin', 'fbi'), host_json,
            project_name, pandalog_json, project_name]

# Command line curtail argument takes priority, otherwise use project specific one
# global curtail
if curtail != 0:
    fbi_args.append(str(curtail))
elif "curtail" in project:
    fbi_args.append(str(project.get("curtail", 0)))

dprint("fbi invocation: [%s]" % (subprocess.list2cmdline(fbi_args)), debug)
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

print()
progress("Found Bugs, Injectable!!")

fib_time = tock()
print("fib complete %.2f seconds" % fib_time)
sys.stdout.flush()

db = LavaDatabase(project)

print("Count\tBug Type Num\tName")
for i in range(len(Bug.type_strings)):
    n = db.session.query(Bug).filter(Bug.type == i).count()
    print("%d\t%d\t%s" % (n, i, Bug.type_strings[i]))

print("total dua:", db.session.query(Dua).count())
print("total atp:", db.session.query(AttackPoint).count())
print("total bug:", db.session.query(Bug).count())
db.session.close()
