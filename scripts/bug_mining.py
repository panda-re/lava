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

from errno import EEXIST

from os.path import dirname
from os.path import basename

from lava import Dua
from lava import Bug
from lava import AttackPoint
from lava import LavaDatabase

from vars import parse_vars
from os.path import abspath, join
from pandare import Panda
from pandare.extras import dwarfdump

host_json = abspath(sys.argv[1])
project_name = sys.argv[2]

project = parse_vars(host_json, project_name)
qemu_path = project['qemu']

panda = Panda(generic=qemu_path.split('-')[-1],
              expect_prompt=project['expect_prompt'])

debug = True
qemu_use_rr = False

start_time = 0
version = "2.0.0"
curtail = 0

installdir = None
command_args = None


# Replace create_recording in first link
# https://github.com/panda-re/panda/blob/dev/panda/scripts/run_guest.py#L151-L189
# https://github.com/panda-re/panda/blob/dev/panda/python/core/pandare/panda.py#L2595-L2645
@panda.queue_blocking
def create_recording():
    global command_args
    global installdir
    print("args", command_args)
    print("install dir", installdir)
    guest_command = subprocess.list2cmdline(command_args)
    # Technically the first two steps of record_cmd
    # but running executable ONLY works with absolute paths
    panda.revert_sync('root')
    panda.copy_to_guest(installdir, absolute_paths=True)

    # Pass in None for snap_name since I already did the revert_sync already
    panda.record_cmd(guest_command=guest_command, snap_name=None)
    panda.stop_run()


def tick():
    global start_time
    start_time = time.time()


def tock():
    global start_time
    return time.time() - start_time


def dprint(msg):
    if debug:
        print(msg)


def progress(msg):
    print()
    if sys.stdout.isatty():
        print(Fore.GREEN + '[bug_mining.py] ' +
              Fore.RESET + Style.BRIGHT + msg + Style.RESET_ALL)
    else:
        print('[bug_mining.py] ' + msg)


if len(sys.argv) < 4:
    print("Bug mining script version {}".format(version))
    print("Usage: python bug_mining.py host.json project_name inputfile",
          file=sys.stderr)
    sys.exit(1)

tick()

input_file = abspath(project["config_dir"] + "/" + sys.argv[3])
input_file_base = os.path.basename(input_file)
print("bug_mining.py %s %s" % (project_name, input_file))

if len(sys.argv) > 4:
    # global curtail
    curtail = int(sys.argv[4])

lavadir = dirname(dirname(abspath(sys.argv[0])))

progress("Entering {}".format(project['output_dir']))

os.chdir(os.path.join(project['output_dir']))

tar_files = subprocess.check_output(['tar', 'tf', project['tarfile']]).decode('utf-8')
sourcedir = tar_files.splitlines()[0].split(os.path.sep)[0]
sourcedir = abspath(sourcedir)

print()
# e.g. file-5.22-true.iso
installdir = join(sourcedir, 'lava-install')
input_file_guest = join(installdir, input_file_base)
command_args = shlex.split(
    project['command'].format(
        install_dir=shlex.quote(installdir),
        input_file=input_file_guest))
shutil.copy(input_file, installdir)

panda.run()

try:
    os.mkdir('inputs')
except OSError as e:
    if e.errno != EEXIST:
        raise
shutil.copy(input_file, 'inputs/')

record_time = tock()
print("panda record complete %.2f seconds" % record_time)
sys.stdout.flush()

tick()
print()
progress("Starting first and only replay, tainting on file open...")

# process name
if command_args[0].startswith('LD_PRELOAD'):
    cmdpath = command_args[1]
    proc_name = basename(command_args[1])
else:
    cmdpath = command_args[0]
    proc_name = basename(command_args[0])

binpath = os.path.join(installdir, "bin", proc_name)
if not os.path.exists(binpath):
    binpath = os.path.join(installdir, "lib", proc_name)
    if not os.path.exists(binpath):
        binpath = os.path.join(installdir, proc_name)

pandalog = "{}/queries-{}.plog".format(project['output_dir'], input_file_base)
pandalog_json = "{}/queries-{}.json".format(project['output_dir'], input_file_base)

print("pandalog = [%s] " % pandalog)

dwarf_cmd = ["dwarfdump", "-dil", cmdpath]
dwarfout = subprocess.check_output(dwarf_cmd)
dwarfdump.parse_dwarfdump(dwarfout, binpath)

# Based on this example:
# https://github.com/panda-re/panda/blob/dev/panda/python/examples/file_taint/file_taint.py
panda.set_pandalog(pandalog)
panda.load_plugin("pri")
panda.load_plugin("taint2",
                  args={
                      'no_tp': True
                  })
panda.load_plugin("tainted_branch")

panda.load_plugin("dwarf2",
                  args={
                      'proc': proc_name,
                      'g_debugpath': installdir,
                      'h_debugpath': installdir
                  })
# pri_taint is almost same as Zhenghao's hypercall
# Chaffx64 branch says these are needed?
# if panda.arch != 'i386':
#    panda.load_plugin('hypercall')
#    panda.load_plugin('stackprob')


print(project)
#print('use_stdin' in project)
#print(project['use_stdin'])
if 'use_stdin' in project and project['use_stdin']:
    print("Using stdin for taint analysis")
    panda.load_plugin("file_taint",
                      args={
                          'filename': input_file_guest,
                          'pos': True,
                          'cache_process_details_on_basic_block': True,
                          'enable_taint_on_open': True,
                          'verbose': True
                      })
else:
    print("Using open for taint analysis")
    panda.load_plugin("file_taint",
                      args={
                          'filename': input_file_guest,
                          'pos': True,
                          'cache_process_details_on_basic_block': True,
                          'first_instr': 1,
                          'use_stdin': proc_name,
                          'verbose': True
                      })

panda.load_plugin("pri_taint", args={
    'hypercall': True,
    'chaff': False
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
print("panda log JSON invocation: [%s] > %s" % (subprocess.list2cmdline(convert_json_args), pandalog_json))
try:
    with open(pandalog_json, 'wb') as fd:
        subprocess.check_call(convert_json_args, stdout=fd, stderr=sys.stderr)
except subprocess.CalledProcessError as e:
    print("The script to convert the panda log into JSON has failed")
    raise e

# fbi_args = [join(lavadir, 'fbi', 'fbi'),
# project_file, pandalog, input_file_base]
fbi_args = [join(lavadir, 'tools', 'install', 'bin', 'fbi'), host_json,
            project_name, pandalog_json, input_file_base]

# Command line curtial argument takes priority, otherwise use project specific one
# global curtail
if curtail != 0:
    fbi_args.append(str(curtail))
elif "curtail" in project:
    fbi_args.append(str(project.get("curtail", 0)))

dprint("fbi invocation: [%s]" % (subprocess.list2cmdline(fbi_args)))
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
