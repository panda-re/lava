"""
This script assumes you have already done src-to-src transformation with
lavaTool to add taint and attack point queries to a program, AND managed to
json project file.

Second arg is an input file you want to run, under panda, to get taint info.
"""

from __future__ import print_function

import os
import sys
import time
import pipes
import shlex
import shutil
import subprocess

from colorama import Fore
from colorama import Style

from errno import EEXIST

from os.path import join
from os.path import abspath
from os.path import dirname
from os.path import basename

from lava import Dua
from lava import Bug
from lava import AttackPoint
from lava import LavaDatabase

from vars import parse_vars

debug = True
qemu_use_rr = False

start_time = 0
version = "2.0.0"
curtail = 0


# Replace
# https://github.com/panda-re/panda/blob/dev/panda/scripts/run_guest.py
# https://docs.panda.re/#recordings
# https://github.com/panda-re/panda/blob/dev/panda/python/core/pandare/panda.py#L2595-L2645
def create_recording(qemu_path_name, command, copy_directory, iso_name):
    # I assume qemu_path is just 'panda-system-i386', `panda-system-x86_64`, etc.
    from pandare import Panda
    panda = Panda(arch=qemu_path_name.split('-')[-1])
    guest_command = subprocess.list2cmdline(command)
    panda.record_cmd(guest_command=guest_command, copy_directory=copy_directory, iso_name=iso_name)


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

host_json = abspath(sys.argv[1])
project_name = sys.argv[2]

project = parse_vars(host_json, project_name)

input_file = abspath(project["config_dir"] + "/" + sys.argv[3])
input_file_base = os.path.basename(input_file)
print("bug_mining.py %s %s" % (project_name, input_file))

if len(sys.argv) > 4:
    #global curtail
    curtail = int(sys.argv[4])

qemu_path = project['qemu']
qemu_build_dir = dirname(dirname(abspath(qemu_path)))
src_path = None

print("{}".format(join(qemu_build_dir, 'config-host.mak')))

with open(join(qemu_build_dir, 'config-host.mak')) as config_host:
    for line in config_host:
        var, sep, value = line.strip().partition('=')
        if var == 'SRC_PATH':
            src_path = value
            break
assert src_path
panda_scripts_dir = join(src_path, 'panda', 'scripts')
sys.path.append(panda_scripts_dir)


from os.path import abspath, join

chaff = project.get('chaff', False)

panda_os_string = project.get('panda_os_string',
                              'linux-32-debian:3.2.0-4-686-pae')

lavadir = dirname(dirname(abspath(sys.argv[0])))

progress("Entering {}".format(project['output_dir']))

os.chdir(os.path.join(project['output_dir']))

tar_files = subprocess.check_output(['tar', 'tf', project['tarfile']])
sourcedir = tar_files.splitlines()[0].split(os.path.sep)[0]
sourcedir = abspath(sourcedir)

print()
# e.g. file-5.22-true.iso
installdir = join(sourcedir, 'lava-install')
input_file_guest = join(installdir, input_file_base)
isoname = '{}-{}.iso'.format(sourcedir, input_file_base)
command_args = shlex.split(project['command'].format(
    install_dir=pipes.quote(installdir),
    input_file=input_file_guest))
shutil.copy(input_file, installdir)

create_recording(qemu_path, command_args, copy_directory=installdir, iso_name=isoname)

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
    proc_name = basename(command_args[1])
else:
    proc_name = basename(command_args[0])

pandalog = "{}/queries-{}.plog".format(project['output_dir'],
                                       os.path.basename(isoname))

print("pandalog = [%s] " % pandalog)

panda_args = {
    'pri': {},
    'pri_dwarf': {
        'proc': proc_name,
        'g_debugpath': installdir,
        'h_debugpath': installdir
    },
    'pri_taint': {
        'hypercall': True,
        'chaff': chaff
    },
    'taint2': {'no_tp': True},
    'tainted_branch': {},
    'file_taint': {
        'pos': True,
        'cache_process_details_on_basic_block': True,
    }
}

if 'use_stdin' in project and project['use_stdin']:
    panda_args['file_taint']['first_instr'] = 1
    panda_args['file_taint']['use_stdin'] = proc_name
else:
    panda_args['file_taint']['enable_taint_on_open'] = True

qemu_args = [
    project['qemu'], '-replay', isoname,
    '-pandalog', pandalog, '-os', panda_os_string
]

for plugin, plugin_args in panda_args.iteritems():
    qemu_args.append('-panda')
    arg_string = ",".join(["{}={}".format(arg, val)
                           for arg, val in plugin_args.iteritems()])
    qemu_args.append('{}{}{}'.format(plugin, ':'
    if arg_string else '', arg_string))

# Use -panda-plugin-arg to account for commas and colons in filename.
qemu_args.extend(['-panda-arg', 'file_taint:filename=' + input_file_guest])

dprint("qemu args: [{}]".format(subprocess.list2cmdline(qemu_args)))
sys.stdout.flush()
try:
    subprocess.check_call(qemu_args, stderr=subprocess.STDOUT)
except subprocess.CalledProcessError:
    if qemu_use_rr:
        qemu_args = ['rr', 'record', project['qemu'], '-replay', isoname]
        subprocess.check_call(qemu_args)
    else:
        raise

replay_time = tock()
print("taint analysis complete %.2f seconds" % replay_time)
sys.stdout.flush()

tick()

progress("Trying to create database {}...".format(project['name']))
createdb_args = ['createdb', '-U', 'postgres', '-h', 'database', project['db']]
createdb_result = subprocess.call(createdb_args,
                                  stdout=sys.stdout, stderr=sys.stderr)

print()
if createdb_result == 0:  # Created new DB; now populate
    progress("Database created. Initializing...")
    # psql_args = ['psql', '-U', 'postgres', '-d', project['db'],
    # '-f', join(join(lavadir, 'include'), 'lava.sql')]
    psql_args = ['psql', '-U', 'postgres', '-h', 'database', '-d', project['db'],
                 '-f', join(join(lavadir, 'fbi'), 'lava.sql')]
    dprint("psql invocation: [%s]" % (" ".join(psql_args)))
    subprocess.check_call(psql_args, stdout=sys.stdout, stderr=sys.stderr)
else:
    progress("Database already exists.")

print()
progress("Calling the FBI on queries.plog...")
# fbi_args = [join(lavadir, 'fbi', 'fbi'),
# project_file, pandalog, input_file_base]
fbi_args = [join(lavadir, 'tools', 'install', 'bin', 'fbi'), host_json,
            project_name, pandalog, input_file_base]

# Command line curtial argument takes priority, otherwise use project specific one
#global curtail
if curtail !=0 :
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
