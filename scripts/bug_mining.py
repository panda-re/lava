'''
This script assumes you have already done src-to-src transformation with
lavaTool to add taint and attack point queries to a program, AND managed to
get it to compile.  The script 

Only two inputs to the script.

First is a json project file.  The set of asserts below 
indicate the required json fields and their meaning.

Second is input file you want to run, under panda, to get taint info.  
'''

from __future__ import print_function

import json
import os
import pipes
import shlex
import shutil
import subprocess32
import sys
import time

from colorama import Fore, Style
from errno import EEXIST
from os.path import abspath, basename, dirname, join

from lava import LavaDatabase, Dua, Bug, AttackPoint

debug = True
qemu_use_rr = False

start_time = 0

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
        print(Fore.GREEN + '[bug_mining.py] ' + Fore.RESET + Style.BRIGHT + msg + Style.RESET_ALL)
    else:
        print('[bug_mining.py] ' + msg)

if len(sys.argv) < 3:
    print("Usage: python project.json inputfile", file=sys.stderr)
    sys.exit(1)

tick()

project_file = abspath(sys.argv[1])
input_file = abspath(sys.argv[2])
input_file_base = os.path.basename(input_file)

print("bug_mining.py %s %s" % (project_file, input_file))

with open(project_file, 'r') as project_f:
    project = json.load(project_f)

# *** Required json fields
# path to qemu exec (correct guest)
assert 'qemu' in project
# name of snapshot from which to revert which will be booted & logged in as root?
assert 'snapshot' in project
# same directory as in add_queries.sh, under which will be the build
assert 'directory' in project
# command line to run the target program (already instrumented with taint and attack queries)
assert 'command' in project
# path to guest qcow
assert 'qcow' in project
# name of project
assert 'name' in project
# path to tarfile for target (original source)
assert 'tarfile' in project
# namespace in db for prospective bugs
assert 'db' in project

qemu_path = project['qemu']
qemu_build_dir = dirname(dirname(abspath(qemu_path)))
src_path = None
with open(join(qemu_build_dir, 'config-host.mak')) as config_host:
    for line in config_host:
        var, sep, value = line.strip().partition('=')
        if var == 'SRC_PATH':
            src_path = value
            break
assert src_path
panda_scripts_dir = join(src_path, 'panda', 'scripts')
sys.path.append(panda_scripts_dir)
from run_guest import create_recording

chaff = project.get('chaff', False)

panda_os_string = project.get('panda_os_string', 'linux-32-debian:3.2.0-4-686-pae')

lavadir = dirname(dirname(abspath(sys.argv[0])))

progress("Entering {}.".format(project['directory']))

os.chdir(os.path.join(project['directory'], project['name']))

tar_files = subprocess32.check_output(['tar', 'tf', project['tarfile']])
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

create_recording(qemu_path, project['qcow'], project['snapshot'],
                 command_args, installdir, isoname, project["expect_prompt"], rr=qemu_use_rr)
                 #command_args, installdir, isoname, isoname, rr=qemu_use_rr) # for non-standard panda versions

try: os.mkdir('inputs')
except OSError as e:
    if e.errno != EEXIST: raise
shutil.copy(input_file, 'inputs/')

record_time = tock()
print("panda record complete %.2f seconds" % record_time)
sys.stdout.flush()

tick()
print()
progress("Starting first and only replay, tainting on file open...")

# process name
proc_name = basename(command_args[0])

pandalog = "%s/%s/queries-%s.plog" % (project['directory'], project['name'], os.path.basename(isoname))
print("pandalog = [%s] " % pandalog)

panda_args = {
    'syscalls2': { 'load-info': True },
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
    'taint2': { 'no_tp': True },
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
    arg_string = ",".join(["{}={}".format(arg, val) for arg, val in plugin_args.iteritems()])
    qemu_args.append('{}{}{}'.format(plugin, ':' if arg_string else '', arg_string))

# Use -panda-plugin-arg to account for commas and colons in filename.
qemu_args.extend(['-panda-arg', 'file_taint:filename=' + input_file_guest])

dprint("qemu args: [{}]".format(subprocess32.list2cmdline(qemu_args)))
sys.stdout.flush()
try:
    subprocess32.check_call(qemu_args, stderr=subprocess32.STDOUT)
except subprocess32.CalledProcessError:
    if qemu_use_rr:
        qemu_args = ['rr', 'record', project['qemu'], '-replay', isoname]
        subprocess32.check_call(qemu_args)
    else: raise

replay_time = tock()
print("taint analysis complete %.2f seconds" % replay_time)
sys.stdout.flush()

tick()

progress("Trying to create database {}...".format(project['name']))
createdb_args = ['createdb', '-U', 'postgres', project['db']]
createdb_result = subprocess32.call(createdb_args, stdout=sys.stdout, stderr=sys.stderr)

print()
if createdb_result == 0: # Created new DB; now populate
    progress("Database created. Initializing...")
    # psql_args = ['psql', '-U', 'postgres', '-d', project['db'],
                 # '-f', join(join(lavadir, 'include'), 'lava.sql')]
    psql_args = ['psql', '-U', 'postgres', '-d', project['db'],
                 '-f', join(join(lavadir, 'fbi'), 'lava.sql')]
    dprint ("psql invocation: [%s]" % (" ".join(psql_args)))
    subprocess32.check_call(psql_args, stdout=sys.stdout, stderr=sys.stderr)
else:
    progress("Database already exists.")

print()
progress("Calling the FBI on queries.plog...")
fbi_args = [join(lavadir, 'fbi', 'fbi'), project_file, pandalog, input_file_base]
dprint ("fbi invocation: [%s]" % (subprocess32.list2cmdline(fbi_args)))
subprocess32.check_call(fbi_args, stdout=sys.stdout, stderr=sys.stderr)

print()
progress("Found Bugs, Injectable!!")

fib_time = tock()
print("fib complete %.2f seconds" % fib_time)
sys.stdout.flush()

db = LavaDatabase(project)

print("total dua:", db.session.query(Dua).count())
print("total atp:", db.session.query(AttackPoint).count())
print("total bug:", db.session.query(Bug).count())


