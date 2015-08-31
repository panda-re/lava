'''
This script assumes you have already done src-to-src transformation with
lavaTool to add taint and attack point queries to a program, AND managed to
get it to compile.  The script 

Only two inputs to the script.

First is a json project file.  The set of asserts below 
indicate the required json fields and their meaning.

Second is input file you want to run, under panda, to get taint info.  


'''




import re
import os
import socket
import sys
import tempfile
import subprocess32
import shutil
import time
import pipes
import json
import psycopg2
from colorama import Fore, Back, Style
from pexpect import spawn, fdpexpect
from os.path import dirname, abspath, join

debug = True


def dprint(msg):
    if debug:
        print msg

def progress(msg):
    print Fore.RED + msg + Fore.RESET

if len(sys.argv) < 3:
    print >>sys.stderr, "Usage: python project.json inputfile"
    sys.exit(1)


project_file = abspath(sys.argv[1])
input_file = abspath(sys.argv[2])

print "bug_mining.py %s %s" % (project_file, input_file)

input_file_base = os.path.basename(input_file)
project = json.load(open(project_file, "r"))


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
# if needed, what to set LD_LIBRARY_PATH to
assert 'library_path' in project
# network name of host where postgres is running
assert 'dbhost' in project
# namespace in db for prospective bugs
assert 'db' in project

lavadir = dirname(dirname(abspath(sys.argv[0])))

progress("Entering {}.".format(project['directory']))
os.chdir(os.path.join(project['directory'], project['name']))

tar_files = subprocess32.check_output(['tar', 'tf', project['tarfile']])
sourcedir = tar_files.splitlines()[0].split(os.path.sep)[0]
sourcedir = abspath(sourcedir)

print
isoname = '{}-{}.iso'.format(sourcedir, input_file_base)
progress("Creaing ISO {}...".format(isoname))
installdir = join(sourcedir, 'lava-install')
shutil.copy(input_file, join(installdir, input_file_base))
subprocess32.check_call(['genisoimage', '-R', '-J',
    '-o', isoname, installdir])
try: os.mkdir('inputs')
except: pass
shutil.copy(input_file, 'inputs/')
os.unlink(join(installdir, input_file_base))

tempdir = tempfile.mkdtemp()

monitor_path = os.path.join(tempdir, 'monitor')
serial_path = os.path.join(tempdir, 'serial')
qemu_args = [project['qcow'], '-loadvm', project['snapshot'],
        '-monitor', 'unix:' + monitor_path + ',server,nowait',
        '-serial', 'unix:' + serial_path + ',server,nowait',
        '-display', 'none'] 

print
progress("Running qemu with args:")
print project['qemu'], " ".join(qemu_args)
print

os.mkfifo(monitor_path)
os.mkfifo(serial_path)
qemu = spawn(project['qemu'], qemu_args)
time.sleep(1)

monitor = spawn("socat", ["stdin", "unix-connect:" + monitor_path])
monitor.logfile = open(os.path.join(tempdir, 'monitor.txt'), 'w')
console = spawn("socat", ["stdin", "unix-connect:" + serial_path])
console.logfile = open(os.path.join(tempdir, 'console.txt'), 'w')

def run_monitor(cmd):
    if debug:
        print "monitor cmd: [%s]" % cmd
    print Style.BRIGHT + "(qemu)" + Style.RESET_ALL,
    monitor.sendline(cmd)
    monitor.expect_exact("(qemu)")
    print monitor.before.partition("\r\n")[2]

def run_console(cmd):
    if debug:
        print "console cmd: [%s]" % cmd
    print Style.BRIGHT + "root@debian-i386:~#" + Style.RESET_ALL,
    console.sendline(cmd)
    if expect in project:
        console.expect_exact(project['expect'])
    else:
        console.expect_exact("root@debian-i386:~#")
    print console.before.partition("\n")[2]

# Make sure monitor/console are in right state.
monitor.expect_exact("(qemu)")
console.sendline("")
console.expect_exact("root@debian-i386:~#")

progress("Inserting CD...")
run_monitor("change ide1-cd0 {}".format(isoname))
run_console("mkdir -p /mnt/cdrom")
run_console("mount /dev/cdrom /mnt/cdrom")

# Use the ISO name as the replay name.
progress("Beginning recording queries...")
run_monitor("begin_record {}".format(isoname))

progress("Running command inside guest...")
input_file_guest = join('/mnt/cdrom', input_file_base)
run_console("LD_LIBRARY_PATH={} {}".format(
    project['library_path'].format(install_dir='/mnt/cdrom'),
    project['command'].format(
        install_dir='/mnt/cdrom',
        input_file=input_file_guest)))

progress("Ending recording...")
run_monitor("end_record")

monitor.sendline("quit")
monitor.close()
console.close()
shutil.rmtree(tempdir)

progress("Starting first-pass replay...")
qemu_args = ['-replay', isoname,
        '-panda', 'taint2:no_tp',
        '-panda', 'file_taint:notaint,filename=' + input_file_guest]


dprint ("qemu args: [%s]" % (" ".join(qemu_args)))

qemu_replay = spawn(project['qemu'], qemu_args)
qemu_replay.logfile_read = sys.stdout
# trying to match this: saw open of file we want to taint: [/mnt/cdrom/bash] insn 10022563
qemu_replay.expect(re.compile("saw open of file we want to taint: \[.*\] insn ([0-9]+)"), timeout=400)

#after_progress = qemu_replay.before.rpartition(os.path.basename(isoname) + ":")[2]
#instr = int(after_progress.strip().split()[0])

instr = (int (qemu_replay.match.groups()[0])) - 10000
assert instr != 0
qemu_replay.close()

print
progress("Starting second-pass replay, tainting from {}...".format(instr))
pandalog = 'queries-{}.plog'.format(os.path.basename(isoname))

qemu_args = ['-replay', isoname,
        '-pandalog', pandalog,
        '-panda', 'taint2:no_tp',
        '-panda', 'tainted_branch',
        '-panda', 'file_taint:pos,first_instr={},filename={}'.format(
            instr, input_file_guest)]

dprint ("qemu args: [%s]" % (" ".join(qemu_args)))
subprocess32.check_call([project['qemu']]+ qemu_args, stdout=sys.stdout, stderr=sys.stderr)

progress("Trying to create database {}...".format(project['name']))
createdb_args = ['createdb', '-h', project['dbhost'],
        '-U', 'postgres', project['db']]
createdb_result = subprocess32.call(createdb_args, stdout=sys.stdout, stderr=sys.stderr)

print
if createdb_result == 0: # Created new DB; now populate
    progress("Database created. Initializing...")
    psql_args = ['psql', '-h', project['dbhost'], '-U', 'postgres',
            '-d', project['db'], '-f', join(join(lavadir, 'sql'), 'lava.sql')]
    dprint ("psql invocation: [%s]" % (" ".join(psql_args)))
    subprocess32.check_call(psql_args, stdout=sys.stdout, stderr=sys.stderr)
else:
    progress("Database already exists.")

print
progress("Calling the FBI on queries.plog...")
fbi_args = [join(lavadir, 'panda', 'fbi'), project_file, sourcedir, pandalog, input_file_base]
dprint ("fbi invocation: [%s]" % (" ".join(fbi_args)))
subprocess32.check_call(fbi_args, stdout=sys.stdout, stderr=sys.stderr)

print
progress("Found Bugs, Injectable!!")
