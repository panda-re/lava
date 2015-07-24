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

def progress(msg):
    print Fore.RED + msg + Fore.RESET

if len(sys.argv) < 2:
    print >>sys.stderr, "Usage: python project.json"
    sys.exit(1)

project_file = sys.argv[1]
project = json.load(open(project_file, "r"))
assert 'qemu' in project
assert 'snapshot' in project
assert 'directory' in project
assert 'command' in project
assert 'qcow' in project
assert 'name' in project
assert 'dbhost' in project
assert 'input_filename' in project

lavadir = dirname(dirname(abspath(sys.argv[0])))

progress("Entering {}.".format(project['directory']))
os.chdir(os.path.join(project['directory'], project['name']))
files = os.listdir('.')

tar_files = subprocess32.check_output(['tar', 'tf', project['tarfile']])
sourcedir = tar_files.splitlines()[0].split(os.path.sep)[0]

print
progress("Creaing ISO {}.iso...".format(sourcedir))
subprocess32.check_call(['genisoimage', '-R', '-J',
    '-o', sourcedir + '.iso', join(sourcedir, 'lava-install')])

tempdir = tempfile.mkdtemp()

monitor_path = os.path.join(tempdir, 'monitor')
serial_path = os.path.join(tempdir, 'serial')
qemu_args = [project['qcow'], '-loadvm', project['snapshot'],
        '-monitor', 'unix:' + monitor_path + ',server,nowait',
        '-serial', 'unix:' + serial_path + ',server,nowait',
        '-vnc', ':9']

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
    print Style.BRIGHT + "(qemu)" + Style.RESET_ALL,
    monitor.sendline(cmd)
    monitor.expect_exact("(qemu)")
    print monitor.before.partition("\r\n")[2]

def run_console(cmd):
    print Style.BRIGHT + "root@debian-i386:~#" + Style.RESET_ALL,
    console.sendline(cmd)
    console.expect_exact("root@debian-i386:~#")
    print console.before.partition("\n")[2]

# Make sure monitor/console are in right state.
monitor.expect_exact("(qemu)")
console.sendline("")
console.expect_exact("root@debian-i386:~#")

progress("Inserting CD...")
run_monitor("change ide1-cd0 {}".format(sourcedir + '.iso'))
run_console("mkdir -p /mnt/cdrom")
run_console("umount /mnt/cdrom")
run_console("mount /dev/cdrom /mnt/cdrom")

replay_name = "queries"
progress("Beginning recording queries...")
run_monitor("begin_record {}".format(replay_name))

progress("Running command inside guest...")
run_console(project['command'])

progress("Ending recording...")
run_monitor("end_record")

monitor.sendline("quit")
monitor.close()
console.close()
shutil.rmtree(tempdir)

progress("Starting first-pass replay...")
qemu_args = ['-replay', replay_name,
        '-panda', 'taint2:no_tp',
        '-panda', 'file_taint:notaint,filename=' + project['input_filename']]
qemu_replay = spawn(project['qemu'], qemu_args)
qemu_replay.logfile_read = sys.stdout
qemu_replay.expect_exact("saw open of file we want to taint")

after_progress = qemu_replay.before.rpartition(replay_name + ":")[2]
instr = int(after_progress.strip().split()[0])
assert instr != 0
qemu_replay.close()

print
progress("Starting second-pass replay, tainting from {}...".format(instr))
qemu_args = ['-replay', replay_name,
        '-pandalog', 'queries.plog',
        '-panda', 'taint2:no_tp',
        '-panda', 'tainted_branch',
        '-panda', 'file_taint:pos,first_instr={},filename={}'.format(
            instr, project['input_filename'])]

subprocess32.check_call([project['qemu']]+ qemu_args, stdout=sys.stdout, stderr=sys.stderr)

print
progress("Trying to create database {}...".format(project['name']))
createdb_args = ['createdb', '-h', project['dbhost'],
        '-U', 'postgres', project['db']]
createdb_result = subprocess32.call(createdb_args, stdout=sys.stdout, stderr=sys.stderr)

print
if createdb_result == 0: # Created new DB; now populate
    progress("Database created. Initializing...")
    pgsql_args = ['pgsql', '-h', project['dbhost'], '-U', 'postgres',
            '-d', project['db'], '-f', join(join(lavadir, 'sql'), 'lava.sql')]
    subprocess32.check_call(pgsql_args, stdout=sys.stdout, stderr=sys.stderr)
else:
    progress("Database already exists.")

print
progress("Calling the FBI on queries.plog...")
fbi_args = [join(lavadir, 'panda', 'fbi'), project_file, sourcedir]
subprocess32.check_call(fbi_args, stdout=sys.stdout, stderr=sys.stderr)

print
progress("Found Bugs, Injectable!!")
