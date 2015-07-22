import os
import socket
import sys
import tempfile
import subprocess32
import shutil
import time
import pipes
import json
from colorama import Fore, Back, Style
from pexpect import spawn, fdpexpect

def cleanup(msg=None):
    if msg:
        print >>sys.stderr, msg

    try:
        qemu.kill()
        monitor.close()
        serial.close()
    except:
        pass
    
    try:
        shutil.rmtree(tempdir)
        pass
    except OSError:
        print "Still connected! Error!"
    sys.exit(1 if msg else 0)

def sockexpect(path):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(path)
    return fdpexpect.fdspawn(sock)

def progress(msg):
    print Fore.RED + msg + Fore.RESET

if len(sys.argv) < 2:
    print >>sys.stderr, "Usage: python project.json"
    sys.exit(1)

project = json.load(open(sys.argv[1], "r"))
assert 'qemu' in project
assert 'snapshot' in project
assert 'directory' in project
assert 'command' in project
assert 'qcow' in project
assert 'name' in project

progress("Entering {}.".format(project['directory']))
os.chdir(os.path.join(project['directory'], project['name']))
files = os.listdir('.')
sourcedir = ""
for f in files:
    if os.path.isdir(f):
        sourcedir = f

progress("Creaing ISO {}.iso...".format(sourcedir))
subprocess32.check_call(['genisoimage', '-R', '-J',
    '-o', sourcedir + '.iso', sourcedir])

tempdir = tempfile.mkdtemp()

monitor_path = os.path.join(tempdir, 'monitor')
serial_path = os.path.join(tempdir, 'serial')
qemu_args = [project['qcow'], '-loadvm', project['snapshot'],
        '-monitor', 'unix:' + monitor_path + ',server,nowait',
        '-serial', 'unix:' + serial_path + ',server,nowait',
        '-vnc', ':9']

progress("Running qemu with args:")
print project['qemu'], " ".join(qemu_args)
print

try:
    os.mkfifo(monitor_path)
    os.mkfifo(serial_path)
    qemu = spawn(project['qemu'], qemu_args)
    time.sleep(1)
except OSError, msg:
    cleanup(msg)
    raise

try:
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

    progress("Beginning recording queries...")
    run_monitor("begin_record queries")

    progress("Running command inside guest...")
    run_console(project['command'])

    progress("Ending recording...")
    run_monitor("end_record")

except socket.error, msg:
    cleanup(msg)
    raise

cleanup()
