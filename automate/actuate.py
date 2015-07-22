import os
import socket
import sys
import tempfile
import subprocess32
import shutil
import time
import pipes
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

if len(sys.argv) < 6:
    print >>sys.stderr, "Usage: python actuate.py qemu qcow snapshot CD command"
    sys.exit(1)

tempdir = tempfile.mkdtemp()

monitor_path = os.path.join(tempdir, 'monitor')
serial_path = os.path.join(tempdir, 'serial')
qemu_args = [sys.argv[2], '-loadvm', sys.argv[3],
        '-monitor', 'unix:' + monitor_path + ',server,nowait',
        '-serial', 'unix:' + serial_path + ',server,nowait',
        '-vnc', ':9']

progress("Running qemu with args:")
print qemu_args
print

try:
    os.mkfifo(monitor_path)
    os.mkfifo(serial_path)
    qemu = spawn(sys.argv[1], qemu_args)
    time.sleep(1)
except OSError, msg:
    cleanup(msg)
    raise

try:
    monitor = spawn("socat", ["stdin", "unix-connect:" + monitor_path])
    console = spawn("socat", ["stdin", "unix-connect:" + serial_path])

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
    run_monitor("change ide1-cd0 {}".format(sys.argv[4]))
    run_console("mkdir -p /mnt/cdrom")
    run_console("umount /mnt/cdrom")
    run_console("mount /dev/cdrom /mnt/cdrom")

    progress("Beginning recording queries...")
    run_monitor("begin_record queries")

    progress("Running command inside guest...")
    run_console(" ".join(map(pipes.quote, sys.argv[5:])))

    progress("Ending recording...")
    run_monitor("end_record")

except socket.error, msg:
    cleanup(msg)
    raise

cleanup()
