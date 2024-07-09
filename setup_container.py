#!/usr/bin/python
import os
import sys
import shlex
import subprocess
from colorama import Fore
from colorama import Style


LAVA_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))
os.chdir(LAVA_DIR)


def progress(msg):
    print('')
# PANDA_UBUNTU = "https://goo.gl/GNMNmJ"
    print(Fore.GREEN + '[setup.py] ' + Fore.RESET + Style.BRIGHT
          + msg + Style.RESET_ALL)

def error(msg):
    print('')
    print(Fore.RED + '[setup.py] ' + Fore.RESET + Style.BRIGHT
          + msg + Style.RESET_ALL)
    sys.exit(1)


def cmd_to_list(cmd):
    cmd_args = shlex.split(cmd) if isinstance(cmd, str) else cmd
    cmd = subprocess.list2cmdline(cmd_args)
    return cmd, cmd_args

def run(cmd):
    cmd, cmd_args = cmd_to_list(cmd)
    try:
        progress("Running [{}] . . . ".format(cmd))
        subprocess.check_call(cmd_args)
    except subprocess.CalledProcessError:
        error("[{}] cmd did not execute properly.".format(cmd))
        raise

if __name__ == '__main__':
    # Compile btrace
    compile_cmd = ['cd', os.path.join(LAVA_DIR, 'tools', 'btrace'),
                   '&&', 'bash', 'compile.sh']
    run(['bash', '-c', subprocess.list2cmdline(compile_cmd)])
    # Compile lavaTool inside the docker container.
    progress("Creating $LAVA_DIR/tools/lavaTool/config.mak")

    run(['rm', '-rf', os.path.join(LAVA_DIR, 'tools/build')])
    run(['mkdir', '-p', os.path.join(LAVA_DIR, 'tools/build')])
    run(['mkdir', '-p', os.path.join(LAVA_DIR, 'tools/install')])

    run(['cmake', '-B{}'.format(os.path.join(LAVA_DIR, 'tools/build')),
                '-H{}'.format(os.path.join(LAVA_DIR, 'tools')),
                '-DCMAKE_INSTALL_PREFIX={}'.format(os.path.join(LAVA_DIR,
                                                        'tools/install'))])
    run(['make','--no-print-directory','-j4', 'install', '-C',
                os.path.join(LAVA_DIR, 'tools/build/lavaTool')])

    # -----------Beginning .mak file stuff -------------------
    # I think this would be useful, but i'm seperating it out
    # in case anyone thinks it's a bad idea
    # the idea is that if someone wants llvm and panda installed in certain
    # locations, they can make their lava.mak ahead of time
    # then setup.py will parse it and configure the environmet to those specs
    os.chdir(LAVA_DIR)

    # ----------------End .mak file stuff ---------------------
    progress("Making each component of lava, fbi and lavaTool")
    progress("Compiling fbi")

    os.chdir(os.path.join(LAVA_DIR, "tools/build"))
    run("make --no-print-directory -j4 -C fbi install")
    os.chdir(LAVA_DIR)
