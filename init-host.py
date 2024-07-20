#!/usr/bin/env python3

# import argparse
import os
import sys
import json
import shlex
import subprocess

from os.path import join
from os.path import isdir
from os.path import isfile
from os.path import dirname
from os.path import abspath
from os.path import basename
from os.path import expandvars

from colorama import Fore
from colorama import Style

TAR_URL = "ftp://ftp.astron.com/pub/file/file-5.22.tar.gz"
LAVA_DIR = dirname(abspath(sys.argv[0]))


def progress(msg):
    print('')
    print(Fore.GREEN + '[setup.py] ' + Fore.RESET +
          Style.BRIGHT + msg + Style.RESET_ALL)


def error(msg):
    print('')
    print(Fore.RED + '[setup.py] ' + Fore.RESET +
          Style.BRIGHT + msg + Style.RESET_ALL)
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
        error("[{}] cmd did not execute properly.")
        raise


def main():

    # parser = argparse.ArgumentParser(description='Setup LAVA')
    # parser.add_argument('-s', '--skip_docker_build', action='store_true',
    # default = False,
    # help = 'Whether or not to skip building docker image')
    # args = parser.parse_args()
    # IGNORE_DOCKER = args.skip_docker_build
    progress("In LAVA git dir at {}".format(LAVA_DIR))

    # Tars should just be tracked by git now, maybe we can change that later
    TAR_DIR = join(LAVA_DIR, "target_bins")
    if not isdir(TAR_DIR):
        os.mkdir(TAR_DIR)

    # summon tar and qcow files
    if not isfile(join(TAR_DIR, basename(TAR_URL))):
        progress("Downloading {}".format(basename(TAR_URL)))
        os.chdir(TAR_DIR)
        run(["wget", TAR_URL])
        os.chdir(LAVA_DIR)
    else:
        progress("Found existing target_bins/{}".format(basename(TAR_URL)))

    if not isfile(join(LAVA_DIR, "host.json")):
        progress("Building host.json")
        # Build host.json
        json_configs = {}
        json_configs["qemu"] = "panda-system-i386"
        json_configs["qcow_dir"] = LAVA_DIR
        json_configs["output_dir"] = join(LAVA_DIR, "target_injections")
        json_configs["config_dir"] = join(LAVA_DIR, "target_configs")
        json_configs["tar_dir"] = join(LAVA_DIR, "target_bins")
        json_configs["db_suffix"] = "_" + os.environ["USER"]

        # write out json file
        out_json = join(LAVA_DIR, "host.json")

        with open(out_json, 'w') as f:
            f.write(json.dumps(json_configs, indent=4))
    else:
        progress("Found existing host.json")

    progress("Successful!  Now run:\n  $ scripts/lava.sh -ak file")
    return 0


if __name__ == "__main__":
    sys.exit(main())
