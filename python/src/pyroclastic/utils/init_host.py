#!/usr/bin/env python3

import argparse
import json
import sys
import os
from colorama import Fore, Style
from pandare.qcows_internal import Qcows
from .vars import get_valid_architectures


def progress(msg):
    print('')
    print(Fore.GREEN + '[init-host.py] ' + Fore.RESET +
          Style.BRIGHT + msg + Style.RESET_ALL)


def main():
    # Download PyPanda QCows and set up a new home for all lava-configs in ~/.lava/
    Qcows.get_qcow('x86_64')
    lava_config_directory = os.path.join(os.path.expanduser("~"), ".lava")
    os.makedirs(lava_config_directory, exist_ok=True)

    parser = argparse.ArgumentParser(description='Arguments to modify host.json for LAVA depending on the environment')
    parser.add_argument('--docker', '-d', dest='docker', action='store_true',
                        help='If set, have host.json assume LAVA will be run from Docker environment')
    parser.add_argument('--container', '-c', dest='container', default='lava64',
                        help='Set the name of the Docker container with LAVA installed. (default: lava64)')
    parser.add_argument('--qemu', '-q', dest='qemu', default='x86_64',
                        choices=get_valid_architectures(),
                        help='Set the name of the Docker container with LAVA installed. (default: lava64)')
    parser.add_argument('--action', '-a', dest='action', action='store_true',
                        help='Use this flag only for the GitHub Actions environment.')
    parser.add_argument('--force', '-f', dest='force', action='store_true',
                        help='Use this flag to force over-write of existing host.json.')
    args = parser.parse_args()

    progress(f"Using LAVA config directory at {os.getcwd()}")

    # Check if 'target_bins' and 'target_configs' exist. If not, stop and warn user.
    # Create a 'target_injections' directory.
    if not os.path.isdir(os.path.join(os.getcwd(), "target_bins")):
        progress("Error: 'target_bins' directory not found in current working directory. "
                 "Please create it and add target binaries before running 'lava init-host'.")
        return 1
    if not os.path.isdir(os.path.join(os.getcwd(), "target_configs")):
        progress("Error: 'target_configs' directory not found in current working directory. "
                 "Please create it and add target configurations before running 'lava init-host'.")
        return 1
    os.makedirs(os.path.join(os.getcwd(), "target_injections"), exist_ok=True)

    host_json_path = os.path.join(lava_config_directory, "host.json")
    json_configs = {
        "qemu": args.qemu,
        "output_dir": os.path.join(os.getcwd(), "target_injections"),
        "config_dir": os.path.join(os.getcwd(), "target_configs"),
        "tar_dir": os.path.join(os.getcwd(), "target_bins"),
        "db_suffix": "_" + os.environ["USER"],
        "port": 5432,
        "pguser": "postgres",
        "debug": False,
        "llvm": "/usr/lib/llvm-14"
    }

    if args.docker:
        json_configs["buildhost"] = "docker"
        json_configs["host"] = "database"
        json_configs["docker"] = args.container
    else:
        json_configs["buildhost"] = "localhost"
        json_configs["host"] = "localhost"
    # Sometimes GitHub Actions need complete_rr for CI/CD to work
    # Note, please avoid using debug print in CI/CD, this causes issues on replay
    if args.action:
        json_configs["complete_rr"] = True

    if os.path.isfile(host_json_path):
        if args.force:
            progress(f"Over-writing existing host.json at {host_json_path}")
            with open(host_json_path, 'w+') as f:
                f.write(json.dumps(json_configs, indent=4))
        else:
            progress(f"Found existing host.json at {host_json_path}, not over-writing.")
    else:
        progress(f"new host.json created at {host_json_path}")
        with open(host_json_path, 'w+') as f:
            f.write(json.dumps(json_configs, indent=4))

    progress("Successful!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
