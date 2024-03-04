import argparse
import json
import subprocess
from os import system


def process_crash(buf):
    """
    Process a buffer of output from target program
    Identify all LAVALOG lines

    returns list of bugids (ints) seen
    """
    bugs = []

    def get_bug_id(line):
        if len(line.split(":")) > 2:
            return int(line.split(": ")[1].split(": ")[0])
        return None

    for line in buf.split("\n"):
        if line.startswith("LAVALOG:"):
            bugid = get_bug_id(line)
            if bugid:
                bugs.append(bugid)

    return bugs


def main(args):
    # Copy built_dir and input_file into /shared 
    # Run sandbox with /shared
    # run program in sandbox
    # parse output, return bug ID

    project = json.loads(args.project.read())

    command = project["command"].format(install_dir=args.install_dir, input_file=args.input)

    p = subprocess.Popen(command, cwd=None, env=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    timeout = 10
    try:
        stdout, stderr = p.communicate(timeout=timeout)  # returns tuple (stdout, stderr)
    except subprocess.TimeoutExpired:
        print("Killing process due to timeout expiration.")
        p.terminate()

    if stderr:
        print("Warning: Errors encountered running {}:\n\t{}".format(command, stderr))

    print("Exited with {}".format(p.returncode))

    bugs = process_crash(stdout)

    if len(bugs) > 2:
        raise RuntimeError("Multiple bugs triggered!? {}".format(bugs))
    elif len(bugs) == 1:
        bug = bugs[0]
    else:
        bug = None

    if p.returncode != 0 and bug:
        print("Found bug {}".format(bug))
    else:
        print("No bugs found")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Given an input and a lava-fied binary with LAVA_LOGGING on, determine what bug (if any) is triggered by the input')
    parser.add_argument('project', type=argparse.FileType('r'),
                        help='JSON project file')
    parser.add_argument('install_dir',
                        help="Install dir")
    parser.add_argument('input',
                        help="File to input into binary")

    args = parser.parse_args()
    main(args)
