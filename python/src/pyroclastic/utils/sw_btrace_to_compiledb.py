#!/usr/bin/env python3

import json
import os

kDrivers = [
    "cc", "c++", "cc1",
    "gcc", "g++",
    "clang", "clang++",
]

kSourceExtensions = [".c", ".cc", ".cpp", ".cxx", ".c++"]
kAssemblyExtensions = [".s", ".S"]


class Command(object):
    def __init__(self, cwd, parent, argv, line):
        assert isinstance(cwd, str)
        assert parent is None or isinstance(parent, Command)
        self.cwd = cwd
        self.parent = parent
        self.argv = argv
        self.line = line
        self.isCompilerDriver = (os.path.basename(self.argv[0]).split('-', 1)[0] in kDrivers)


def read_pid_list(pidlist: list[int]):
    """
    The pidlist field of a record is a flattened list of
    (pidDelta, startTimeDelta) pairs, where each successive pair is the delta
    from the previous pair to the new pair.  Return a list of
    (pid, startTime) pairs.
    """
    assert len(pidlist) % 2 == 0 and len(pidlist) >= 2
    ret = [(pidlist[0], pidlist[1])]
    for i in range(2, len(pidlist), 2):
        ret.append((ret[-1][0] + pidlist[i], ret[-1][1] + pidlist[i + 1]))
    return ret


def read_file(path: str):
    command_list = []
    command_id_to_command = {}
    line = 0

    try:
        with open(path) as fp:
            for recordString in fp:
                line += 1
                record = json.loads(recordString)
                parent = None
                process_list = read_pid_list(record["pidlist"])
                for procID in process_list[:-1]:
                    parent = command_id_to_command.get(procID, parent)
                command = Command(record["cwd"], parent, record["argv"], line)
                command_list.append(command)
                command_id_to_command[process_list[-1]] = command
        return command_list
    except FileNotFoundError as e:
        print(f"Error: Could not find btrace log file at {os.getcwd()}")
        raise e


def ends_with_one_of(text, extensions):
    for extension in extensions:
        if text.endswith(extension):
            return True
    return False


def join_command_line(argv):
    # TODO: Actually get this right -- quotes,spaces,escapes,newlines
    # TODO: Review what Clang's libtooling and CMake do, especially on Windows.
    return " ".join(argv)


def is_child_of_compiler_driver(command):
    parent = command.parent
    while parent is not None:
        if parent.isCompilerDriver:
            return True
        parent = parent.parent
    return False


def compile_mode(argv):
    """Return the last compile-mode argument in a command line."""
    k_modes = ["-c", "-S", "-E"]
    mode = None
    for arg in argv:
        if arg in k_modes:
            mode = arg
    return mode


def extract_source_file(command, clang_include_path):
    """Attempt to extract a compile step from a driver command line."""

    # Accommodate ccache.  With ccache, a parent process will be exec'ed using
    # a program name like "g++", but the g++ is really a symlink to a ccache
    # program.  ccache invokes children g++ subprocesses, but with altered
    # arguments.  e.g. Instead of:
    #    g++ -c file.cc -o file.o
    # we get something like this:
    #    g++ -E file.cc   [output redirected to a tmp file]
    #    g++ -c $HOME/.ccache/tmp/tmp.i -o $HOME/.ccache/tmp.o.1234
    # The translation unit compilation is now split into two, and the output
    # filename is lost.  The approach taken here is to ignore any subprocesses
    # of a compiler driver invocation.

    # TODO: this misses gcc foo.c -o foo; it only catches gcc -c foo.c -o foo. Can't we default to assuming it's -c?

    if not command.isCompilerDriver or is_child_of_compiler_driver(command) or \
            compile_mode(command.argv) != "-c":
        return None

    args = command.argv[1:]
    input_file = None

    while len(args) > 0:
        arg = args.pop(0)
        if arg[0] == "-":
            pass
        elif ends_with_one_of(arg, kSourceExtensions):
            assert input_file is None
            input_file = arg
        elif ends_with_one_of(arg, kAssemblyExtensions):
            return None

    if input_file is None:
        return None
    if not os.path.isdir(command.cwd):
        print(f'warning: line {command.line}: directory {command.cwd} does not exist, skipping')
        return None
    absolute_input_file = os.path.join(command.cwd, input_file)
    if not os.path.isfile(absolute_input_file):
        print(f'warning: line {command.line}: input file {absolute_input_file} does not exist, skipping')
        return None

    cmd = join_command_line(command.argv) + " -I" + clang_include_path
    output = {"directory": command.cwd, "command": cmd, "file": input_file}
    return output


def main(include_clang_path: str):
    """
    Parse the btrace.log file and generate compile_commands.json
    This JSON file has the following fields:
    directory: The working directory where the compile command was run
    command: The full compile command
    file: The source file being compiled
    Args:
        include_clang_path: The path to Clang system headers to include
    """
    commands = read_file("btrace.log")

    results = []
    for x in commands:
        source_file = extract_source_file(x, include_clang_path)
        if source_file is not None:
            results.append(source_file)

    if not len(results):
        raise RuntimeError("No source files found by sw-btrace-to-compilerdb")

    with open("compile_commands.json", "w") as f:
        json.dump(results, f, indent=4)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Need to specify include path.")
        print(f"Usage: {sys.argv[0]} <clang_system_headers>")
        sys.exit(1)
    include_path = sys.argv[1]
    main(include_path)
