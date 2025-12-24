#!/usr/bin/env python3

import json
import os
import shutil
import sys


def process_compile_commands(source_path: str) -> list[dict]:
    """"
    Remove duplicate entries from compile_commands.json and rewrite while
    preserving the original, if necessary.  This prevents the clang tool from
    processing the same files multiple times causing redundant queries and other
    problems.  Not currently clear that this won't introduce other problems
    though...
    """
    c_files = []
    modification_needed = False
    path_string = os.path.join(source_path, 'compile_commands.json')
    with open(path_string, 'r') as jsonFile:
        compile_commands = json.load(jsonFile)

    new_compile_commands = compile_commands[:]
    for i in compile_commands:
        if 'Werror' in i['command']:
            modification_needed = True
            new_compile_commands.remove(i)
            i['command'] = i['command'].replace('-Werror ', '')
            new_compile_commands.append(i)
        file = os.path.realpath(os.path.join(i['directory'], i['file']))
        if file in c_files:
            modification_needed = True
            new_compile_commands.remove(i)
        else:
            c_files.append(file)

    if modification_needed:
        shutil.copyfile(path_string,
                        os.path.join(source_path, 'compile_commands_original.json'))
        with open(path_string, 'w') as jsonFile:
            json.dump(new_compile_commands, jsonFile, indent=4)

    return new_compile_commands


def main():
    if len(sys.argv) < 2:
        print('Usage: ./get_c_files.py <src dir>')
        sys.exit(1)
    process_compile_commands(sys.argv[1])


if __name__ == '__main__':
    main()

