#!/usr/bin/env python3

import json
import os
import shutil
import sys


def processCompileCommands(srcPath):
    '''
    Remove duplicate entries from compile_commands.json and rewrite while
    preserving the original, if necessary.  This prevents the clang tool from
    processing the same files multiple times causing redundant queries and other
    problems.  Not currently clear that this won't introduce other problems
    though...
    '''
    cFiles = []
    modificationNeeded = False
    pathStr = os.path.join(srcPath, 'compile_commands.json')
    with open(pathStr, 'r') as jsonFile:
        compileCommands = json.load(jsonFile)

    newCompileCommands = compileCommands[:]
    for i in compileCommands:
        if 'Werror' in i['command']:
            modificationNeeded = True
            newCompileCommands.remove(i)
            i['command'] = i['command'].replace('-Werror ', '')
            newCompileCommands.append(i)
        f = os.path.realpath(os.path.join(i['directory'], i['file']))
        if f in cFiles:
            modificationNeeded = True
            newCompileCommands.remove(i)
        else:
            cFiles.append(f)

    if modificationNeeded:
        shutil.copyfile(pathStr,
            os.path.join(srcPath, 'compile_commands_original.json'))
        with open(pathStr, 'w') as jsonFile:
            json.dump(newCompileCommands, jsonFile, indent=4)

    return newCompileCommands


def getCFiles(compileCommands):
    for d in compileCommands:
        print(os.path.join(d['directory'], d['file']))


def main():
    if (len(sys.argv) < 2):
        print('Usage: ./get_c_files.py <src dir>')
        sys.exit(1)
    newCompileCommands = processCompileCommands(sys.argv[1])
    getCFiles(newCompileCommands)


if __name__ == '__main__':
    main()

