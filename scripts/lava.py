#!/usr/bin/env python


'''
    This is the start of a global LAVA script that will automate all aspects of
    transformation (instrumentation and bug insertion), and data gathering
    (through PANDA record/replay of instrumented source/binaries).

    To keep it simple, there are only a few arguments.  One of them is a path to
    a simple JSON dictionary that will store the arguments, as the list will
    probably grow a bunch.  Current arguments are the path to lavaTool, the
    source directory being transformed, and the path to LAVA data (.duas, .aps,
    .bugs).  Here is an example:

    lavaConfig.json
    ===============
    {
        "toolPath" : "/home/user/git/lava/src_clang/build/",
        "sourcePath" : "/nas/user/lava/file",
        "lavaDataPath" : "/path/to/lava/data"
    }
    ===============

    Some example insertion examples from Amy:
    build/lavaTool -action=inject -mode=atp inputs/test_input.c -info=20,memcpy,dead_data1,4 --
    build/lavaTool -p=/home/amy/src/binutils-2.22 -action=inject -mode=dua $source -info=1906,abfd,[112,113,114,115,],dead_data1
'''


import argparse
import json
import subprocess
import sys


def parseConfigFile(configFilePath):
    with open(configFilePath) as config:
        return json.load(config)


def lavaInsertTaintQueries(config):
    ''' Pull stuff in from, and generalize fileLavaScript.sh '''
    print 'Inserting taint queries...'


def lavaInsertBugs(config):
    print 'Inserting bugs...'
    spArgs = [config['toolPath'] + 'lavaTool', '-action=inject']
    proc = subprocess.Popen(spArgs)
    proc.wait()
    if proc.returncode != 0:
        print 'Error returned from subprocess ' + spArgs[0] + '...'
        sys.exit(1)


def getPandaRecording():
    '''Restore to a booted snapshot, mount an ISO with transformed
    source/compiled binaries, begin recording, execute a parameterized command,
    end recording
    '''
    return None


def runPandaReplay():
    '''Run a replay of an instrumented binary to get LAVA information
    '''
    return None


def main():
    ap = argparse.ArgumentParser(description='LAVA automation script')
    ap.add_argument('--action', required='True', choices=['insert', 'query'],
        help=('LAVA action to execute'))
    ap.add_argument('--config', required='True',
        help=('Path to JSON configuration file.  See comments for an example.'))
    args = ap.parse_args()

    config = parseConfigFile(args.config)
    print 'Source path:' + config['sourcePath']

    if args.action == 'insert':
        lavaInsertBugs(config)
    elif args.action == 'query':
        lavaInsertTaintQueries(config)


if __name__ == '__main__':
    main()

