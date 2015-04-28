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
    build/lavaTool -action=inject -mode=atp inputs/test_input.c -info=20,memcpy,dead_data1,4 -- (atp info is currently: line, type, new global name, size)
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
    ''' Pull stuff in from, and generalize fileLavaScript.sh and get_c_files.py '''
    print 'Inserting taint queries...'


def parseAPFile(config):
    ''' Parse the attack points file '''
    attackPoints = []
    with open(config['lavaDataPath'] + '/lava.aps') as apFile:
        for line in apFile:
            ap = line.strip('\n').split(',')
            attackPoints.append(dict([
                ('fileName', ap[0]),
                ('lineNumber', ap[1]),
                ('astNode', ap[2])
            ]))
    return attackPoints


def parseDUAFile(config):
    ''' Parse the DUAs file '''
    return None


def insertAttackPointTransforms(config, attackPoints):
    ''' Call lavaTool with data read from a .aps file '''
    for i, ap in enumerate(attackPoints):
        spArgs = [
            config['toolPath'] + '/lavaTool',
            '-p=' + config['sourcePath'],
            '-action=inject',
            '-mode=atp',
            ('-info=' + ap['lineNumber'] + ',' +
                ap['astNode'] + ',' +
                'dead_data1,4' # placeholder global and size
            ),
            ap['fileName']
        ]
        print 'spArgs: ' + str(spArgs)
        proc = subprocess.Popen(spArgs)
        proc.wait()
        if proc.returncode != 0:
            print ('Error returned from subprocess ' + spArgs[0] +
                ' on file ' + ap['fileName'] + '...')
            sys.exit(1)


def insertDuaTransforms(config, attackPoints):
    ''' Call lavaTool with data read from a .aps file '''
    return None


def lavaInsertBugs(config):
    print 'Inserting bugs...'
    print '\tTransforming attack points in .aps file...\n\n'
    aps = parseAPFile(config)
    insertAttackPointTransforms(config, aps)

    #print '\tTransforming DUAs in .duas file...'
    duas = parseDUAFile(config)
    insertDuaTransforms(config, duas)
    print '\n\nDone inserting bugs.'


def compileSource(config):
    ''' Compile a source project, original or transformed.  Confirm that
    compilation completed without errors.
    '''
    return None


def runProgram(config, crashExpected):
    ''' Run a program with arguments specified in the configuration file.
    Confirm expected behavior of a successful bug (crash), or successful
    transformation (no crash).
    '''
    return None


def getPandaRecording():
    ''' Restore to a booted snapshot, mount an ISO with transformed
    source/compiled binaries, begin recording, execute a parameterized command,
    end recording
    '''
    return None


def runPandaReplay():
    ''' Run a replay of an instrumented binary to get LAVA information '''
    return None


def main():
    ap = argparse.ArgumentParser(description='LAVA automation script')
    ap.add_argument('--action', required='True', choices=['insert', 'query'],
        help=('LAVA action to execute'))
    ap.add_argument('--config', required='True',
        help=('Path to JSON configuration file.  See comments for an example.'))
    args = ap.parse_args()

    config = parseConfigFile(args.config)

    if args.action == 'insert':
        lavaInsertBugs(config)
    elif args.action == 'query':
        lavaInsertTaintQueries(config)


if __name__ == '__main__':
    main()

