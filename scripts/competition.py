#!/usr/bin/python

import argparse
import atexit
import datetime
import json
import lockfile
import os
import pipes
import re
import shlex
import shutil
import signal
import string
import subprocess32
import sys
import time

from math import sqrt
from os.path import basename, dirname, join, abspath, exists

from lava import LavaDatabase, Bug, Build, DuaBytes, Run, \
    run_cmd, run_cmd_notimeout, mutfile, inject_bugs, LavaPaths, \
    validate_bugs, run_modified_program, unfuzzed_input_for_bug, \
    fuzzed_input_for_bug, get_trigger_line

# collect num bugs AND num non-bugs
# with some hairy constraints
# we need no two bugs or non-bugs to have same file/line attack point
# that allows us to easily evaluate systems which say there is a bug at file/line.
# further, we require that no two bugs or non-bugs have same file/line dua
# because otherwise the db might give us all the same dua
def competition_bugs_and_non_bugs(num, db):
    bugs_and_non_bugs = []
    fileline = set()
    def get_bugs_non_bugs(fake, limit):
        items = db.uninjected_random(fake)
        for item in items:
            dfl = (item.trigger_lval.loc_filename, item.trigger_lval.loc_begin_line)
            afl = (item.atp.loc_filename, item.atp.loc_begin_line)
            if (dfl in fileline) or (afl in fileline):
                continue
            if fake:
                print "non-bug", 
            else:
                print "bug    ", 
            print ' dua_fl={} atp_fl={}'.format(str(dfl), str(afl))
            fileline.add(dfl)
            fileline.add(afl)
            bugs_and_non_bugs.append(item)
            if (len(bugs_and_non_bugs) == limit):
                break
    get_bugs_non_bugs(False, num)
    get_bugs_non_bugs(True, 2*num)
    return [b.id for b in bugs_and_non_bugs]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Inject and test LAVA bugs.')
    parser.add_argument('project', type=argparse.FileType('r'),
            help = 'JSON project file')
    parser.add_argument('-m', '--many', action="store", default=-1,
            help = 'Inject this many bugs and this many non-bugs (chosen randomly)')
    parser.add_argument('-n', '--minYield', action="store", default=-1,
            help = 'Require at least this many real bugs')
    parser.add_argument('-l', '--buglist', action="store", default=False,
            help = 'Inject this list of bugs')
    parser.add_argument('-e', '--exitCode', action="store", default=0, type=int,
            help = ('Expected exit code when program exits without crashing. Default 0'))
    
    args = parser.parse_args()
    project = json.load(args.project)
    project_file = args.project.name

    # Set various paths
    lp = LavaPaths(project)

    # Make the bugs top_dir start with competition
    lp.bugs_top_dir = join(lp.top_dir, "competition")
    compdir = join(lp.top_dir, "competition")
    bugdir = join(compdir, "bugs")

    db = LavaDatabase(project)

    if not os.path.exists(bugdir):
        os.makedirs(bugdir)

    bugs_parent = bugdir
    lp.set_bugs_parent(bugdir)

    try:
        shutil.rmtree(bugdir)
    except:
        pass

    args.knobTrigger = -1
    args.checkStacktrace = False
    args.arg_dataflow = False

    while True:

        if True:
            if args.buglist:
                bug_list = eval(args.buglist)
            elif args.many:
                bug_list = competition_bugs_and_non_bugs(int(args.many), db)

#        bug_list = [114L, 138L, 3295L, 3353L, 4635L, 14355L, 21112L, 34878L, 66341L, 72856L, 205102L, 222709L, 222865L, 271819L, 387124L, 388491L, 530292L]
        # add bugs to the source code and check that we can still compile
        (build, input_files) = inject_bugs(bug_list, db, lp, project_file, \
                                              project, args, False)

        # bug is valid if seg fault (or bus error)
        # AND if stack trace indicates bug manifests at trigger line we inserted
        real_bug_list = validate_bugs(bug_list, db, lp, project, input_files, build, \
                                          args, False)

        if len(real_bug_list) < int(args.minYield):
            print "\n\nXXX Yield too low -- %d bugs minimum is required for competition" % int(args.minYield)
            print "Trying again.\n"
        else:
            print "\n\n Yield acceptable"
            break

    # re-build just with the real bugs
    (build,input_files) = inject_bugs(real_bug_list, db, lp, project_file, \
                                          project, args, False)


    corpus_dir = join(compdir, "corpora")
    subprocess32.check_call(["mkdir", "-p", corpus_dir])

    # original bugs src dir
    bd = join(lp.bugs_parent, lp.source_root)
    # directory for this corpus
    corpname = "lava-corpus-" + ((datetime.datetime.now()).strftime("%Y-%m-%d-%H-%M-%S"))
    corpdir = join(corpus_dir,corpname)
    subprocess32.check_call(["mkdir", corpdir])
    # subdir with trigger inputs
    inputsdir = join(corpdir, "inputs")
    subprocess32.check_call(["mkdir", inputsdir])
    # subdir with src -- note we can't create it or copytree will fail!
    srcdir = join(corpdir, "src")
    # copy src
    shutil.copytree(bd, srcdir)

    # TODO: this is broken - get_trigger_line doesn't work
    predictions = {}
    for bug in  db.session.query(Bug).filter(Bug.id.in_(real_bug_list)).all():
        prediction = "{}:{}".format(basename(bug.atp.loc_filename),
                                    get_trigger_line(lp, bug))
#        print "Bug %d: prediction = [%s]" % (bug.id, prediction)
        if not get_trigger_line(lp, bug):
            print("Warning - unknown trigger, skipping")
            continue

        assert not (prediction in predictions)
        unfuzzed_input = unfuzzed_input_for_bug(lp, bug)
        fuzzed_input = fuzzed_input_for_bug(lp, bug)
        (dc, fi) = os.path.split(fuzzed_input)
        shutil.copy(fuzzed_input, inputsdir)
        predictions[prediction] = fi

    print "Answer key:"
    ans = open(join(corpdir, "ans"), "w")
    for prediction in predictions:
        print "ANSWER  [%s] [%s]" % (prediction, predictions[prediction])
        ans.write("%s %s\n" % (prediction, predictions[prediction]))
    ans.close()
    # clean up before tar
    os.chdir(srcdir)
    subprocess32.check_call(["make", "distclean"])
    shutil.rmtree(join(srcdir, ".git"))
    shutil.rmtree(join(srcdir, "lava-install"))
    os.remove(join(srcdir, "compile_commands.json"))
    os.remove(join(srcdir, "btrace.log"))
    tarball = join(srcdir + ".tgz")
    os.chdir(corpdir)
    cmd = "/bin/tar czvf " + tarball + " src"
    subprocess32.check_call(cmd.split())
    print "created corpus tarball " + tarball + "\n";
    build = open(join(corpdir, "build"), "w")
    build.write("%s\n" % project['configure'])
    build.write("%s\n" % project['make'])
    build.close()
