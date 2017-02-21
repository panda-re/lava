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
from os.path import basename, dirname, join, abspath

from lava import LavaDatabase, Bug, Build, DuaBytes, Run, \
    run_cmd, run_cmd_notimeout, mutfile, inject_bugs, LavaPaths, \
    validate_bugs, run_modified_program


#def check_bug(bugid, jsonfile, runonfuzzedinput):
#    cmds = [runonfuzzedinput, "-nl", "-l", "[%d]" % bugid, "-s", jsonfile]
#    print " ".join(cmds)
#    p = subprocess32.Popen(cmds, stdout=subprocess32.PIPE, stderr=subprocess32.PIPE)
#    (outp,errs) = p.communicate()
#    for line in outp.split("\n"):
#        foo = re.search("DIVERGENCE", line)
#        if foo:
#            # this means there was a crash but its not on the line we expected
#            print "divergence"
#            return False
#        foo = re.search("False", line)
#        if foo:
#            # this means there wasnt even a crash
#            print "doesnt crash"
#            return False
#    return True

#def get_atp_line(bug, bugs_build):
#    print bug
#    print bugs_build
#    print bug.atp.loc_filename
#    with open(join(bugs_build, bug.atp.loc_filename), "r") as f:
#        atp_iter = (line_num for line_num, line in enumerate(f) if
#                    "lava_get({})".format(bug.id) in line)
#        try:
#            line_num = atp_iter.next() + 1
#            return line_num
#        except StopIteration:
#            print "lava_get({}) was not in {}".format(bug.id, bug.atp.loc_filename)
#            raise



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
    parser.add_argument('-l', '--buglist', action="store", default=False,
            help = 'Inject this list of bugs')
    parser.add_argument('-d', '--bugdir', action="store", default=False,
            help = 'directory for corpus')
    
    args = parser.parse_args()
    project = json.load(args.project)
    project_file = args.project.name

    # Set various paths
    lp = LavaPaths(project)

    db = LavaDatabase(project)

    try:
        os.makedirs(args.bugdir)
    except Exception: pass

    bugs_parent = args.bugdir
    lp.set_bugs_parent(args.bugdir)

    shutil.rmtree(args.bugdir)
 
    print (str(lp))
    

    if False:
        if args.buglist:
            bug_list = eval(args.buglist)
        elif args.many:
            bug_list = competition_bugs_and_non_bugs(int(args.many), db)

    bug_list = [475187L, 135879L, 442734L, 555117L, 85147L, 55982L, 232105L, 353204L, 423770L, 278537L]

    knobTrigger = -1

    # add all those bugs to the source code and check that it compiles
    (build, input_files) = inject_bugs(bug_list, bugs_parent, db, lp, project_file, \
                                          project, knobTrigger, False)

    # determine which of those bugs actually cause a seg fault
    real_bug_list = validate_bugs(bug_list, db, lp, project, input_files, build, \
                                      knobTrigger, False)

    if len(real_bug_list) == 0:
        print "Oops we don't have any real bugs?  Try again"
        sys.exit(0)

    # re-build just with the real bugs
    (build,input_files) = inject_bugs(real_bug_list, bugs_parent + "_real", db, lp, project_file, \
                                          project, -1, False)

    # determine which of those bugs actually cause a seg fault
    real2_bug_list = validate_bugs(real_bug_list, db, lp, project, input_files, build, \
                                       knobTrigger, False)
    
    corpus_dir = lp.bugs_top_dir + "/corpora"
    subprocess32.check_call(["mkdir", "-p", corpus_dir])

    print "created corpus dir " + corpus_dir + "\n"
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
    # copy over the inputs as well
    predictions = {}
    for bug_index, bug in enumerate(bugs_to_inject):
        if not (bug.id in real_bugs):
            continue
        print "validating bug %d" % bug.id
        # make sure this bug actually works and
        # triggers at the attack point as expected
        if (check_bug(bug.id, sys.argv[-1], project['lava'] + "/scripts/run-on-fuzzed-input.py")):
            print "  -- works and triggers in the right place"
            prediction = "{}:{}".format(basename(bug.atp.loc_filename),
                                        get_atp_line(bug, bugs_build))
            print prediction
            if prediction in predictions:
                print "... but we already have a bug for that attack point"
            else:
                fuzzed_input = "{}-fuzzed-{}{}".format(pref, bug.id, suff)
                (dc, fi) = os.path.split(fuzzed_input)
                shutil.copy(fuzzed_input, inputsdir)
                predictions[prediction] = fi
        else:
            print "  -- either doesnt work or triggers in wrong place"
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
