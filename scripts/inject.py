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
    validate_bug, run_modified_program

start_time = time.time()

project = None
# this is how much code we add to top of any file with main fn in it
NUM_LINES_MAIN_INSTR = 5
debugging = True



# here's how to run the built program

def filter_printable(text):
    return ''.join([ '.' if c not in string.printable else c for c in text])


def check_bug(bugid, jsonfile, runonfuzzedinput):
    cmds = [runonfuzzedinput, "-nl", "-l", "[%d]" % bugid, "-s", jsonfile]
    print " ".join(cmds)
    p = subprocess32.Popen(cmds, stdout=subprocess32.PIPE, stderr=subprocess32.PIPE)
    (outp,errs) = p.communicate()


#    outp = subprocess32.check_output([runonfuzzedinput, "-l", "[%d]" % bugid, "-s", jsonfile])
    for line in outp.split("\n"):
        foo = re.search("DIVERGENCE", line)
        if foo:
            # this means there was a crash but its not on the line we expected
            print "divergence"
            return False
        foo = re.search("False", line)
        if foo:
            # this means there wasnt even a crash
            print "doesnt crash"
            return False
    return True


def get_bug_list(args, db):
    update_db = False
    print "Picking bugs to inject."
    sys.stdout.flush()
    # pick bugs based on args
    bugs_to_inject = []
    if args.bugid != -1:
        bug_id = int(args.bugid)
        score = 0
        bugs_to_inject.append(db.session.query(Bug).filter_by(id=bug_id).one())
    elif args.randomize:
        print "Remaining to inj:", db.uninjected().count()
        print "Using strategy: random"
#        (bug_id, dua_id, atp_id, inj) = next_bug_random(project, True)
        bugs_to_inject.append(db.next_bug_random(False))
        update_db = True
    elif args.buglist:
        buglist = eval(args.buglist)
        bugs_to_inject = db.session.query(Bug).filter(Bug.id.in_(buglist)).all()
        update_db = False
    elif args.many:
        num_bugs_to_inject = int(args.many)
        if args.corpus:
#            bugs_to_inject = db.competition_bugs_and_non_bugs(num_bugs_to_inject)
            bugs_to_inject.append(db.session.query(Bug).filter_by(id=355891).one())
        else:
            print "Injecting %d bugs" % num_bugs_to_inject
            assert db.uninjected_random(False).count() >= num_bugs_to_inject
            bugs_to_inject.extend(db.uninjected_random(False)[:num_bugs_to_inject])
        update_db = True
    else: assert False

    bug_list = [b.id for b in bugs_to_inject]
 
    return (update_db, bugs_to_inject, bug_list)


# choose directory into which we are going
# to put buggy source. locking etc is so that
# two instances of inject.py can run at same time
# and they use different directories
def get_bugs_parent(lp):    
    bugs_parent = ""
    candidate = 0
    bugs_lock = None
    print "Getting locked bugs directory..."
    sys.stdout.flush()

    while bugs_parent == "":
        candidate_path = join(lp.bugs_top_dir, str(candidate))
        if args.noLock:
            # just use 0 always
            bugs_parent = join(candidate_path)
        else:
            lock = lockfile.LockFile(candidate_path)
            try:
                lock.acquire(timeout=-1)
                bugs_parent = join(candidate_path)
                bugs_lock = lock
            except lockfile.AlreadyLocked:
                candidate += 1

    if (not args.noLock):
        atexit.register(bugs_lock.release)
        for sig in [signal.SIGINT, signal.SIGTERM]:
            signal.signal(sig, lambda s, f: sys.exit(0))

    print "Using dir", bugs_parent
    return bugs_parent


def get_atp_line(bug, bugs_build):
    print bug
    print bugs_build
    print bug.atp.loc_filename
    with open(join(bugs_build, bug.atp.loc_filename), "r") as f:
        atp_iter = (line_num for line_num, line in enumerate(f) if
                    "lava_get({})".format(bug.id) in line)
        try:
            line_num = atp_iter.next() + 1
            return line_num
        except StopIteration:
            print "lava_get({}) was not in {}".format(bug.id, bug.atp.loc_filename)
            raise

if __name__ == "__main__":
    update_db = False
    parser = argparse.ArgumentParser(description='Inject and test LAVA bugs.')
    parser.add_argument('project', type=argparse.FileType('r'),
            help = 'JSON project file')
    parser.add_argument('-b', '--bugid', action="store", default=-1,
            help = 'Bug id (otherwise, highest scored will be chosen)')
    parser.add_argument('-r', '--randomize', action='store_true', default = False,
            help = 'Choose the next bug randomly rather than by score')
    parser.add_argument('-m', '--many', action="store", default=-1,
            help = 'Inject this many bugs (chosen randomly)')
    parser.add_argument('-l', '--buglist', action="store", default=False,
            help = 'Inject this list of bugs')
    parser.add_argument('-k', '--knobTrigger', metavar='int', type=int, action="store", default=-1,
            help = 'specify a knob trigger style bug, eg -k [sizeof knob offset]')
    parser.add_argument('-s', '--skipInject', action="store", default=False,
            help = 'skip the inject phase and just run the bugged binary on fuzzed inputs')

    parser.add_argument('-c', dest='corpus', action='store_true',
            help = 'package up bugs as a competition corpus')

    parser.add_argument('-nl', '--noLock', action="store_true", default=False,
            help = ('No need to take lock on bugs dir'))

    args = parser.parse_args()
    project = json.load(args.project)
    project_file = args.project.name

    # Set various paths
    lp = LavaPaths(project)

    # Set up our globals now that we have a project
    db = LavaDatabase(project)

    timeout = project.get('timeout', 5)

#    # only makes sense to try to package a corpus if we are injecting several bugs.
#    if args.corpus:
#        assert (args.many)
#        corpus_dir = join(lp.top_dir, "corpus")

    try:
        os.makedirs(lp.bugs_top_dir)
    except Exception: pass

    bugs_parent = get_bugs_parent(lp)
    lp.set_bugs_parent(bugs_parent)

    (update_db, bugs_to_inject, bug_list) = get_bug_list(args, db)

    (build,input_files) = inject_bugs(db, lp, project_file, project, bug_list, \
                                          args.knobTrigger, update_db)

    try:
        # build succeeded -- testing
        print "------------\n"
        # first, try the original file
        print "TESTING -- ORIG INPUT"
        for input_file in input_files:
            unfuzzed_input = join(lp.top_dir, 'inputs', basename(input_file))
            (rv, outp) = run_modified_program(project, lp.bugs_install, \
                                                  unfuzzed_input, timeout)
            if rv != 0:
                print "***** buggy program fails on original input!"
                assert False
            else:
                print "buggy program succeeds on original input", input_file
            print "retval = %d" % rv
            print "output:"
            lines = outp[0] + " ; " + outp[1]
            if update_db:
                db.session.add(Run(build=build, fuzzed=None, exitcode=rv,
                                output='', success=True))
        print "SUCCESS\n"

        # second, try each of the fuzzed inputs and validate
        print "TESTING -- FUZZED INPUTS"
        real_bugs = []
        fuzzed_inputs = []
        for bug_index, bug in enumerate(bugs_to_inject):
            print ("testing with fuzzed input for {} of {} potential.  ".format(
                    bug_index + 1, len(bugs_to_inject)))
            fuzzed_input = validate_bug(db, lp, project, bug, bug_index, build, \
                                            args.knobTrigger, update_db)
            if not (fuzzed_input is None):
                real_bugs.append(bug.id)
                fuzzed_inputs.append(fuzzed_input)
            print ("{} real. bug {}".format(len(real_bugs), bug.id))
            print
        f = float(len(real_bugs)) / len(bugs_to_inject)
        print u"yield {:.2f} ({} out of {}) real bugs (95% CI +/- {:.2f}) ".format(
            f, len(real_bugs), len(bugs_to_inject),
            1.96 * sqrt(f * (1 - f) / len(bugs_to_inject))
        )
        print "TESTING COMPLETE"
        if len(bugs_to_inject) > 1:
            print "list of real validated bugs:", real_bugs

        if update_db: db.session.commit()
        # NB: at the end of testing, the fuzzed input is still in place
        # if you want to try it

        if 1==0 and args.corpus:
            # package up a corpus
            subprocess32.check_call(["mkdir", "-p", corpus_dir])
            print "created corpus dir " + corpus_dir + "\n"
            # original bugs src dir
            bd = join(bugs_parent, source_root)
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

    except Exception as e:
        print "TESTING FAIL"
        if update_db:
            db.session.add(Run(build=build, fuzzed=None, exitcode=-22,
                               output=str(e), success=False))
            db.session.commit()
        raise

    print "inject complete %.2f seconds" % (time.time() - start_time)
