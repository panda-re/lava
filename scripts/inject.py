#!/usr/bin/python

import argparse
import atexit
import json
import lockfile
import os
import signal
import sys
import time

from os.path import join

from lava import LavaDatabase, Run, inject_bugs, LavaPaths, validate_bugs

start_time = time.time()

debugging = False

# get list of bugs either from cmd line or db
def get_bug_list(args, db):
    update_db = False
    print "Picking bugs to inject."
    sys.stdout.flush()

    bug_list = []
    if args.bugid != -1:
        bug_id = int(args.bugid)
        bug_list.append(bug_id)
    elif args.randomize:
        print "Remaining to inj:", db.uninjected().count()
        print "Using strategy: random"
        bug = db.next_bug_random(False)
        bug_list.append(bug.id)
        update_db = True
    elif args.buglist:
        bug_list = eval(args.buglist)
        update_db = False
    elif args.many:
        num_bugs_to_inject = int(args.many)
        print "Selecting %d bugs for injection" % num_bugs_to_inject
        assert db.uninjected_random(False).count() >= num_bugs_to_inject
        bugs_to_inject = db.uninjected_random(False)[:num_bugs_to_inject]
        bug_list = [b.id for b in bugs_to_inject]
        update_db = True
    else: assert False

    return update_db, bug_list


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

    if not args.noLock:
        atexit.register(bugs_lock.release)
        for sig in [signal.SIGINT, signal.SIGTERM]:
            signal.signal(sig, lambda s, f: sys.exit(0))

    print "Using dir", bugs_parent
    lp.set_bugs_parent(bugs_parent)
    return bugs_parent

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
    parser.add_argument('-nl', '--noLock', action="store_true", default=False,
            help = ('No need to take lock on bugs dir'))
    parser.add_argument('-c', '--checkStacktrace', action="store_true", default=False,
            help = ('When validating a bug, make sure it manifests at same line as lava-inserted trigger'))
    parser.add_argument('-d', '--arg_dataflow', action="store_true", default=False,
            help = ('Inject bugs using function args instead of globals'))
    parser.add_argument('-e', '--exitCode', action="store", default=0, type=int,
            help = ('Expected exit code when program exits without crashing. Default 0'))

    args = parser.parse_args()
    global project
    project = json.load(args.project)
    project_file = args.project.name

    # Set various paths
    lp = LavaPaths(project)

    db = LavaDatabase(project)

    try:
        os.makedirs(lp.bugs_top_dir)
    except Exception: pass

    # this is where buggy source code will be
    bugs_parent = get_bugs_parent(lp)

    # obtain list of bugs to inject based on cmd-line args and consulting db
    (update_db, bug_list) = get_bug_list(args, db)

    # add all those bugs to the source code and check that it compiles
    (build, input_files) = inject_bugs(bug_list, db, lp, project_file,
                                       project, args, update_db)
    try:
        # determine which of those bugs actually cause a seg fault
        real_bug_list = validate_bugs(bug_list, db, lp, project, input_files, build,
                                      args, update_db)

        print "real bugs:", real_bug_list

    except Exception as e:
        print "TESTING FAIL"
        if update_db:
            db.session.add(Run(build=build, fuzzed=None, exitcode=-22,
                               output=str(e), success=False))
            db.session.commit()
        raise

    print "inject complete %.2f seconds" % (time.time() - start_time)
