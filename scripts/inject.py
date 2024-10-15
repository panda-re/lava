#!/usr/bin/env python3

import argparse
import atexit
import lockfile
import os
import signal
import sys
import time

from os.path import join

from vars import parse_vars
from lava import LavaDatabase, Run, Bug, \
    inject_bugs, LavaPaths, validate_bugs, \
    get_bugs, run_cmd, get_allowed_bugtype_num

start_time = time.time()

debugging = False

version = "2.0.0"


# get list of bugs either from cmd line or db
def get_bug_list(args, db, allowed_bugtypes):
    update_db = False
    print("Picking bugs to inject.")
    sys.stdout.flush()

    bug_list = []
    if args.bugid != -1:
        bug_id = int(args.bugid)
        bug_list.append(bug_id)
    elif args.randomize:
        print("Remaining to inj:", db.uninjected().count())
        print("Using strategy: random")
        bug = db.next_bug_random(False)
        bug_list.append(bug.id)
        update_db = True
    elif args.buglist:
        bug_list = eval(args.buglist)  # TODO
        update_db = False
    elif args.many:
        num_bugs_to_inject = int(args.many)
        huge = db.huge()

        available = "tons" if huge else db.uninjected().count()  # Only count if not huge
        print("Selecting %d bugs for injection of %s available" % (num_bugs_to_inject, str(available)))

        if not huge:
            assert available >= num_bugs_to_inject

        if args.balancebugtype:
            bugs_to_inject = db.uninjected_random_balance(False, num_bugs_to_inject, allowed_bugtypes)
        else:
            bugs_to_inject = db.uninjected_random_limit(allowed_bugtypes=allowed_bugtypes, count=num_bugs_to_inject)

        bug_list = [b.id for b in bugs_to_inject]
        print("%d is size of bug_list" % (len(bug_list)))
        update_db = True
    else:
        assert False
    return update_db, bug_list


# choose directory into which we are going
# to put buggy source. locking etc is so that
# two instances of inject.py can run at same time
# and they use different directories
def get_bugs_parent(lp):
    bugs_parent = ""
    candidate = 0
    bugs_lock = None
    print("Getting locked bugs directory...")
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

    print("Using dir", bugs_parent)
    lp.set_bugs_parent(bugs_parent)
    return bugs_parent


if __name__ == "__main__":
    update_db = False
    parser = argparse.ArgumentParser(description='Inject and test LAVA bugs.')
    parser.add_argument('host_json', help='Host JSON file')
    parser.add_argument('project', help='Project name')
    parser.add_argument('-b', '--bugid', action="store", default=-1,
                        help='Bug id (otherwise, highest scored will be chosen)')
    parser.add_argument('-r', '--randomize', action='store_true', default=False,
                        help='Choose the next bug randomly rather than by score')
    parser.add_argument('-m', '--many', action="store", default=-1,
                        help='Inject this many bugs (chosen randomly)')
    parser.add_argument('-l', '--buglist', action="store", default=False,
                        help='Inject this list of bugs')
    parser.add_argument('-k', '--knobTrigger', metavar='int', type=int, action="store", default=0,
                        help='specify a knob trigger style bug, eg -k [sizeof knob offset]')
    parser.add_argument('-s', '--skipInject', action="store", default=False,
                        help='skip the inject phase and just run the bugged binary on fuzzed inputs')
    parser.add_argument('-nl', '--noLock', action="store_true", default=False,
                        help='No need to take lock on bugs dir')
    parser.add_argument('-c', '--checkStacktrace', action="store_true", default=False,
                        help='When validating a bug, make sure it manifests at same line as lava-inserted trigger')
    parser.add_argument('-e', '--exitCode', action="store", default=0, type=int,
                        help='Expected exit code when program exits without crashing. Default 0')
    parser.add_argument('-bb', '--balancebugtype', action="store_true", default=False,
                        help='Attempt to balance bug types, i.e. inject as many of each type')
    parser.add_argument('-competition', '--competition', action="store_true", default=False,
                        help='Inject in competition mode where logging will be added in #IFDEFs')
    parser.add_argument("-fixups", "--fixupsscript", action="store", default=False,
                        help="script to run after injecting bugs into source to fixup before make")
    #    parser.add_argument('-wl', '--whitelist', action="store", default=None,
    #                        help = ('White list file of functions to bug and data flow'))
    parser.add_argument('-t', '--bugtypes', action="store", default="ptr_add,rel_write",
                        help='bug types to inject')
    parser.add_argument('--version', action="version", version="%(prog)s {}".format(version))

    args = parser.parse_args()
    global project
    project = parse_vars(args.host_json, args.project)
    dataflow = project.get("dataflow", False)

    allowed_bugtypes = get_allowed_bugtype_num(args)

    print("allowed bug types: " + (str(allowed_bugtypes)))

    # Set various paths
    lp = LavaPaths(project)

    db = LavaDatabase(project)

    try:
        os.makedirs(lp.bugs_top_dir)
    except Exception:
        pass

    # this is where buggy source code will be
    bugs_parent = get_bugs_parent(lp)

    # Remove all old YAML files
    run_cmd(["rm -f {}/*.yaml".format(lp.bugs_build)], None, 10, cwd="/", shell=True)

    # obtain list of bugs to inject based on cmd-line args and consulting db
    (update_db, bug_list) = get_bug_list(args, db, allowed_bugtypes)

    # add all those bugs to the source code and check that it compiles
    # TODO use bug_solutions and make inject_bugs return solutions for single-dua bugs?
    (build, input_files, bug_solutions) = inject_bugs(bug_list, db, lp, args.host_json,
                                                      project, args, update_db, dataflow=dataflow,
                                                      competition=args.competition)
    if build is None:
        raise RuntimeError("LavaTool failed to build target binary")

    try:
        # determine which of those bugs actually cause a seg fault
        real_bug_list = validate_bugs(bug_list, db, lp, project, input_files, build,
                                      args, update_db)


        def count_bug_types(id_list):
            tcount = {}
            buglist = {}
            for bug in get_bugs(db, id_list):
                if not bug.type in tcount:
                    tcount[bug.type] = 0
                    buglist[bug.type] = []
                tcount[bug.type] += 1
                buglist[bug.type].append(bug.id)
            for t in tcount.keys():
                print("%d c(%s)=%d" % (t, Bug.type_strings[t], tcount[t]))
                print(str(buglist[t]))


        print("\nBug types in original, potential set")
        count_bug_types(bug_list)

        print("\nBug types in validated set")
        count_bug_types(real_bug_list)


    except Exception as e:
        print("TESTING FAIL")
        if update_db:
            db.session.add(Run(build=build, fuzzed=None, exitcode=-22,
                               output=str(e), success=False, validated=False))
            db.session.commit()
        raise

    print("inject complete %.2f seconds" % (time.time() - start_time))
