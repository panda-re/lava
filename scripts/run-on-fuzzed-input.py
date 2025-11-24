#!/usr/bin/env python3

import argparse
import json
import lockfile
import os
import string
import subprocess
import sys
import time
import difflib
import itertools
from colorama import Fore
assert itertools

import re
import shutil
assert re
# need random to evaluate expressions for knobRange input
# allows user to express knob randome as random samples of a particular range
import random
assert random
import numpy
assert numpy

from os.path import basename, dirname, join, abspath

from lava import *
import multiprocessing
assert multiprocessing

start_time = time.time()

project = None
timeout = None
queries_install = None
bugs_install = None
bugs_build = None
top_dir = None
args = None
# global for stack trace option
VERBOSE = False

# this is how much code we add to top of any file with main fn in it
NUM_LINES_MAIN_INSTR = 5
UPDATE_DB = False
RR = "/home/ulrich/git/obj/bin/rr"
CUR_DIR = dirname(abspath(sys.argv[0]))
RR_TRACES_TOP_DIR = join(CUR_DIR, "rr_traces")

debugging = False
mutfile_cache = None
# trace_template = ("rr: Saving the execution of `.*?' to trace"
                # "directory `(.*?)'\.")
# trace_dir_re = re.compile(trace_template)
TICKS_RE = re.compile("ticks:([0-9]+)", re.MULTILINE)

def get_suffix(fn):
    split = basename(fn).split(".")
    if len(split) == 1:
        return ""
    else:
        return "." + split[-1]

def run(args, **kwargs):
    print("run(", " ".join(args), ")")
    subprocess.check_call(args, cwd=bugs_build,
            stdout=sys.stdout, stderr=sys.stderr, **kwargs)

def exit_error(msg):
    print(Fore.RED + msg + Fore.RESET)
    sys.exit(1)

# here's how to run the built program
def run_modified_program(install_dir, input_file, timeout, rr=False, rr_dir=""):
    cmd = project['command'].format(install_dir=install_dir,input_file=input_file)
    if rr:
        cmd = "{} record {}".format(RR, cmd)
    if debugging:
        print(cmd)
    envv = {}
    lib_path = project['library_path'].format(install_dir=install_dir)
    envv["LD_LIBRARY_PATH"] = join(install_dir, lib_path)
    if rr_dir != "" and rr:
        envv["_RR_TRACE_DIR"] = dirname(rr_dir)
    (rc, outp) = run_cmd(cmd, install_dir, envv, timeout, rr=rr) # shell=True)
    if rr:
        (_, (ps_stdout, ps_stderr)) = run_cmd("{} ps {}".format(RR, rr_dir), install_dir,
                                              envv, timeout)
        # get the third column from the second line in output which returns the 
        # exit code
        try:
            rc = int(ps_stdout.split("\n")[1].split()[2])
        except:
            rr_env = ("_RR_TRACE_DIR={}".format(envv["_RR_TRACE_DIR"])
                      if "_RR_TRACE_DIR" in envv
                      else "")
            libpath_env = "LD_LIBRARY_PATH={}".format(envv["LD_LIBRARY_PATH"])
            print("Could not get return code from rr ps")
            print("stdout: {}".format(ps_stdout))
            print("stderr: {}".format(ps_stderr))
            print("cmd: [{} {} {}]".format(rr_env, libpath_env, cmd))
            print("{} ps {}".format(RR, rr_dir))
            sys.exit(1)
        return rc, outp[1:]
    else:
        return rc, outp

def confirm_bug_in_executable(install_dir):
    cmd = project['command'].format(install_dir=install_dir,input_file="foo")
    nm_cmd = 'nm {}'.format(cmd.split()[0])

    (exitcode, output) = run_cmd_notimeout(nm_cmd, None, {})
    if exitcode != 0:
        exit_error("Error running cmd confirm injection: {}".format(nm_cmd))
    else:
        contains_lava = lambda line: "lava_val" in line
        return len(filter(contains_lava, output)) > 0

def checkKnobRangeExpression(knobRangeStr):
    def issafe(n):
        return isinstance(n, int) and n > 0
    try:
        l = eval(knobRangeStr)
    # Python error'd when trying to evaluate knobRangeStr
    except:
        return False
    return len(l) > 0 and all(map(issafe, l))

def filter_printable(text):
    return ''.join([ '.' if c not in string.printable else c for c in text])

def rr_get_tick_from_event(rr_trace_dir, event_num):
    rr_cmd = "{} dump {} {}".format(RR, rr_trace_dir, event_num)
    (_, out) = run_cmd(rr_cmd, None, {}, 10000) # shell=True)
    try:
        (pout, perr) = out
        m = TICKS_RE.search(pout)
        return int(m.groups()[0])
    except:
        print("RR dumps did not return proper ouput for event")
        print("========stdout========")
        print(pout)
        print("========stderr========")
        print(perr)
        sys.exit(1)

def get_atp_line(bug, bugs_build):
    with open(join(bugs_build, bug.atp.loc_filename), "r") as f:
        atp_iter = (line_num + 1 for line_num, line in enumerate(f) if
                    "lava_get({})".format(bug.trigger.id) in line)
        try:
            line_num = atp_iter.next()
            return line_num
        except StopIteration:
            exit_error("lava_get({}) was not in {}".format(bug.trigger.id,
                                                        bug.atp.loc_filename))

def do_function(inp):
    # TODO: someone document this please
    global timeout
    global queries_install
    global bugs_install
    global KT
    global top_dir
    global mutfile_cache
    global args
    # real_bugs = []
    (knobSize, bug) = inp
    run_id = ("{}-{}".format(bug.id, knobSize) if KT else "{}".format(bug.id))
    if args.gdb:
        rr_new_trace_dir = join(RR_TRACES_TOP_DIR, "rr-{}".format(run_id))
        os.mkdir(rr_new_trace_dir)
        proc_name = os.path.basename(project['command'].split()[0])
        rr_trace_dir = join(rr_new_trace_dir, "{}-{}".format(proc_name, 0))
    else:
        rr_trace_dir = ""

    orig_input = join(top_dir, 'inputs', basename(bug.trigger.dua.inputfile))
    suff = get_suffix(orig_input)
    pref = orig_input[:-len(suff)] if suff != "" else orig_input

    fuzzed_input = "{}-fuzzed-{}{}".format(pref, run_id, suff)

    fuzz_labels_list = [bug.trigger.all_labels]
    if len(bug.extra_duas) > 0:
        extra_query = db.session.query(DuaBytes)\
            .filter(DuaBytes.id.in_(bug.extra_duas))
        fuzz_labels_list.extend([d.all_labels for d in extra_query])
    if not fuzzed_input in mutfile_cache:
        if KT:
            mutfile(orig_input, fuzz_labels_list, fuzzed_input, bug.id, kt=True, knob=knobSize)
        else:
            mutfile(orig_input, fuzz_labels_list, fuzzed_input, bug.id)
    # only run on rr if we will eventually run the program in gdb for crash
    # state information
    rr = args.gdb
    (rv, outp) = run_modified_program(bugs_install, fuzzed_input,
                                      timeout, rr=rr, rr_dir=rr_trace_dir)
    # print "retval = %d" % rv
    # print "output: [{}]".format(" ;".join(outp))
    if args.compareToQueriesBuild:
        print("DIFFING . . .")
        (orig_rv, orig_outp) = run_modified_program(queries_install, fuzzed_input, timeout)
        diff = list(difflib.ndiff(orig_outp, outp))
        if (len(diff) < 2 or
            not any(map(lambda line: line[0] in ["+", "-"], diff))):
            print("SAME!")
        elif all(map(lambda line: line == "", outp)):
            print("Inject Build Has No Output - CANCELING")
            pass
        else:
            print("DIFFERENT")
            print("".join(diff))
    # We could try to figure out how to update the DB with the exit code for the
    # input
    # if UPDATE_DB:
        # db.session.add(Run(build=build, fuzzed=bug, exitcode=rv,
                        # output=orig_outp, success=True))
    if rv == -11 or rv == -6:
        # real_bugs.append(bug.id)
        if args.gdb:
            line_num = get_atp_line(bug, bugs_build)
            atp_loc = "{}:{}".format(bug.atp.loc_filename, line_num)
            atp_prefix = " ATP=\"{}\"".format(atp_loc)
            gdb_py_script = join(lava_dir, "scripts/signal_analysis_gdb.py")
            lib_path = project['library_path'].format(install_dir=bugs_install)
            lib_prefix = "LD_LIBRARY_PATH={}".format(lib_path)
            # cmd = project['command'].format(install_dir=bugs_install,input_file=fuzzed_input)
            # if (debug): print "cmd: " + lib_path + " " + cmd
            # gdb_cmd = " gdb --batch --silent -x {} --args {}".format(gdb_py_script, cmd)
            # rr_cmd = " {} replay -x {}".format(RR, gdb_py_script)
            rr_cmd = " {} replay -x {} {}".format(RR, gdb_py_script, rr_trace_dir)
            full_cmd = lib_prefix + atp_prefix + rr_cmd
            envv = {"LD_LIBRARY_PATH": lib_path}
            envv["ATP"] = atp_loc
            (_, out) = run_cmd(rr_cmd, bugs_install, envv, 5) # shell=True)
            # hasInstrCount = lambda line: "Instruction Count = " in line
            hasInstrCount = lambda line: "Events = " in line
            instr_iter = (out_type for out_type in out if hasInstrCount(out_type))
            try:
                # count = int(instr_iter.next().split("Instruction Count = ")[1].split()[0])
                (after, before) = instr_iter.next().strip().split("Events = ")[1].split()
                after_tick = rr_get_tick_from_event(rr_trace_dir, after)
                before_tick = rr_get_tick_from_event(rr_trace_dir, before)
                count = after_tick - before_tick
            except StopIteration:
                print("\"Instruction Count = \" was not in gdb output")
                cmd = project['command'].format(install_dir=bugs_install,input_file=fuzzed_input)
                print("======gdb out======")
                print("\n".join(out))
                print("======end gdb out======")
                print("Bug_id {} failed on KT:{}".format(bug.id, knobSize))
                print("cmd: [{} {} replay {}]".format(lib_prefix, RR, cmd))
                print("rr cmd: [{}]".format(full_cmd))
                sys.exit(1)
                # count = -1
            # os.system(full_cmd)
        else:
            count = -1
        if args.stackBackTrace:
            gdb_py_script = join(lava_dir, "scripts/stacktrace_gdb.py")
            lib_path = project['library_path'].format(install_dir=bugs_install)
            envv = {"LD_LIBRARY_PATH": lib_path}
            cmd = project['command'].format(install_dir=bugs_install,input_file=fuzzed_input)
            gdb_cmd = "gdb --batch --silent -x {} --args {}".format(gdb_py_script, cmd)
            full_cmd = "LD_LIBRARY_PATH={} {}".format(lib_path, gdb_cmd)
            (rc, (out, err)) = run_cmd(gdb_cmd, bugs_install, envv, 10000) # shell=True)
            if VERBOSE:
                print(out.split("\n")[-2], err)
            else:
                prediction = "{}:{}".format(basename(bug.atp.loc_filename),
                                         get_atp_line(bug, bugs_build))
                print("Prediction {}".format(prediction))
                for line in out.split("\n"):
                    if line.startswith("#0"):
                        actual = line.split(" at ")[1]
                        if actual != prediction:
                            print("Actual {}".format(actual))
                            print("DIVERGENCE.  Exiting . . .")
                            sys.exit(1)
                        break


    else:
        count = -1
    return bug.id, knobSize, rv == -6 or rv == -11, count


if __name__ == "__main__":
    # set up multiprocessing manager
    # manager = Manager()
    # set up arg parser
    parser = argparse.ArgumentParser(description='Inject and test LAVA bugs.')
    parser.add_argument('project', type=argparse.FileType('r'),
            help = 'JSON project file')
    parser.add_argument('-b', '--bugid', action="store", default=-1,
            help = 'Bug id (otherwise, highest scored will be chosen)')
    parser.add_argument('-l', '--buglist', action="store", default=False,
            help = 'Inject this list of bugs')
    parser.add_argument('-k', '--knobTrigger', action="store", default=False,
            help = 'Specify a knob trigger style bug with a python expression for the knob range, eg. -k \"range(1,18000, 10)\"')
    parser.add_argument('-g', '--gdb', action="store_true", default=False,
            help = 'Switch on gdb mode which will run fuzzed input under gdb')
    parser.add_argument('-c', '--compareToQueriesBuild', action="store_true", default=False,
            help = 'Compare the output of Knob Trigger inject build to the output of the inject build')
    parser.add_argument('-s', '--stackBackTrace', action="store_true", default=False,
            help = ('Output the stack backtrace IF the input triggered a rv of '
                    '-6 or -11'))
    parser.add_argument('-nl', '--noLock', action="store_true", default=False,
            help = ('No need to take lock on bugs dir'))
    parser.add_argument('-e', '--exitCode', action="store", default=0, type=int,
            help = ('Expected exit code when program exits without crashing. Default 0'))


    args = parser.parse_args()
    project = json.load(args.project)
    project_file = args.project.name

    # set up knobTrigger range
    if args.knobTrigger:
        if not checkKnobRangeExpression(args.knobTrigger):
            exit_error("--knobTrigger: \"{}\" is not valid python range expression".format(args.knobRange))
        knobRange = sorted(list(set(eval(args.knobTrigger))))
        print("Testing {} inputs for knob offsets in range: {}".format(len(knobRange), knobRange))
        KT = True
    else:
        KT = False

    # Set up our globals now that we have a project
    db = LavaDatabase(project)

    timeout = project.get('timeout', 5)

    # This is top-level directory for our LAVA stuff.
    top_dir = join(project['directory'], project['name'])
    lava_dir = dirname(dirname(abspath(sys.argv[0])))
    lava_tool = join(lava_dir, 'src_clang', 'build', 'lavaTool')

    mutfile_cache = set(os.listdir(join("inputs", top_dir)))

    # This should be {{directory}}/{{name}}/bugs
    bugs_top_dir = join(top_dir, 'bugs')

    try:
        os.makedirs(bugs_top_dir)
    except: pass

    # This is where we're going to do our injection. We need to make sure it's
    # not being used by another inject.py.
    bugs_parent = ""
    candidate = 0
    bugs_lock = None
    while bugs_parent == "":
        candidate_path = join(bugs_top_dir, str(candidate))        
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
                print("Can\'t acquire lock on bug folder")
                bugs_parent = ""
                sys.exit(1)
                candidate += 1

    print("Using dir", bugs_parent)

    if not args.noLock:
        # release bug lock.  who cares if another process
        # could theoretically modify this directory
        bugs_lock.release()
        # at exit.register(bugs_lock.release)
        # for sig in [signal.SIGINT, signal.SIGTERM]:
        # signal.signal(sig, lambda s, f: sys.exit(-1))

    try:
        os.mkdir(bugs_parent)
    except:
        pass

    if 'source_root' in project:
        source_root = project['source_root']
    else:
        tar_files = subprocess.check_output(['tar', 'tf', project['tarfile']], stderr=sys.stderr)
        source_root = tar_files.splitlines()[0].split(os.path.sep)[0]

    queries_build = join(top_dir, source_root)
    queries_install = join(queries_build, 'lava-install')
    bugs_build = join(bugs_parent, source_root)
    bugs_install = join(bugs_build, 'lava-install')
    # Make sure directories and btrace is ready for bug injection.
    if not os.path.exists(bugs_build):
        exit_error("bug_build dir: {} does not exit".format(bugs_build))
    if not os.path.exists(join(bugs_build, '.git')):
        exit_error("bug_build dir: {} does not have git repo".format(bugs_build))
    if not os.path.exists(join(bugs_build, 'btrace.log')):
        exit_error("bug_build dir: {} does not have btrace.log".format(bugs_build))

    lavadb = join(top_dir, 'lavadb')

    main_files = set(project['main_file'])

    if not os.path.exists(join(bugs_build, 'compile_commands.json')):
        exit_error("bug_build dir: {} does not have compile_commands.json".format(bugs_build))

    # Now start picking the bug and injecting
    bugs_to_inject = []
    if args.bugid != -1:
        bug_id = int(args.bugid)
        score = 0
        bugs_to_inject.append(db.session.query(Bug).filter_by(id=bug_id).one())
    elif args.buglist:
        buglist = eval(args.buglist)
        bugs_to_inject = db.session.query(Bug).filter(Bug.id.in_(buglist)).all()
        # UPDATE_DB = False
    else: assert False

    # exits if lava_val does not appear in executable
    if not confirm_bug_in_executable(bugs_install):
        exit_error("A lava bug does not appear to have been injected: ")

    bug = bugs_to_inject[0]
    # for bug_index, bug in enumerate(bugs_to_inject):
         # print "------------\n"
         # print "SELECTED BUG {} : {}".format(bug_index, bug.id)#
         # print "   (%d,%d)" % (bug.trigger.dua.id, bug.atp.id)
         # print "DUA:"
         # print "   ", bug.trigger.dua
         # print "ATP:"
         # print "   ", bug.atp
         # print "max_tcn={}  max_liveness={}".format(
             # bug.trigger.dua.max_liveness, bug.trigger.dua.max_tcn)

    # make a "fresh" RR tracedir for the current run
    if os.path.exists(RR_TRACES_TOP_DIR):
        shutil.rmtree(RR_TRACES_TOP_DIR)
    os.mkdir(RR_TRACES_TOP_DIR)
    try:
        # build succeeded -- testing
        print("------------\n")
        # first, try the original file
        print("TESTING -- ORIG INPUT")
        orig_input = join(top_dir, 'inputs', basename(bug.trigger.dua.inputfile))

        (rv, outp) = run_modified_program(bugs_install, orig_input, timeout)
        if rv != args.exitCode:
            print("***** buggy program fails on original input!")
            assert False
        else:
            print("buggy program succeeds on original input")
        print("retval = %d" % rv)
        print("SUCCESS")
        # second, fuzz it with the magic value
        print("TESTING -- FUZZED INPUTS")
        # iterate through knob range or just a list of one element

        # start 4 worker processes

        knobSize_iter = knobRange if KT else [None]
        ################# multiprocessing solution ###################
        # pool = multiprocessing.Pool(processes=4)
        # inp_iter = itertools.product(knobSize_iter, bugs_to_inject)
        # for out_data in pool.map(do_function, inp_iter):
            # # print "=================================================="
            # out_data = do_function(inp)
            # (bug_id, ks, is_valid, step_size) = out_data
            # print "({},{},{},{})".format(bug_id, ks, is_valid, step_size)
        ################# multiprocessing solution ###################
        for inp in itertools.product(knobSize_iter, bugs_to_inject):
            print("==================================================")
            out_data = do_function(inp)
            (bug_id, ks, is_valid, step_size) = out_data
            print("({},{},{},{})".format(bug_id, ks, is_valid, step_size))
            # if UPDATE_DB: db.session.commit()
            # NB: at the end of testing, the fuzzed input is still in place
            # if you want to try it
            ##################################################################
    except Exception as e:
        print("TESTING FAIL")
        raise

    print("inject complete %.2f seconds" % (time.time() - start_time))

