#!/usr/bin/python

import datetime
import argparse
import atexit
import json
import lockfile
import os
import psycopg2
import random
import re
import shlex
import shutil
import signal
import signal
import string
import subprocess32
import sys
import time

from os.path import basename, dirname, join, abspath

from lava import *

start_time = time.time()

project = None
# this is how much code we add to top of any file with main fn in it
NUM_LINES_MAIN_INSTR = 5
debugging = False

# run lavatool on this file to inject any parts of this list of bugs
# offset will be nonzero if file contains main and therefore
# has already been instrumented with a bunch of defs of lava_get and lava_set and so on
def inject_bugs_into_src(bugs, filename, offset, kt=False):
    global bugs_build
    global lava_tool
    global lavadb
    buglist = ','.join([str(bug.id) for bug in bugs])
    if kt:
        cmd = ('{} -action=inject -kt -bug-list={} -lava-db={} -src-prefix={} ' + \
            '-main_instr_correction={} {} -project-file={}').format(
                lava_tool, buglist, lavadb, bugs_build, offset,
                join(bugs_build, filename), project_file
            )
    else:
        cmd = ('{} -action=inject -bug-list={} -lava-db={} -src-prefix={} ' + \
            '-main_instr_correction={} {} -project-file={}').format(
                lava_tool, buglist, lavadb, bugs_build, offset,
                join(bugs_build, filename), project_file
            )
    return run_cmd_notimeout(cmd, None, None)

# run lavatool on this file and add defns for lava_get and lava_set
def instrument_main(filename):
    global bugs_build
    global lava_tool
    global lavadb
    filename_bug_part = bugs_build + "/" + filename
    cmd = lava_tool + ' -action=main -bug-list=\"\"' \
        + ' -lava-db=' + lavadb + ' -p ' + bugs_build \
        + ' ' + filename_bug_part \
        + ' ' + '-project-file=' + project_file \
        + ' ' + '-src-prefix=' + bugs_build
    run_cmd_notimeout(cmd, None, None)

def get_suffix(fn):
    split = basename(fn).split(".")
    if len(split) == 1:
        return ""
    else:
        return "." + split[-1]

# here's how to run the built program
def run_modified_program(install_dir, input_file, timeout):
    cmd = project['command'].format(install_dir=install_dir,input_file=input_file)
    print cmd
    envv = {}
    lib_path = project['library_path'].format(install_dir=install_dir)
    envv["LD_LIBRARY_PATH"] = join(install_dir, lib_path)
    return run_cmd(cmd, install_dir, envv, timeout) # shell=True)

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


def get_atp_line(bug, bugs_build):
    with open(join(bugs_build, bug.atp.loc_filename), "r") as f:
        atp_iter = (line_num for line_num, line in enumerate(f) if
                    "lava_get({})".format(bug.id) in line)
        try:
            line_num = atp_iter.next() + 1
            return line_num
        except StopIteration:
            exit_error("lava_get({}) was not in {}".format(bug.id,
                                                        bug.atp.loc_filename))

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


    # Set up our globals now that we have a project
    db = LavaDatabase(project)

    timeout = project.get('timeout', 5)

    # This is top-level directory for our LAVA stuff.
    top_dir = join(project['directory'], project['name'])
    lava_dir = dirname(dirname(abspath(sys.argv[0])))
    project['lava'] = lava_dir
    lava_tool = join(lava_dir, 'src_clang', 'build', 'lavaTool')

    # This should be {{directory}}/{{name}}/bugs
    bugs_top_dir = join(top_dir, 'bugs')

    # only makes sense to try to package a corpus if we are injecting several bugs.
    if args.corpus:
        assert (args.many)
        corpus_dir = join(top_dir, "corpus")

    try:
        os.makedirs(bugs_top_dir)
    except Exception: pass

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
                candidate += 1

    print "Using dir", bugs_parent

    if (not args.noLock):
        atexit.register(bugs_lock.release)
        for sig in [signal.SIGINT, signal.SIGTERM]:
            signal.signal(sig, lambda s, f: sys.exit(0))

    try:
        os.mkdir(bugs_parent)
    except Exception: pass

    if 'source_root' in project:
        source_root = project['source_root']
    else:
        tar_files = subprocess32.check_output(['tar', 'tf', project['tarfile']], stderr=sys.stderr)
        source_root = tar_files.splitlines()[0].split(os.path.sep)[0]

    print "source_root = " + source_root + "\n"

    queries_build = join(top_dir, source_root)
    bugs_build = join(bugs_parent, source_root)
    bugs_install = join(bugs_build, 'lava-install')
    # Make sure directories and btrace is ready for bug injection.
    def run(args, **kwargs):
        print "run(", subprocess32.list2cmdline(args), ")"
        subprocess32.check_call(args, cwd=bugs_build,
                stdout=sys.stdout, stderr=sys.stderr, **kwargs)
    if not os.path.exists(bugs_build):
        subprocess32.check_call(['tar', '--no-same-owner', '-xf', project['tarfile'],
            '-C', bugs_parent], stderr=sys.stderr)
    if not os.path.exists(join(bugs_build, '.git')):
        run(['git', 'init'])
        run(['git', 'config', 'user.name', 'LAVA'])
        run(['git', 'config', 'user.email', 'nobody@nowhere'])
        run(['git', 'add', '-A', '.'])
        run(['git', 'commit', '-m', 'Unmodified source.'])
    if not os.path.exists(join(bugs_build, 'btrace.log')):
        run(shlex.split(project['configure']) + ['--prefix=' + bugs_install])
        run([join(lava_dir, 'btrace', 'sw-btrace')] + shlex.split(project['make']))

    lavadb = join(top_dir, 'lavadb')

    main_files = set(project['main_file'])

    if not os.path.exists(join(bugs_build, 'compile_commands.json')):
        # find llvm_src dir so we can figure out where clang #includes are for btrace
        llvm_src = None
        config_mak = project['lava'] + "/src_clang/config.mak"
        print "config.mak = [%s]" % config_mak
        for line in open(config_mak):
            foo = re.search("LLVM_SRC_PATH := (.*)$", line)
            if foo:
                llvm_src = foo.groups()[0]
                break
        assert(not (llvm_src is None))

        print "llvm_src =", llvm_src

        run([join(lava_dir, 'btrace', 'sw-btrace-to-compiledb'), llvm_src + "/Release/lib/clang/3.6.2/include"])
        # also insert instr for main() fn in all files that need it
        print "Instrumenting main fn by running lavatool on %d files\n" % (len(main_files))
        for f in main_files:
            print "injecting lava_set and lava_get code into [%s]" % f
            instrument_main(f)
            run(['git', 'add', f])
        run(['git', 'add', 'compile_commands.json'])
        run(['git', 'commit', '-m', 'Add compile_commands.json and instrument main.'])
        run(shlex.split(project['make']))
        try:
            run(shlex.split("find .  -name '*.[ch]' -exec git add '{}' \\;"))
            run(['git', 'commit', '-m', 'Adding source files'])
        except subprocess32.CalledProcessError:
            pass
        if not os.path.exists(bugs_install):
            run(project['install'], shell=True)

        # ugh binutils readelf.c will not be lavaTool-able without
        # bfd.h which gets created by make.
        run_cmd_notimeout(project["make"], bugs_build, None)
        run(shlex.split("find .  -name '*.[ch]' -exec git add '{}' \\;"))
        try:
            run(['git', 'commit', '-m', 'Adding any make-generated source files'])
        except subprocess32.CalledProcessError:
            pass

    # Now start picking the bug and injecting
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
            # competition
            bugs_to_inject = db.competition_bugs_and_non_bugs(num_bugs_to_inject)
        else:
            # demo, I guess
            print "Injecting %d bugs" % num_bugs_to_inject
            for i in range(num_bugs_to_inject):
                bugs_to_inject.append(db.next_bug_random(False))
        update_db = True
    else: assert False

    # collect set of src files into which we must inject code
    src_files = set()
    i = 0

    for bug_index, bug in enumerate(bugs_to_inject):
         print "------------\n"
         print "SELECTED "
         if bug.dua.fake_dua:
             print "NON-BUG"
         else:
             print "BUG"
         print " {} : {}".format(bug_index, bug.id)#
 ####        if not args.randomize: print "   score=%d " % score
         print "   (%d,%d)" % (bug.dua.id, bug.atp.id)
         print "DUA:"
         print "   ", bug.dua
         print "ATP:"
         print "   ", bug.atp
         print "max_tcn={}  max_liveness={}".format(
             bug.max_liveness, bug.dua.max_tcn)
         src_files.add(bug.dua.lval.loc_filename)
         src_files.add(bug.atp.loc_filename)

    # cleanup
    print "------------\n"
    print "CLEAN UP SRC"
    run_cmd_notimeout("/usr/bin/git checkout -f", bugs_build, None)

    print "------------\n"
    print "INJECTING BUGS INTO SOURCE"
    print "%d source files: " % (len(src_files))
    print src_files
    print main_files
    for src_file in src_files:
        print "inserting code into dua file %s" % src_file
        offset = 0
        if src_file in main_files:
            offset = NUM_LINES_MAIN_INSTR

        if args.knobTrigger != -1:
            (exitcode, output) = inject_bugs_into_src(bugs_to_inject, src_file, offset, True)
        else:
            (exitcode, output) = inject_bugs_into_src(bugs_to_inject, src_file, offset)
        # note: now that we are inserting many dua / atp bug parts into each source, potentially.
        # which means we can't have simple exitcodes to indicate precisely what happened
        print "exitcode = %d" % exitcode
        if debugging:
            print output[0]
        if debugging or exitcode != 0:
            print output[1]
        if exitcode < 0:
            raise RuntimeError("bad!")

    # ugh -- with tshark if you *dont* do this, your bug-inj source may not build, sadly
    # it looks like their makefile doesn't understand its own dependencies, in fact
    if ('makeclean' in project) and (project['makeclean']):
        run_cmd_notimeout("make clean", bugs_build, None)

    # compile
    print "------------\n"
    print "ATTEMPTING BUILD OF INJECTED BUG"
    print "build_dir = " + bugs_build
    (rv, outp) = run_cmd_notimeout(project['make'], bugs_build, None)
    build = Build(compile=(rv == 0), output=(outp[0] + ";" + outp[1]))
    if rv!=0:
        # build failed
        print outp
        print "build failed"
        sys.exit(1)
    else:
        # build success
        print "build succeeded"
        (rv, outp) = run_cmd_notimeout("make install", bugs_build, None)
        assert rv == 0 # really how can this fail if build succeeds?
        print "make install succeeded"

    # add a row to the build table in the db
    if update_db:
        db.session.add(build)

    try:
        # build succeeded -- testing
        print "------------\n"
        # first, try the original file
        print "TESTING -- ORIG INPUT"
        orig_input = join(top_dir, 'inputs', basename(bug.dua.inputfile))
        (rv, outp) = run_modified_program(bugs_install, orig_input, timeout)
        if rv != 0:
            print "***** buggy program fails on original input!"
            assert False
        else:
            print "buggy program succeeds on original input"
        print "retval = %d" % rv
        print "output:"
        lines = outp[0] + " ; " + outp[1]
#            print lines
        if update_db:
            db.session.add(Run(build=build, fuzzed=None, exitcode=rv,
                               output=lines, success=True))
        print "SUCCESS"
        # second, fuzz it with the magic value
        print "TESTING -- FUZZED INPUTS"
        suff = get_suffix(orig_input)
        pref = orig_input[:-len(suff)] if suff != "" else orig_input
        real_bugs = []
        fuzzed_inputs = []
        for bug_index, bug in enumerate(bugs_to_inject):
            fuzzed_input = "{}-fuzzed-{}{}".format(pref, bug.id, suff)
            print bug
            print "fuzzed = [%s]" % fuzzed_input
            if args.knobTrigger != -1:
                print "Knob size: {}".format(args.knobTrigger)
                mutfile(orig_input, bug.dua.all_labels, fuzzed_input, bug.id, True, args.knobTrigger)
            else:
                mutfile(orig_input, bug.dua.all_labels, fuzzed_input, bug.id)
            print "testing with fuzzed input for {} of {} potential.  ".format(
                bug_index + 1, len(bugs_to_inject))
            print "{} real. bug {}".format(len(real_bugs), bug.id)
            (rv, outp) = run_modified_program(bugs_install, fuzzed_input, timeout)
            print "retval = %d" % rv
            print "output:"
            lines = outp[0] + " ; " + outp[1]
#                print lines
            if update_db:
                db.session.add(Run(build=build, fuzzed=bug, exitcode=rv,
                                output=lines.encode('string-escape'), success=True))
            if bug.dua.fake_dua == False:
                # this really is supposed to be a bug
                # we should see a seg fault or something
                if rv == -11 or rv == -6:
                    real_bugs.append(bug.id)
                    fuzzed_inputs.append(fuzzed_input)
            else:
                # this really is supposed to be a non-bug
                # we should see a 0
                assert (rv == 0)


            print
        f = float(len(real_bugs)) / len(bugs_to_inject)
        print "yield {:.2f} ({} out of {}) real bugs".format(
            f, len(real_bugs), len(bugs_to_inject)
        )
        print "TESTING COMPLETE"
        if len(bugs_to_inject) > 1:
            print "list of real validated bugs:", real_bugs

        if update_db: db.session.commit()
        # NB: at the end of testing, the fuzzed input is still in place
        # if you want to try it

        if args.corpus:
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
