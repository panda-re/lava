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
    fuzzed_input_for_bug, get_trigger_line, AttackPoint, Bug, get_allowed_bugtype_num

# from pycparser.diversifier.diversify import diversify
from process_compile_commands import get_c_files


RETRY_COUNT = 0

# Build both scripts - in a seperate fn for testing
def run_builds(scripts):
    for script in scripts:
        with open(script) as f:
            print(f.read())
        (rv, outp) = run_cmd_notimeout(["/bin/bash", script])
        if rv != 0:
            raise RuntimeError("Could not build {}".format(script))
        print("Built with command {}".format(script))

# collect num bugs AND num non-bugs
# with some hairy constraints
# we need no two bugs or non-bugs to have same file/line attack point
# that allows us to easily evaluate systems which say there is a bug at file/line.
# further, we require that no two bugs or non-bugs have same file/line dua
# because otherwise the db might give us all the same dua

def competition_bugs_and_non_bugs(num, db, allowed_bugtypes, buglist):
    max_duplicates_per_line = 0 # Max duplicates we *try* to inject per line
    bugs_and_non_bugs = []
    dfl_fileline = {}
    afl_fileline = {}
    def get_bugs_non_bugs(fake, limit):
        if buglist is None:
            items = db.uninjected_random(fake, allowed_bugtypes)
        else:
            items = db.session.query(Bug).filter(Bug.id.in_(buglist)).all()
            print "items %d" % (len(items))
            limit = 10000000

        for item in items:
            if not (item.type in allowed_bugtypes):
                print("skipping type {} not in {}".format(item.type, allowed_bugtypes))
                continue
            dfl = (item.trigger_lval.loc_filename, item.trigger_lval.loc_begin_line)
            afl = (item.atp.loc_filename, item.atp.loc_begin_line)
            if (dfl in dfl_fileline and dfl_fileline[dfl] > max_duplicates_per_line): 
                print "skipping dfl %s" % (str(dfl))
                continue
            if (afl in afl_fileline and afl_fileline[afl] > max_duplicates_per_line): 
                print "skipping afl %s" % (str(afl))
                continue
            if not (dfl in dfl_fileline): dfl_fileline[dfl] = 0
            if not (afl in afl_fileline): afl_fileline[afl] = 0
            if fake:
                print "non-bug", 
            else:
                print "bug    ",
            print ' dua_fl={} atp_fl={}'.format(str(dfl), str(afl))
            dfl_fileline[dfl] += 1
            afl_fileline[afl] += 1
            bugs_and_non_bugs.append(item)
            if (len(bugs_and_non_bugs) == limit):
                break
    get_bugs_non_bugs(False, num)
    # get_bugs_non_bugs(True, 2*num)
    return [b.id for b in bugs_and_non_bugs]

def main():
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
    parser.add_argument('-i', '--diversify', action="store_true", default=False,
            help = ('Diversify source code. Default false.'))
    parser.add_argument('-s', '--skipinject', action="store_true", default=False,
            help = ('Skip injection step. Use if you must make manual changes to src.'))
    parser.add_argument('-d', '--arg_dataflow', action="store_true", default=False,
            help = ('Inject bugs using function args instead of globals'))
    parser.add_argument('-c', '--chaff', action="store_true", default=False,
            help = ('Leave unvalidated bugs in the binary'))
    parser.add_argument('-t', '--bugtypes', action="store", default="rel_write",
                        help = ('bug types to inject'))
    
    args = parser.parse_args()
    project = json.load(args.project)
    project_file = args.project.name

    allowed_bugtypes = get_allowed_bugtype_num(args)

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

    if not args.skipinject:
        try:
            shutil.rmtree(bugdir)
        except:
            pass

    args.knobTrigger = -1
    args.checkStacktrace = False
    failcount = 0


    if args.buglist:
        print ("bug_list incoming %s" % (str(args.buglist)))
        bug_list = competition_bugs_and_non_bugs(int(args.many), db, allowed_bugtypes, eval(args.buglist))
    elif args.many:
        bug_list = competition_bugs_and_non_bugs(int(args.many), db, allowed_bugtypes, None)
    else:
        print("Fatal error: no bugs specified")
        raise RuntimeError

    assert len(bug_list)

    print('bug_list:')
    bug_list_str = ','.join([str(bug_id) for bug_id in bug_list])
    print(bug_list_str)

    if args.skipinject:
        project['configure'] = "echo 'no reconfigure- Running with skip inject'";

    if not args.skipinject:
        # add either bugs to the source code and check that we can still compile
        try:
            (build, input_files) = inject_bugs(bug_list, db, lp, project_file, \
                                              project, args, False, competition=True,
                                              validated=False)
        except RuntimeError:
            print("Failed to inject bugs\n{}".format(bug_list))
            print("Manually fix errors and resume execution with:")
            print("./scripts/competition.sh -c -d -s -l {buglist} {json}".format(
                buglist=bug_list_str,
                json=project_file))
            sys.exit(-1)
    else:
        # HACK
        build = None
        input_files = project['inputs']
        print(input_files)

    # bug is valid if seg fault (or bus error)
    # AND if stack trace indicates bug manifests at trigger line we inserted
    real_bug_list = validate_bugs(bug_list, db, lp, project, input_files, build, \
                                      args, False, competition=True)

    if len(real_bug_list) < int(args.minYield):
        print "\n\nXXX Yield too low -- %d bugs minimum is required for competition" % int(args.minYield)
        print "TODO: Try again.\n" # TODO: Need to loop?
        sys.exit(-1)
    else:
        print "\n\n Yield acceptable: {}".format(len(real_bug_list))

    if not args.chaff:
        # re-build just with the real bugs. Inject in competition mode
        print("REINJECT validated bugs")
        (build,input_files) = inject_bugs(real_bug_list, db, lp, project_file, \
                                              project, args, False, competition=True, validated=True)


    corpus_dir = join(compdir, "corpora")
    subprocess32.check_call(["mkdir", "-p", corpus_dir])

    # original bugs src dir
    # directory for this corpus
    corpname = "lava-corpus-" + ((datetime.datetime.now()).strftime("%Y-%m-%d-%H-%M-%S"))
    corpdir = join(corpus_dir,corpname)
    subprocess32.check_call(["mkdir", corpdir])

    lava_bd = join(lp.bugs_parent, lp.source_root)

    # Copy lava's builddir into our local build-dir
    bd = join(corpdir, "build-dir")
    shutil.copytree(lava_bd, bd)

    # build internal versio)n
    log_build_sh = join(corpdir, "log_build.sh")
    with open(log_build_sh, "w") as build:
        build.write("""#!/bin/bash
        pushd `pwd`
        cd {bugs_build}

        # Build internal version
        {make_clean}
        {configure}
        {make} CFLAGS+="-DLAVA_LOGGING"
        rm -rf "{internal_builddir}"
        {install}
        {post_install}
        cp -r lava-install {internal_builddir}

        popd
        """.format(
            bugs_build=bd,
            make_clean = project["clean"] if "clean" in project.keys() else "",
            configure=project['configure'],
            make = project['make'],
            internal_builddir = join(corpdir, "lava-install-internal"),
            install = project['install'],
            post_install = project['post_install'] if 'post_install' in project.keys() else "",
            ))
    run_builds([log_build_sh])

    # diversify
    if args.diversify:
        print('Starting diversification\n')
        compile_commands = join(bugdir, lp.source_root, "compile_commands.json")
        all_c_files = get_c_files(lp.bugs_build, compile_commands)
        for c_file in all_c_files:
            print('diversifying {}'.format(c_file))
            c_file = join(bugdir, lp.source_root, c_file)
            # pre-processing
            #   run_cmd_notimeout(
            #           ' '.join([
            #           'gcc', '-E', '-std=gnu99',
            #           '-I.', '-I..',
            #           '-I/llvm-3.6.2/Release/lib/clang/3.6.2/include',
            #           '-o',
            #           '{}.pre'.format(c_file),
            #           c_file]))
            # diversify(c_file, '{}.div'.format(c_file))
            # run_cmd_notimeout(' '.join(['cp', '{}.div'.format(c_file), c_file]))

        # re-build
        (rv, outp) = run_cmd_notimeout(project['make'], cwd=lp.bugs_build)
        for o in outp:
            print(o)
        if rv == 0:
            print('build succeeded')
            subprocess32.check_call(project['install'], cwd=lp.bugs_build, shell=True)
            if 'post_install' in project:
                check_call(project['post_install'], cwd=lp.bugs_build, shell=True)
        else:
            print('build failed')
            sys.exit(-1)

        # re-validate
        old_yield = len(real_bug_list)
        real_bug_list = validate_bugs(bug_list, db, lp, project, input_files, build, \
                                          args, False, competition=True)
        new_yield = len(real_bug_list)
        print('Old yield: {}'.format(old_yield))
        print('New yield: {}'.format(new_yield))

    # Corpus directory structure: lava-corpus-[date]/
    #   inputs/
    #   src/
    #   build.sh
    #   log_build.sh
    #   lava-install-internal
    #   lava-install-prod

    # subdir with trigger inputs
    inputsdir = join(corpdir, "inputs")
    subprocess32.check_call(["mkdir", inputsdir])
    # subdir with src -- note we can't create it or copytree will fail!
    srcdir = join(corpdir, "src")
    # copy src
    shutil.copytree(bd, srcdir)

    predictions = []
    bug_ids = []
    with open(join(corpdir, "ans2"), "w") as ans2:
        for bug in  db.session.query(Bug).filter(Bug.id.in_(real_bug_list)).all():
            prediction = "{}:{}".format(basename(bug.atp.loc_filename),
                                        get_trigger_line(lp, bug))
            ans2.write(str(bug)+"\n") # Simple

            print "Bug %d: prediction = [%s]" % (bug.id, prediction)
            print str(bug)
            if not get_trigger_line(lp, bug):
                print("Warning - unknown trigger, skipping for answer key")
                #continue

#        assert not (prediction in predictions)
            fuzzed_input = fuzzed_input_for_bug(lp, bug) # TODO - this is broken for multidua bugs - is it?
            (dc, fi) = os.path.split(fuzzed_input)
            shutil.copy(fuzzed_input, inputsdir)
            predictions.append((prediction, fi))
            bug_ids.append(bug.id)

    print "Answer key:"
    with open(join(corpdir, "ans"), "w") as ans:
        for (prediction, fi) in predictions:
            print "ANSWER  [%s] [%s]" % (prediction, fi)
            ans.write("%s %s\n" % (prediction, fi))

    with open(join(corpdir, "add_bugs.sql"), "w") as f:
        f.write("/* This file will add all the generated lava_id values to the DB, you must update binary_id */\n")
        f.write("\set binary_id -1\n")
        for bug_id in bug_ids:
            f.write("insert into \"bug\" (\"lava_id\", \"binary\") VALUES (%d, :binary_id); \n" % (bug_id))

    # clean up srcdir before tar
    os.chdir(srcdir)
    try:
        # Unconfigure
        subprocess32.check_call(["make", "distclean"])
    except:
        pass
    shutil.rmtree(join(srcdir, ".git"))
    shutil.rmtree(join(srcdir, "lava-install"))
    os.remove(join(srcdir, "compile_commands.json"))
    os.remove(join(srcdir, "btrace.log"))

    # build source tar
    #tarball = join(srcdir + ".tgz")
    #os.chdir(corpdir)
    #cmd = "/bin/tar czvf " + tarball + " src"
    #subprocess32.check_call(cmd.split())
    #print "created corpus tarball " + tarball + "\n";

    #lp.bugs_install = join(corpdir,"lava-install") # Change to be in our corpdir
    # Save the commands we use into files so we can rerun later
    build_sh = join(corpdir, "build.sh")
    with open(build_sh, "w") as build:
        build.write("""#!/bin/bash
        pushd `pwd`
        cd {bugs_build}
        {make_clean}
        {configure}
        {make}
        {install}
        {post_install}
        mv lava-install {outdir}
        popd
        """.format(
            bugs_build=bd,
            make_clean = project["clean"] if "clean" in project.keys() else "",
            configure=project['configure'],
            make=project['make'],
            install=project['install'],
            outdir=join(corpdir, "lava-install"),
            post_install=project['post_install']
        ))

    public_build_sh = join(corpdir, "public_build.sh") # Simple
    with open(public_build_sh, "w") as build:
        build.write("""#!/bin/bash
        pushd `pwd`
        cd {bugs_build}

        # Build public version
        {make_clean}
        {configure}
        {make}
        rm -rf "{public_builddir}"
        {install}
        {post_install}
        cp -r lava-install {public_builddir}

        popd
        """.format(
            bugs_build=bd,
            make_clean = project["clean"] if "clean" in project.keys() else "",
            configure=project['configure'],
            make = project['make'],
            public_builddir = join(corpdir, "lava-install"),
            install = project['install'],
            post_install = project['post_install']
            ))

    trigger_all_crashes = join(corpdir, "trigger_crashes.sh")
    with open(trigger_all_crashes, "w") as build:
        build.write("""#!/bin/bash
rm -rf validated_inputs.txt validated_bugs.txt

trap "echo 'CRASH'" {{1..31}}

for fname in {inputdir}; do
    # Get bug ID from filename (# after last -)
    IFS='-'
    read -ra fname_parts <<< "$fname"
    for i in ${{fname_parts[@]}}; do
        bugid=$i
    done
    IFS=' '

    #Non-logging version
    LD_LIBRARY_PATH={librarydir2} {command2} &> /dev/null
    code=$?

    if [ "$code" -gt 130 ]; then # Competition version crashed, check log version
        LD_LIBRARY_PATH={librarydir} {command} &> /tmp/comp.txt
        logcode=$?
        if [ "$logcode" -lt 131 ]; then # internal version didn't crash
            echo "UNEXPECTED ERROR ($bugid): competition version exited $logcode while normal exited with $code -- Skipping";
        else
            if grep -q "LAVALOG: $bugid" /tmp/comp.txt; then
                echo $fname >> validated_inputs.txt
                echo $bugid >> validated_bugs.txt
            else
                echo "Competition infrastructure failed on $bugid";
            fi
        fi
    fi
done""".format(command = project['command'].format(**{"install_dir": "./lava-install-internal", "input_file": "$fname"}), # This syntax is weird but only thing that works?
            corpdir = corpdir,
            librarydir = join("./lava-install-internal", "lib"),
            librarydir2 = join("./lava-install", "lib"),
            command2 = project['command'].format(**{"install_dir": "./lava-install", "input_file": "$fname"}), # This syntax is weird but only thing that works?
            inputdir = "./inputs/*-fuzzed-*"
            ))

    # Build a version to ship in src
    run_builds([build_sh, public_build_sh])
    print("Success! Competition build in {}".format(corpdir))


if __name__ == "__main__":
    main()
