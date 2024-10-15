#!/usr/bin/env python3

import argparse
import datetime
import os
import random
import shutil
import stat
import subprocess
from os.path import basename, join

from lava import LavaDatabase, run_cmd, run_cmd_notimeout, inject_bugs, LavaPaths, \
    validate_bugs, fuzzed_input_for_bug, AttackPoint, Bug, \
    get_allowed_bugtype_num, limit_atp_reuse
from vars import parse_vars

# from pycparser.diversifier.diversify import diversify
# from process_compile_commands import get_c_files

version = "2.0.0"

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


def random_choice(options, probs):
    # Select from options with probabilities from prob
    sum_probs = sum(probs)
    norm_probs = [float(x) / sum_probs for x in probs]
    r = random.uniform(0, 1)
    for idx, prb in enumerate(norm_probs):
        if r < prb: return options[idx]
        r -= prb
    raise RuntimeError("Random choice broke")


# collect num bugs AND num non-bugs
# with some hairy constraints
# we need no two bugs or non-bugs to have same file/line attack point
# that allows us to easily evaluate systems which say there is a bug at file/line.
# further, we require that no two bugs or non-bugs have same file/line dua
# because otherwise the db might give us all the same dua

def competition_bugs_and_non_bugs(limit, db, allowed_bugtypes, buglist):
    # XXX This function is prtty gross, definitely needs a rewrite
    max_duplicates_per_line = 50  # Max duplicates we *try* to inject per line. After validation, we filter down to ~1 per line
    bugs_and_non_bugs = []
    dfl_fileline = {}
    afl_fileline = {}

    fake = False

    # Find a set of bugs of allowed_bugtype with limited overlap on trigger and atp location with other selected bugs
    def parse(item):
        """
        Given a bug, decide if we should add it to bugs_and_non_bugs, if so add it

        return False IFF we have reached limit bugs and should stop parsing
        """

        if not (item.type in allowed_bugtypes):
            # print("skipping type {} not in {}".format(item.type, allowed_bugtypes))
            return True
        dfl = (item.trigger_lval.loc_filename, item.trigger_lval.loc_begin_line)
        afl = (item.atp.loc_filename, item.atp.loc_begin_line, item.atp.loc_begin_column)

        if not (dfl in dfl_fileline.keys()): dfl_fileline[dfl] = 0
        if not (afl in afl_fileline.keys()): afl_fileline[afl] = 0

        if dfl_fileline[dfl] > max_duplicates_per_line:
            # print "skipping dfl %s" % (str(dfl))
            return True
        if afl_fileline[afl] > max_duplicates_per_line:
            # print "skipping afl %s" % (str(afl))
            return True
        if fake:
            print("non-bug")
        else:
            print("bug    ")
        print('id={} dua_fl={} atp_fl={} dua_ast={} type={}'.format(item.id, str(dfl), str(afl),
                                                                    str(item.trigger_lval.ast_name),
                                                                    Bug.type_strings[item.type]))
        dfl_fileline[dfl] += 1
        afl_fileline[afl] += 1
        bugs_and_non_bugs.append(item)
        if len(bugs_and_non_bugs) >= limit:
            print("Abort bug-selection because we already found {} bugs to inject".format(limit))
            return False
        return True

    if buglist is None:
        abort = False
        # Note atp_types are different from bugtypes, there are places we can attack, not how we do so
        # but the names overlap and are kind of related
        # TODO we don't find rel_writes at function calls
        atp_types = [AttackPoint.FUNCTION_CALL, AttackPoint.POINTER_WRITE]

        # Get limit bugs at each ATP
        # atp_item_lists = db.uninjected_random_by_atp(fake, atp_types=atp_types, allowed_bugtypes=allowed_bugtypes, atp_lim=limit)
        # Returns list of lists where each sublist corresponds to the same atp: [[ATP1_bug1, ATP1_bug2], [ATP2_bug1], [ATP3_bug1, ATP3_bug2]]

        atp_item_lists = db.uninjected_random_by_atp_bugtype(fake, atp_types=atp_types,
                                                             allowed_bugtypes=allowed_bugtypes, atp_lim=limit)
        # Returns dict of list of lists where each dict is a bugtype and within each, each sublist corresponds to the same atp: [[ATP1_bug1, ATP1_bug2], [ATP2_bug1], [ATP3_bug1, ATP3_bug2]]
        while True:

            for selected_bugtype in allowed_bugtypes:
                atp_item_lists[selected_bugtype] = [x for x in atp_item_lists[selected_bugtype] if
                                                    len(x)]  # Delete any empty lists
            if sum([len(x) for x in atp_item_lists.values()]) == 0:
                print(
                    "Abort bug-selection because we've selected all {} potential bugs we have (Failed to find all {} requested bugs)".format(
                        len(bugs_and_non_bugs), limit))
                break

            # Randomly select a sublist from atp_item_lists (none will be empty)
            # weight by bugtype

            # Of the allowed bugtypes, the ratio will be normalized.
            # As this is now, we'll pick REL_WRITES (multiduas) more often than others because they work less frequently
            # Ratios for RET_BUFFER and PRINTF_LEAK are just guesses
            bug_ratios = {Bug.REL_WRITE: 200, Bug.PTR_ADD: 15, Bug.RET_BUFFER: 15, Bug.PRINTF_LEAK: 15}
            for x in allowed_bugtypes:
                if x not in bug_ratios:
                    assert ("Bug type {} not in bug_ratios. Fix me!".format(Bug.type_strings[this_bugtype]))
            allowed_bug_ratios = [bug_ratios[x] for x in allowed_bugtypes]

            this_bugtype = random_choice(allowed_bugtypes, allowed_bug_ratios)
            # print("Selected bugtype {}".format(Bug.type_strings[this_bugtype]))

            this_bugtype_atp_item_lists = atp_item_lists[this_bugtype]
            if len(this_bugtype_atp_item_lists) == 0:
                # TODO: intelligently select a different bugype in this case
                allowed_bugtypes.remove(this_bugtype)
                print("Warning: tried to select a bug of type {} but none available".format(
                    Bug.type_strings[this_bugtype]))
                assert (len(allowed_bugtypes) > 0), "No bugs available"
                continue

            atp_item_idx = random.randint(0, len(this_bugtype_atp_item_lists) - 1)
            item = this_bugtype_atp_item_lists[
                atp_item_idx].pop()  # Pop the first bug from that bug_list (Sublist will be sorted randomly)

            """
            # TODO: fix this manual libjpeg hack. Blacklist bugs here by strings in their dua/extra_duas
            blacklist = [("data_ptr", None), ("quant_table", None), ("dtbl).pub", None), ("compptr", 3609), ("compptr).downsampled_width", 3557), ("htbl", None), ("compptr).downsampled_height", None), ("dtbl).valoffset", None)]

            cont = False
            for (badword, minidx) in blacklist:

                extra_duas = db.session.query(DuaBytes).filter(DuaBytes.id.in_(item.extra_duas)).all()
                for dua in [item.trigger_lval] + [x.dua.lval for x in extra_duas]:
                    if cont: break
                    if badword in dua.ast_name and (not minidx or dua.loc_begin_line < minidx):
                        print("Skipping dua {} since its ast {} contains a bad ast string ({}) before {}".format(dua, dua.ast_name, badword, minidx))
                        cont = True
                        break
            if cont:
                continue

            # End of libjpeg hack
            """

            abort |= not parse(item)  # Once parse returns true, break
            if abort:
                break
    else:
        for item in db.session.query(Bug).filter(Bug.id.in_(buglist)).all():
            if not parse(item):
                break

    # Show some stats about requested bugs
    afls = {}
    for item in bugs_and_non_bugs:
        afl = (item.atp.loc_filename, item.atp.loc_begin_line, item.atp.loc_begin_column)
        if afl not in afls.keys():
            afls[afl] = 0
        afls[afl] += 1

    print("{} potential bugs were selected across {} ATPs:".format(len(bugs_and_non_bugs), len(afls)))
    for bugtype in allowed_bugtypes:
        bt_count = len([x for x in bugs_and_non_bugs if x.type == bugtype])
        print("{} potential bugs of type {}".format(bt_count, Bug.type_strings[bugtype]))

    for atp, count in afls.items():
        print("\t{}\t bugs at {}".format(count, atp))

    return [b.id for b in bugs_and_non_bugs]


def main():
    parser = argparse.ArgumentParser(prog="competition.py", description='Inject and test LAVA bugs.')
    parser.add_argument('host_json', help='Host JSON file')
    parser.add_argument('project', help='Project name')

    parser.add_argument('-m', '--many', action="store", default=-1,
                        help='Inject this many bugs and this many non-bugs (chosen randomly)')
    parser.add_argument('-n', '--minYield', action="store", default=-1,
                        help='Require at least this many real bugs')
    parser.add_argument('-l', '--buglist', action="store", default=False,
                        help='Inject this list of bugs')
    parser.add_argument('-e', '--exitCode', action="store", default=0, type=int,
                        help='Expected exit code when program exits without crashing. Default 0')
    # parser.add_argument('-i', '--diversify', action="store_true", default=False,
    # help = ('Diversify source code. Default false.'))
    parser.add_argument('-c', '--chaff', action="store_true", default=False,
                        # TODO chaf and unvalided bugs aren't always the same thing
                        help='Leave unvalidated bugs in the binary')
    parser.add_argument('-t', '--bugtypes', action="store", default="rel_write",
                        help='bug types to inject')
    parser.add_argument('--version', action="version", version="%(prog)s {}".format(version))

    args = parser.parse_args()
    global project
    project = parse_vars(args.host_json, args.project)

    dataflow = project.get("dataflow", False)  # Default to false

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

    try:
        shutil.rmtree(bugdir)
    except:
        pass

    args.knobTrigger = False
    args.checkStacktrace = False
    failcount = 0

    # generate a random seed to pass through to lavaTool so it behaves deterministcally between runs
    lavatoolseed = random.randint(0, 100000)

    ###############
    ## First we get a list of bugs, either from cli options, or through competition_bugs_and_non_bugs
    ###############

    if args.buglist:
        print("bug_list incoming %s" % (str(args.buglist)))
        bug_list = competition_bugs_and_non_bugs(len(args.buglist), db, allowed_bugtypes,
                                                 eval(args.buglist))  # XXX EVAL WHY
    elif args.many:
        bug_list = competition_bugs_and_non_bugs(int(args.many), db, allowed_bugtypes, None)
    else:
        print("Fatal error: no bugs specified")
        raise RuntimeError

    assert len(bug_list)  # Found no bugs

    print('bug_list (len={}):'.format(len(bug_list)))
    bug_list_str = ','.join([str(bug_id) for bug_id in bug_list])
    print(bug_list_str)

    ###############
    ## With our bug list in hand, we inject all these bugs and count how many we can trigger
    ###############

    real_bug_list = []
    # add bugs to the source code and check that we can still compile
    (build, input_files, bug_solutions) = inject_bugs(bug_list, db, lp, args.host_json,
                                                      project, args, False, dataflow=dataflow, competition=True,
                                                      validated=False, lavatoolseed=lavatoolseed)
    assert build is not None  # build is None when injection fails. Could block here to allow for manual patches

    # Test if the injected bugs cause approperiate crashes and that our competition infrastructure parses the crashes correctly
    real_bug_list = validate_bugs(bug_list, db, lp, project, input_files, build,
                                  args, False, competition=True, bug_solutions=bug_solutions)

    if len(real_bug_list) < int(args.minYield):
        print("\n\nXXX Yield too low after injection -- Require at least {} bugs for"
              " competition, only have {}".format(args.minYield, len(real_bug_list)))
        raise RuntimeError("Failure")

    print("\n\n Yield acceptable: {}".format(len(real_bug_list)))

    # TODO- the rebuild process may invalidate a previously validated bug because the trigger will change
    # Need to find a way to pass data between lavaTool and here so we can reinject *identical* bugs as before

    ###############
    ## After we have a list of validated bugs, we inject again. This time, we will only inject the bugs we have
    ## already validated, so these should all validate again. Before we reinject these, we'll remove any bugs from
    ## our list that use the same ATP as other bugs we're injecting.
    ###############

    if not args.chaff:
        # re-build just with the real bugs. Inject in competition mode. Deduplicate bugs with the same ATP location
        print("Reinjecting only validated bugs")

        real_bugs = db.session.query(Bug).filter(Bug.id.in_(real_bug_list)).all()
        real_bug_list = limit_atp_reuse(real_bugs)

        # TODO retry a few times if we fail this test
        if bug_list != real_bug_list:  # Only reinject if our bug list has changed
            if len(real_bug_list) < int(args.minYield):
                print("\n\nXXX Yield too low after reducing duplicates -- Require at least {} bugs for  \
                        competition, only have {}".format(args.minYield, len(real_bug_list)))
                raise RuntimeError("Failure")
            (build, input_files, bug_solutions) = inject_bugs(real_bug_list, db, lp, args.host_json,
                                                              project, args, False, dataflow=dataflow,
                                                              competition=True, validated=True,
                                                              lavatoolseed=lavatoolseed)

            assert build is not None  # build is None if injection fails

    ###############
    ## Now build our corpora directory with the buggy source dir, binaries in lava-install-public,
    ## lava-install-internal, and scripts to rebuild the binaries
    ###############

    corpus_dir = join(compdir, "corpora")
    subprocess.check_call(["mkdir", "-p", corpus_dir])

    # original bugs src dir
    # directory for this corpus
    corpname = "lava-corpus-" + ((datetime.datetime.now()).strftime("%Y-%m-%d-%H-%M-%S"))
    corpdir = join(corpus_dir, corpname)
    subprocess.check_call(["mkdir", corpdir])

    lava_bd = join(lp.bugs_parent, lp.source_root)

    # Copy lava's builddir into our local build-dir
    bd = join(corpdir, "build-dir")
    shutil.copytree(lava_bd, bd)

    # build internal version
    log_build_sh = join(corpdir, "log_build.sh")

    # We need to set the environmnet for the make command
    log_make = "CFLAGS=-DLAVA_LOGGING {}".format(project["make"])

    internal_builddir = join(corpdir, "lava-install-internal")
    lava_installdir = join(bd, "lava-install")
    with open(log_build_sh, "w") as build:
        build.write("""#!/bin/bash
        pushd `pwd`
        cd {bugs_build}

        # Build internal version
        {make_clean}
        {configure}
        {log_make}
        rm -rf "{internal_builddir}"
        {install}
        {post_install}
        mv lava-install {internal_builddir}

        popd
        """.format(
            bugs_build=bd,
            make_clean=project["clean"] if "clean" in project.keys() else "",
            configure=project['configure'] if "configure" in project.keys() else "",
            log_make=log_make,
            internal_builddir=internal_builddir,
            install=project['install'].format(install_dir=lava_installdir),
            post_install=project['post_install'] if 'post_install' in project.keys() else "",
        ))
    run_builds([log_build_sh])

    # diversify
    """
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
            #           '-I/usr/lib/llvm-11/lib/clang/11/include',
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
            subprocess.check_call(project['install'], cwd=lp.bugs_build, shell=True)
            if 'post_install' in project:
                check_call(project['post_install'], cwd=lp.bugs_build, shell=True)
        else:
            print('build failed')
            sys.exit(-1)

        # re-validate
        old_yield = len(real_bug_list)
        real_bug_list = validate_bugs(bug_list, db, lp, project, input_files, build, \
                                          args, False, competition=True, bug_solutions=bug_solutions)
        new_yield = len(real_bug_list)
        print('Old yield: {}'.format(old_yield))
        print('New yield: {}'.format(new_yield))
    """

    # Corpus directory structure: lava-corpus-[date]/
    #   inputs/
    #   src/
    #   build.sh
    #   log_build.sh
    #   lava-install-internal
    #   lava-install-prod

    # subdir with trigger inputs
    inputsdir = join(corpdir, "inputs")
    subprocess.check_call(["mkdir", inputsdir])
    # subdir with src -- note we can't create it or copytree will fail!
    srcdir = join(corpdir, "src")
    # copy src
    shutil.copytree(bd, srcdir)

    predictions = []
    bug_ids = []

    for bug in db.session.query(Bug).filter(Bug.id.in_(real_bug_list)).all():
        prediction = basename(bug.atp.loc_filename)
        fuzzed_input = fuzzed_input_for_bug(project, bug)
        (dc, fi) = os.path.split(fuzzed_input)
        shutil.copy(fuzzed_input, inputsdir)
        predictions.append((prediction, fi, bug.type))
        bug_ids.append(bug.id)

    print("Answer key:")
    with open(join(corpdir, "ans"), "w") as ans:
        for (prediction, fi, bugtype) in predictions:
            print("ANSWER  [%s] [%s] [%s]" % (prediction, fi, Bug.type_strings[bugtype]))
            ans.write("%s %s %s\n" % (prediction, fi, Bug.type_strings[bugtype]))

    with open(join(corpdir, "add_bugs.sql"), "w") as f:
        f.write("/* This file will add all the generated lava_id values to the DB, you must update binary_id */\n")
        f.write("\set binary_id 0\n")
        for bug_id in bug_ids:
            f.write("insert into \"bug\" (\"lava_id\", \"binary\") VALUES (%d, :binary_id); \n" % bug_id)

    # clean up srcdir before tar
    os.chdir(srcdir)
    try:
        # Unconfigure
        subprocess.check_call(["make", "distclean"])
    except:
        pass

    # Delete private files
    deldirs = [join(srcdir, x) for x in [".git", "lava-instal"]]
    delfiles = [join(srcdir, x) for x in ["compile_commands.json", "btrace.log"]]

    for dirname in deldirs:
        if os.path.isdir(dirname):
            shutil.rmtree(dirname)
    for fname in delfiles:
        if os.path.exists(fname):
            os.remove(fname)

    # build source tar
    # tarball = join(srcdir + ".tgz")
    # os.chdir(corpdir)
    # cmd = "/bin/tar czvf " + tarball + " src"
    # subprocess.check_call(cmd.split())
    # print "created corpus tarball " + tarball + "\n";

    # lp.bugs_install = join(corpdir,"lava-install") # Change to be in our corpdir

    # Save the commands we use into files so we can rerun later
    public_build_sh = join(corpdir, "public_build.sh")  # Simple
    public_builddir = join(corpdir, "lava-install-public")
    lava_installdir = join(bd, "lava-install")
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
        mv lava-install {public_builddir}

        popd
        """.format(
            bugs_build=bd,
            make_clean=project["clean"] if "clean" in project.keys() else "",
            configure=project['configure'] if "configure" in project.keys() else "",
            make=project['make'],
            public_builddir=public_builddir,
            install=project['install'].format(install_dir=lava_installdir),
            post_install=project['post_install'] if "post_install" in project.keys() else ""
        ))

    trigger_all_crashes = join(corpdir, "trigger_crashes.sh")
    with open(trigger_all_crashes, "w") as build:
        build.write("""#!/bin/bash
rm -rf validated_inputs.txt validated_bugs.txt

trap "echo 'CRASH'" {{3..31}}

for fname in {inputdir}; do
    # Get bug ID from filename (# after last -)
    IFS='-'
    read -ra fname_parts <<< "$fname"
    for i in ${{fname_parts[@]}}; do
        bugid=$i
    done
    IFS=' '
    bugid=${{bugid%.*}}

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
done""".format(command=project['command'].format(**{"install_dir": "./lava-install-internal", "input_file": "$fname"}),
               # This syntax is weird but only thing that works?
               corpdir=corpdir,
               librarydir=join("./lava-install-internal", "lib"),
               librarydir2=join("./lava-install-public", "lib"),
               command2=project['command'].format(**{"install_dir": "./lava-install-public", "input_file": "$fname"}),
               # This syntax is weird but only thing that works?
               inputdir="./inputs/*-fuzzed-*"
               ))
    os.chmod(trigger_all_crashes, (stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IROTH | stat.S_IXOTH))
    # Build a version to ship in src
    run_builds([log_build_sh, public_build_sh])
    print("Injected {} bugs".format(len(real_bug_list)))

    print("Counting how many crashes competition infrastructure identifies...")
    run_cmd(trigger_all_crashes, cwd=corpdir)  # Prints about segfaults
    (rv, outp) = run_cmd("wc -l {}".format(join(corpdir, "validated_bugs.txt")))
    if rv != 0:
        raise RuntimeError("Validated bugs file does not exist. Something went wrong")

    (a, b) = outp[0].split()
    n = int(a)
    print("\tCompetition infrastructure found: %d of %d injected bugs" % (n, len(real_bug_list)))


if __name__ == "__main__":
    main()
