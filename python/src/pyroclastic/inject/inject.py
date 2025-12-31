#!/usr/bin/env python3
import argparse
import sys
import time
import math
import os
import shlex
import struct
import subprocess
import random
from typing import List
from subprocess import PIPE, check_call
# LAVA imports
from .process_compile_commands import get_c_files, process_compile_commands
from ..utils.vars import parse_vars
from ..utils.funcs import get_inject_parser
from ..utils.sw_btrace_to_compiledb import main as sw_btrace_to_compiledb
from ..utils.database_types import Bug, DuaBytes, Build, Run, BugKind, LavaDatabase

NUM_BUGTYPES = 3  # Make sure this matches what's in lavaTool
start_time = time.time()


class LavaPaths(object):
    def __init__(self, project):
        self.top_dir = project['output_dir']
        self.lavadb = os.path.join(self.top_dir, 'lavadb')
        self.lava_tool = 'lavaTool'
        if 'source_root' in project:
            self.source_root = project['source_root']
        else:
            tar_files = subprocess.check_output(['tar', 'tf',
                                                project['tarfile']],
                                                stderr=sys.stderr)
            self.source_root = tar_files.decode().splitlines()[0].split(os.path.sep)[0]
        self.queries_build = os.path.join(self.top_dir, self.source_root)
        self.bugs_top_dir = os.path.join(self.top_dir, 'bugs')
        self.bugs_parent = ''
        self.bugs_build = ''
        self.bugs_install = ''

    def __str__(self):
        rets = ""
        rets += "top_dir =       %s\n" % self.top_dir
        rets += "lavadb =        %s\n" % self.lavadb
        rets += "lava_tool =     %s\n" % self.lava_tool
        rets += "source_root =   %s\n" % self.source_root
        rets += "queries_build = %s\n" % self.queries_build
        rets += "bugs_top_dir =  %s\n" % self.bugs_top_dir
        rets += "bugs_parent =   %s\n" % self.bugs_parent
        rets += "bugs_build =    %s\n" % self.bugs_build
        rets += "bugs_install =  %s\n" % self.bugs_install
        return rets

    def set_bugs_parent(self, bugs_parent):
        assert self.bugs_top_dir == os.path.dirname(bugs_parent)
        self.bugs_parent = bugs_parent
        self.bugs_build = os.path.join(self.bugs_parent, self.source_root)
        self.bugs_install = os.path.join(str(self.bugs_build), 'lava-install')


# get list of bugs either from cmd line or db
def get_bug_list(arguments, db, allowed_bugtypes):
    update_db = False
    print("Picking bugs to inject.")
    sys.stdout.flush()

    bug_list = []
    if arguments.bugid != -1:
        bug_id = int(arguments.bugid)
        bug_list.append(bug_id)
    elif arguments.randomize:
        print("Remaining to inj:", db.uninjected().count())
        print("Using strategy: random")
        bug = db.next_bug_random(False)
        bug_list.append(bug.id)
        update_db = True
    elif arguments.buglist:
        bug_list = eval(arguments.buglist)  # TODO
        update_db = False
    elif arguments.count:
        num_bugs_to_inject = int(arguments.count)
        huge = db.huge()

        available = "tons" if huge else db.uninjected().count()  # Only count if not huge
        print("Selecting %d bugs for injection of %s available" % (num_bugs_to_inject, str(available)))

        if not huge:
            assert available >= num_bugs_to_inject

        if arguments.balance:
            bugs_to_inject = db.uninjected_random_balance(False, num_bugs_to_inject, allowed_bugtypes)
        else:
            bugs_to_inject = db.uninjected_random_limit(allowed_bugtypes=allowed_bugtypes, count=num_bugs_to_inject)

        bug_list = [b.id for b in bugs_to_inject]
        print("%d is size of bug_list" % (len(bug_list)))
        update_db = True
    else:
        assert False
    return update_db, bug_list


def get_bugs_parent(lp: LavaPaths):
    """
    Choose directory into which we are going to put buggy source. locking etc.
    is so that two instances of inject.py can run at same time, and they use
    different directories.
    Given the whole context manager above, this function just uses index 0.
    We assume that there shouldn't be other instances of inject running at the same time.
    Args:
        lp (LavaPaths): The paths used in this step
    """
    candidate = 0
    print("Getting a bugs directory...")
    sys.stdout.flush()

    while True:
        candidate_path = os.path.join(lp.bugs_top_dir, str(candidate))
        bugs_parent = os.path.join(candidate_path)
        if not os.path.exists(bugs_parent):
            break
        candidate += 1

    print("Using bug build directory", bugs_parent)
    lp.set_bugs_parent(bugs_parent)
    return bugs_parent


def get_bugs(db, bug_id_list):
    bugs = []
    for bug_id in bug_id_list:
        bugs.append(db.session.query(Bug).filter(Bug.id == bug_id).all()[0])
    return bugs


def get_allowed_bugtype_num(arguments) -> list[int]:
    allowed_bugtype_nums = []

    # Safety check if arg is empty
    if not arguments.bugtypes:
        return allowed_bugtype_nums

    for bugtype_name in arguments.bugtypes.split(","):
        bugtype_name = bugtype_name.strip().lower()
        if not bugtype_name:
            continue

        found_kind: BugKind | None = None
        for kind in BugKind:
            normalized_enum_name = kind.name.lower().replace("bug_", "")

            if bugtype_name == normalized_enum_name:
                found_kind = kind
                break

        if found_kind is None:
            # Debug tip: print what we were looking for vs what we have
            available = ", ".join([k.name for k in BugKind])
            raise RuntimeError(f"I dont have a bug type [{bugtype_name}]. Available: {available}")

        allowed_bugtype_nums.append(found_kind.value)

    return allowed_bugtype_nums


# inject this set of bugs into the source place the resulting bugged-up
# version of the program in bug_dir
def inject_bugs(bug_list, db, lp, project: dict, arguments,
                update_db: bool, dataflow: bool = False, competition: bool = False,
                validated: bool=False, lavatoolseed: int = 0):
    # TODO: don't pass args, just pass the data we need to run
    # TODO: split into multiple functions, this is huge

    if not os.path.exists(lp.bugs_parent):
        os.makedirs(lp.bugs_parent)

    print("source_root = " + lp.source_root + "\n")

    # Make sure directories and btrace is ready for bug injection.
    def run(run_arguments, **kwargs):
        """
        Run the commands in the bugs_build directory
        Args:
            run_arguments: Namespace
            **kwargs: other arguments
        """
        print("run(", subprocess.list2cmdline(run_arguments), ")")
        check_call(run_arguments, cwd=lp.bugs_build, **kwargs)

    if not os.path.isdir(lp.bugs_build):
        print("Untarring...")
        check_call(['tar', '--no-same-owner', '-xf', project['tarfile']],
                   cwd=lp.bugs_parent)
    if not os.path.exists(os.path.join(lp.bugs_build, '.git')):
        print("Initializing git repo...")
        run(['git', 'init'])
        run(['git', 'config', 'user.name', 'LAVA'])
        run(['git', 'config', 'user.email', 'nobody@nowhere'])
        run(['git', 'add', '-f', '-A', '.'])
        run(['git', 'commit', '-m', 'Unmodified source.'])
    if not os.path.exists(os.path.join(lp.bugs_build, 'config.log')) \
            and 'configure' in project.keys():
        print('Re-configuring...')
        run(shlex.split(project['configure']) + ['--prefix=' + lp.bugs_install])
        envv = project["env_var"]
        if project['configure']:
            run_cmd(' '.join(shlex.split(project['configure']) + ['--prefix=' + lp.bugs_install]),
                    project, envv, 30, cwd=lp.bugs_build, shell=True)
    if not os.path.exists(os.path.join(lp.bugs_build, 'btrace.log')):
        print("Making with btrace...")

        # Do we need to configure here? I don't think so...
        # run(shlex.split(project['configure']) +
        # ['--prefix=' + lp.bugs_install])

        # Silence warnings related to adding integers to pointers since we already
        # know that it's unsafe.
        envv = project["full_env_var"]
        if competition:
            envv["CFLAGS"] += " -DLAVA_LOGGING"
        envv["BTRACE_LOG"] = "btrace.log"
        envv["LD_PRELOAD"] = "libsw-btrace.so"
        print("Running btrace make command: {} with env: {} in {}"
              .format(project['make'], envv, lp.bugs_build))
        rv, output = run_cmd(project['make'], project, envv, 30,
                             cwd=lp.bugs_build, shell=True)
        assert rv == 0, "Make with btrace failed"

    sys.stdout.flush()
    sys.stderr.flush()

    if not os.path.exists(os.path.join(lp.bugs_build, 'compile_commands.json')):
        clang_include = os.path.join(project["llvm-dir"], "lib/clang", project["llvm-version"], "include")
        previous_dir = os.getcwd()
        os.chdir(lp.bugs_build)
        sw_btrace_to_compiledb(str(clang_include))
        os.chdir(previous_dir)

        process_compile_commands(
            os.path.join(lp.bugs_build, 'compile_commands.json'),
            os.path.join(lp.bugs_top_dir, '../extra_compile_commands.json')
        )

        run(['git', 'add', '-f', 'compile_commands.json'])
        run(['git', 'commit', '-m', 'Add compile_commands.json.'])
        run(shlex.split(project['make']))
        try:
            run(['find', '.', '-name', '*.[ch]', '-exec',
                 'git', 'add', '-f', '{}', ';'])
            run(['git', 'commit', '-m', 'Adding source files'])
        except subprocess.CalledProcessError:
            pass

        # Here we run make install, but it may also run again later
        if not os.path.exists(lp.bugs_install):
            check_call(project['install'].format(install_dir="lava-install"),
                       cwd=lp.bugs_build, shell=True)

        run(shlex.split(project['make']))
        run(['find', '.', '-name', '*.[ch]', '-exec', 'git', 'add', '{}', ';'])
        try:
            run(['git', 'commit', '-m', 'Adding any make-generated source files'])
        except subprocess.CalledProcessError:
            pass

    bugs_to_inject = db.session.query(Bug).filter(Bug.id.in_(bug_list)).all()

    # TODO: We used to have code that would reduce duplicate ATPs at this point
    # see b6627fc05f4a78c7b14d03ade45c344c7747cd4b for the last time it was here
    if validated:
        pass

    # collect set of src files into which we must inject code
    src_files = collect_src_and_print(bugs_to_inject, db)
    input_files = unfuzzed_input_for_bug(project)

    # cleanup
    print("------------\n")
    print("CLEAN UP SRC")
    run_cmd_notimeout("git checkout -f", project, cwd=lp.bugs_build)

    print("------------\n")
    print("INJECTING BUGS INTO SOURCE")
    print("%d source files: " % (len(src_files)))
    print(src_files)

    all_files = src_files | set(project['main_file'])

    if dataflow:
        # if we're injecting with dataflow, we must modify all files in src
        compile_commands = os.path.join(lp.bugs_build, 'compile_commands.json')
        print('compile commands is here: {}'.format(compile_commands))
        all_c_files = get_c_files(lp.bugs_build, compile_commands)
        # print('all_c_files: {}'.format(all_c_files))
        # print('all_files: {}'.format(all_files))
        all_files = all_files.union(all_c_files)

    def modify_source(directory_name):
        return run_lavatool(bugs_to_inject, lp, project, directory_name, knob_trigger=arguments.knobTrigger,
                            dataflow=dataflow, competition=competition, randseed=lavatoolseed)

    bug_solutions = {}  # Returned by lavaTool

    for filename in all_files:
        # TODO call on directories instead of each file,
        # but still store results in bug_solutions
        bug_solutions.update(modify_source(filename))

    clang_apply = os.path.join(project['llvm-dir'], 'bin', 'clang-apply-replacements')

    src_dirs = set()
    src_dirs.add("")  # Empty path for root
    for filename in all_files:
        src_dir = os.path.dirname(filename)
        if len(src_dir):
            src_dirs.add(src_dir.encode("ascii", "ignore"))

    # Here we need to apply replacements. Unfortunately it can be a little complicated
    # compile_commands.json will be in lp.bugs_build. But then it contains data like:
    # directory: "[lp.bugs_build]/" file: src/foo.c" OR
    # directory: "[lp.bugs_build]/src" file: foo.c"
    # depending on how the makefile works

    # In theory, we should be able to run clang-apply-replacements
    # from the lp.bugs_build directory, and it should _just work_ but that doesn't
    # always happen. Instead, we'll run it inside each unique src directory

    one_replacement_success = False
    for src_dir in src_dirs:
        if project['debug']:
            print("Looking at src_dir: {}".format(src_dir))

        clang_cmd = [clang_apply, '.', '-remove-change-desc-files']
        if project['debug']:  # Don't remove desc files
            clang_cmd = [clang_apply, '.']
        print("Apply replacements in {} with {}".format(os.path.join(lp.bugs_build, src_dir), clang_cmd))
        rv, output = run_cmd_notimeout(clang_cmd, project, cwd=os.path.join(lp.bugs_build, src_dir))

        if rv == 0:
            print("Success in {}".format(src_dir))
            one_replacement_success = True

    assert one_replacement_success, "clang-apply-replacements failed in all possible directories"

    # Ugh, Lavatool very hard to get right
    # Permit automated fixups via script after bugs inject but before make.
    if "injfixupsscript" in project.keys():
        print("Running injfixupsscript: {}"
              .format(project["injfixupsscript"].format(bug_build=lp.bugs_build),
                      cwd=lp.bugs_build))
        run_cmd(project["injfixupsscript"].format(bug_build=lp.bugs_build),
                project, cwd=lp.bugs_build)

    if "fixupscript" in project.keys():
        print("Running fixupscript: {}"
              .format(project["fixupsscript"].format(bug_build=lp.bugs_build),
                      cwd=lp.bugs_build))
        run_cmd(project["fixupsscript"].format(bug_build=lp.bugs_build),
                project, cwd=lp.bugs_build)

    # paranoid clean -- some build systems need this
    if 'clean' in project.keys():
        check_call(project['clean'], cwd=lp.bugs_build, shell=True)

    # compile
    print("------------\n")
    print("ATTEMPTING BUILD OF INJECTED BUG(S)")
    print("build_dir = " + lp.bugs_build)

    # Silence warnings related to adding integers to pointers since we already
    # know that it's unsafe.
    make_cmd = project["make"]
    envv = project["full_env_var"]
    if competition:
        envv["CFLAGS"] += " -DLAVA_LOGGING"
    rv, output = run_cmd(make_cmd, project, envv, None, cwd=lp.bugs_build)

    if rv != 0:
        print("Lava tool returned {}! Error log below:".format(rv))
        print(output[1].decode('utf-8'))
        print()
        print("===================================")
        print("build of injected bug failed!!!!!!!")
        print("LAVA TOOL FAILED")
        print("===================================")
        print()
        print(output[0].decode('utf-8').replace("\\n", "\n"))
        print(output[1].decode('utf-8').replace("\\n", "\n"))

        print("Build of injected bugs failed")
        return None, input_files, bug_solutions

    # build success
    print("build succeeded")
    check_call(project['install'].format(install_dir="lava-install"),
               cwd=lp.bugs_build, shell=True)
    if 'post_install' in project.keys():
        check_call(project['post_install'], cwd=lp.bugs_build, shell=True)

    build: Build = Build(compile=(rv == 0), output=(output[0].decode('utf-8') + ";" + output[1].decode('utf-8')),
                  bugs=bugs_to_inject)

    # add a row to the build table in the db
    if update_db:
        db.session.add(build)
        db.session.commit()
        assert build.id is not None
        try:
            run(['git', 'commit', '-am', 'Bugs for build {}.'.format(build.id)])
        except Exception:
            print("\nFatal error: git commit failed! This may be caused by lavaTool not modifying anything")
            raise

        run(['git', 'branch', 'build' + str(build.id), 'master'])
        run(['git', 'reset', 'HEAD~', '--hard'])

    return build, input_files, bug_solutions


def run_cmd(cmd, project, envv=None, timeout=30, cwd=None, shell=False):
    if type(cmd) in [str] and not shell:
        cmd = shlex.split(cmd)

    if project['debug']:
        env_string = ""
        if envv:
            env_string = " ".join(["{}='{}'".format(k, v)
                                   for k, v in envv.items()])
        if type(cmd) == list:
            print("run_cmd(" + env_string + " " + subprocess.list2cmdline(cmd) + ")")
        else:
            print("run_cmd(" + env_string + " " + cmd + ")")
    # Merge current environ with passed envv
    merged_env = os.environ.copy()
    if envv:
        for k, v in envv.items():
            merged_env[k] = v

    p = subprocess.Popen(cmd, cwd=cwd, env=merged_env, stdout=PIPE,
                         stderr=PIPE, shell=shell)
    try:
        # returns tuple (stdout, stderr)
        output = p.communicate(timeout=timeout)
        stdout, stderr = output
        if project['debug']:
            print("Run_cmd stdout: {}".format(stdout.decode("utf-8")))
            print("Run_cmd stderr: {}".format(stderr.decode("utf-8")))
    except subprocess.TimeoutExpired:
        print("Killing process due to timeout expiration.")
        p.terminate()
        return -9, ("", "timeout expired")

    return p.returncode, output


def run_cmd_notimeout(cmd, project, **kwargs):
    return run_cmd(cmd, project,None, None, **kwargs)


# fuzz_labels_list is a list of tainted
# byte offsets within file filename.
# replace those bytes with random in a new
# file named new_filename


def mutfile(unfuzzed_filename: str, fuzz_labels_list, new_filename: str, bug,
            kt=False, knob=0, solution=None):
    # Open filename, mutate it and store in new_filename such that
    # it hopefully triggers the passed bug
    if kt:
        assert knob < 2 ** 16 - 1
        bug_trigger = bug.magic & 0xffff
        magic_val = struct.pack("<I", (knob << 16) | bug_trigger)
    else:
        magic_val = struct.pack("<I", bug.magic)
    # collect set of tainted offsets in file.
    with open(unfuzzed_filename, 'rb') as f:
        file_bytes = bytearray(f.read())
    # change first 4 bytes in dua to magic value

    if bug.type == BugKind.BUG_REL_WRITE:
        assert len(fuzz_labels_list) == 3  # Must have 3 sets of labels

        m = bug.magic
        a, b, c = 0, 0, 0

        if solution:
            a_val = solution[0]
            b_val = solution[1]
            c_val = solution[2]
        else:
            # If we don't have solutions from lavaTool, hope this code matches
            # lavaTool and generate non-ascii solutions here
            if m % NUM_BUGTYPES == 0:  # A + B = M * C
                b = m
                c = 1
                a = 0

            if m % NUM_BUGTYPES == 1:  # B = A*(C+M)
                a = 1
                c = 0
                b = m
            # C % M == M - A*2 NOT USING B, just a 2-dua
            if m % NUM_BUGTYPES == 2:
                a = 5
                c = m - 10
            # Intentional chaff bug - don't even bother
            if m % NUM_BUGTYPES == 3:
                pass

            a_val = struct.pack("<I", a)
            b_val = struct.pack("<I", b)
            c_val = struct.pack("<I", c)

        for i, offset in zip(range(4), fuzz_labels_list[0]):
            file_bytes[offset] = a_val[i]

        for i, offset in zip(range(4), fuzz_labels_list[1]):
            file_bytes[offset] = b_val[i]

        for i, offset in zip(range(4), fuzz_labels_list[2]):
            file_bytes[offset] = c_val[i]

    else:
        for fuzz_labels in fuzz_labels_list:
            for i, offset in zip(range(4), fuzz_labels):
                file_bytes[offset] = magic_val[i]

    with open(new_filename, 'wb') as fuzzed_f:
        fuzzed_f.write(file_bytes)


# run lavatool on this file to inject any parts of this list of bugs
def run_lavatool(bug_list: List[Bug], lp: LavaPaths, project: dict, filename: str,
                 knob_trigger=False, dataflow=False, competition=False,
                 randseed=0):
    lt_debug = False
    print("Running lavaTool on [{}]...".format(filename))
    if len(bug_list) == 0:
        print("\nWARNING: Running lavaTool but no bugs \
              selected for injection\n")
        print("Running with -debug to just inject data_flow")
        lt_debug = True

    db_name = project["db"]
    db_hostname = project['database']
    bug_list_str = ','.join([str(bug.id) for bug in bug_list])
    main_files = ','.join([os.path.join(str(lp.bugs_build), f) for f in project['main_file']])

    cmd = [
        lp.lava_tool, '-action=inject', '-bug-list=' + bug_list_str,
                                        '-src-prefix=' + lp.bugs_build,
                                        '-host=' + db_hostname,
                                        '-db=' + db_name,
                                        '-main-files=' + main_files,
                                        os.path.join(lp.bugs_build, filename)]

    # Todo either parameterize here or hardcode everywhere else
    # For now, lavaTool will only work if it has a whitelist, so we always pass this
    fninstr = os.path.join(project['directory'], project['name'], "fninstr")
    cmd.append('-lava-wl=' + str(fninstr))

    if lt_debug:
        cmd.append("-debug")
    if dataflow:
        cmd.append('-arg_dataflow')
    if knob_trigger > 0:
        cmd.append('-kt')
    if competition:
        cmd.append('-competition')
    if randseed:
        cmd.append('-randseed={}'.format(randseed))
    print("lavaTool command: {}".format(' '.join(cmd)))

    rv, output = run_cmd_notimeout(cmd, project)
    stdout, stderr = output
    stdout = stdout.decode("utf-8")
    stderr = stderr.decode("utf-8")
    log_dir = os.path.join(project["output_dir"], "logs")

    safe_file_name = filename.replace("/", "_").replace(".", "-")

    with open(os.path.join(log_dir, "lavaTool-{}-stdout.log"
            .format(safe_file_name)), "w") as f:
        f.write(stdout)

    with open(os.path.join(log_dir, "lavaTool-{}-stderr.log"
            .format(safe_file_name)), "w") as f:
        f.write(stderr)

    if rv != 0:
        print("ERROR: " + "=" * 20)
        print(stdout.replace("\\n", "\n"))
        print("=" * 20)
        print(stderr.replace("\\n", "\n"))
        print("\nFatal error: LavaTool crashed\n")
        assert False  # LavaTool failed

    # Get solutions back from lavaTool, parse and return
    # See, threeDuaTest in lavaTool.h, used for Bug::REL_WRITE
    solutions = {}
    for line in stdout.split("\n"):
        if line.startswith("SOL") and " == " in line:
            bug_id = line.split("0x")[1].split(" ")[0]
            bug_id = int(bug_id, 16)
            solutions[bug_id] = []
            vals = line.split("0x")[2:]  # Skip bug_id
            for val in vals:
                for idx, c in enumerate(val):
                    if c not in "0123456789abcdef":
                        val = val[:idx]
                        break
                if not len(val):
                    continue
                solutions[bug_id].append(struct.pack("<I", int(val, 16)))
    return solutions


# Given a list of bugs, return the IDs for a subset of bugs with
# `max_per_line` bugs on each line of source
def limit_atp_reuse(bugs: List[Bug], max_per_line: int = 1):
    uniq_bugs = []
    seen = {}
    for bug in bugs:
        tloc = (bug.atp_relationship.loc.filename, bug.atp_relationship.loc.begin.line)
        if tloc not in seen.keys():
            seen[tloc] = 0
        seen[tloc] += 1
        if seen[tloc] <= max_per_line:
            uniq_bugs.append(bug.id)
    print("Limited ATP reuse: Had {} bugs, now have {} with a "
          "max of {} per source line".format(len(bugs), len(uniq_bugs), max_per_line))
    return uniq_bugs


# Build a set of src/input files that we need to modify to inject these bugs
def collect_src_and_print(bugs_to_inject, db):
    src_files = set()

    for bug_index, bug in enumerate(bugs_to_inject):
        print("------------\n")
        print("SELECTED ")
        if bug.trigger_relationship.dua_relationship.fake_dua:
            print("NON-BUG")
        else:
            print("BUG {} id={}".format(bug_index, bug.id))
        print("    ATP file: ", bug.atp_relationship.loc.filename)
        print("        line: ", bug.atp_relationship.loc.begin.line)
        print("DUA:")
        print("   ", bug.trigger_relationship.dua_relationship)
        print("      Src_file: ", bug.lval_relationship.loc.filename)
        print("      Filename: ", bug.trigger_relationship.dua_relationship.inputfile)

        if len(bug.extra_duas):
            print("EXTRA DUAS:")
            for extra_id in bug.extra_duas:
                dua_bytes = db.session.query(DuaBytes).filter(DuaBytes.id == extra_id).first()
                if dua_bytes is None:
                    raise RuntimeError("Bug {} references DuaBytes {} which does not exist" \
                                       .format(bug.id, extra_id))
                print("  ", extra_id, "   @   ", dua_bytes.dua)
                print("     Src_file: ", dua_bytes.dua.lval.loc.filename)

                # Add filenames for extra_duas into src_files and input_files
                # Note this is the file _name_ not the path
                file_name = dua_bytes.dua.lval.loc.filename
                if os.path.sep in file_name:
                    file_name = file_name.split(os.path.sep)[1]
                src_files.add(file_name)
                # input_files.add(lval.inputfile)

        print("ATP:")
        print("   ", bug.atp)
        print("max_tcn={}  max_liveness={}".format(
            bug.trigger_relationship.dua_relationship.max_tcn, bug.max_liveness))
        src_files.add(bug.lval_relationship.loc.filename)
        src_files.add(bug.atp_relationship.loc.filename)
    sys.stdout.flush()
    return src_files


def get_suffix(fn: str) -> str:
    split = os.path.basename(fn).split(".")
    if len(split) == 1:
        return ""
    else:
        return "." + split[-1]


# run the bugged-up program
def run_modified_program(project: dict, install_dir: str, input_file: str,
                         timeout: int, shell: bool= False):
    cmd = project['command'].format(install_dir=install_dir,
                                    input_file=input_file)
    # cmd = "{}".format(cmd) # ... this is a nop?
    # cmd = '/bin/bash -c '+ pipes.quote(cmd)
    envv = {}

    # If library path specified, set env var
    lib_path = project.get('library_path', '')
    if len(lib_path):
        lib_path = lib_path.format(install_dir=install_dir)
        envv["LD_LIBRARY_PATH"] = os.path.join(install_dir, lib_path)

        print("Run modified program: LD_LIBRARY_PATH={} {}"
              .format(os.path.join(install_dir, lib_path), cmd))
    else:
        print("Run modified program: {}".format(cmd))

    # Command might be redirecting input file in so we need shell=True
    return run_cmd(cmd, project, envv, timeout, cwd=install_dir, shell=shell)


# Find actual line number of attack point for this bug in source
def get_trigger_line(lp: LavaPaths, bug: Bug) -> int | None:
    # TODO the triggers aren't a simple mapping from trigger of 0xlava - bug_id
    # But are the lava_get's still correlated to triggers?
    with open(os.path.join(lp.bugs_build, bug.atp_relationship.loc.filename), "r") as f:
        # TODO: should really check for lava_get(bug_id), but bug_id in db
        # isn't matching source for now, we'll just look for "(0x[magic]" since
        # that seems to always be there, at least for old bug types
        lava_get = "(0x{:x}".format(bug.magic)
        atp_lines = [line_num + 1 for line_num, line in enumerate(f) if
                     lava_get in line]  # and "lava_get" in line
        # return closest to original begin line.
        distances = [
            (abs(line - bug.atp_relationship.loc.begin.line), line) for line in atp_lines
        ]
        if not distances:
            return None
        return min(distances)[1]


def check_competition_bug(rv: int, output):
    assert len(output) == 2
    output, error = output

    if (rv % 256) <= 128:
        print("Clean exit (code {})".format(rv))
        return []  # No bugs unless you crash it

    # LAVALOG writes out to stderr
    return process_crash(error)


def unfuzzed_input_for_bug(project: dict) -> list[str]:
    """
    Get the path to the original unfuzzed input file for this bug
    Args:
        project: The project dictionary
    Returns:
        list of all input files
    """
    all_files = []
    for file in os.listdir(os.path.join(project["output_dir"], 'inputs')):
        path = os.path.join(project["output_dir"], 'inputs', file)
        # TODO: I think we should have different folders for initial inputs and good fuzzed inputs
        if os.path.isfile(path) and "-fuzzed-" not in file:
            all_files.append(path)
    return all_files


def fuzzed_input_for_bug(project: dict, bug: Bug) -> str:
    """
    Generate a fuzzed input filename for this bug.
    Select one file at random from the unfuzzed inputs.
    Args:
        project: The project dictionary
        bug: Bug object
    Returns:
        The filename for the fuzzed input for this bug
    """
    unfuzzed_inputs = unfuzzed_input_for_bug(project)
    unfuzzed_input = random.choice(unfuzzed_inputs)
    suffix = get_suffix(unfuzzed_input)
    prefix = unfuzzed_input[:-len(suffix)] if suffix != "" else unfuzzed_input
    return "{}-fuzzed-{}{}".format(prefix, bug.id, suffix)


def validate_bug(db, lp: LavaPaths, project: dict, bug: Bug, build: Build, arguments, update_db: bool,
                 unfuzzed_outputs=None, competition: bool = False, solution=None):
    unfuzzed_input_files = unfuzzed_input_for_bug(project)
    unfuzzed_input_file = random.choice(unfuzzed_input_files)
    fuzzed_input_file_name = fuzzed_input_for_bug(project, bug)
    print(str(bug))
    print("fuzzed = [%s]" % fuzzed_input_file_name)
    mutfile_kwargs = {}
    if arguments.knobTrigger:
        print("Knob size: {}".format(arguments.knobTrigger))
        mutfile_kwargs = {'kt': True, 'knob': arguments.knobTrigger}

    fuzz_labels_list = [bug.trigger_relationship.all_labels]
    if len(bug.extra_duas) > 0:
        extra_query = db.session.query(DuaBytes) \
            .filter(DuaBytes.id.in_(bug.extra_duas))
        fuzz_labels_list.extend([d.all_labels for d in extra_query])
    mutfile(unfuzzed_input_file, fuzz_labels_list, fuzzed_input_file_name, bug,
            solution=solution, **mutfile_kwargs)
    timeout = project.get('timeout', 5)
    rv, output = run_modified_program(project, lp.bugs_install,
                                      fuzzed_input_file_name, timeout, shell=True)
    print("retval = %d" % rv)
    validated = False
    if not bug.trigger_relationship.dua_relationship.fake_dua:
        print("bug type is " + Bug.type)
        if bug.type == BugKind.BUG_PRINTF_LEAK:
            if output != unfuzzed_outputs[bug.trigger_relationship.dua_relationship.inputfile]:
                print("printf bug -- outputs disagree\n")
                validated = True
        else:
            # this really is supposed to be a bug
            # we should see a seg fault or something
            # NB: Wrapping programs in bash transforms rv -> 128 - rv,
            # so we do the mod
            if (rv % 256) > 128 and rv != -9:  # check and ignoring timeouts
                print("RV indicates memory corruption")
                # Default: not checking that bug manifests at same line as
                # trigger point or is found by competition grading
                # infrastructure
                validated = True
                if competition:
                    found_bugs = check_competition_bug(rv, output)
                    if set(found_bugs) == {bug.id}:
                        print("... and competition infrastructure agrees")
                        validated &= True
                    else:
                        validated &= False
                        print("... but competition infrastructure"
                              " misidentified it ({} vs {})".format(found_bugs, bug.id))
            else:
                print("RV does not indicate memory corruption")
                validated = False
    else:
        # this really is supposed to be a non-bug
        # we should see a 0
        print("RV is zero which is good b/c this used a fake dua")
        assert rv == 0
        validated = False

    if update_db:
        db.session.add(Run(build_relationship=build, fuzzed_relationship=bug, exitcode=rv,
                           output=(output[0].decode('ascii', 'ignore') + '\n' + output[1].decode('ascii', 'ignore')),
                           success=True, validated=validated))

    return validated


# validate this set of bugs
def validate_bugs(bug_list, db, lp, project: dict, input_files: list, build,
                  arguments, update_db: bool, competition: bool = False, bug_solutions=None):
    timeout = project.get('timeout', 5)

    print("------------\n")
    # first, try the original files
    print("TESTING -- ORIG INPUT")
    print(bug_list)
    print("------------\n")
    unfuzzed_outputs = {}
    for input_file in input_files:
        unfuzzed_input = os.path.join(project["output_dir"],
                              'inputs', os.path.basename(input_file))
        rv, output = run_modified_program(project, lp.bugs_install,
                                          str(unfuzzed_input), timeout, shell=True)
        unfuzzed_outputs[os.path.basename(input_file)] = output
        if rv != arguments.exitCode:
            print("***** buggy program fails on original input - \
                  Exit code {} does not match expected {}"
                  .format(rv, arguments.exitCode))
            print(output[0].decode('utf-8'))
            print()
            print(output[1].decode('utf-8'))
            assert False  # Fails on original input
        else:
            print("buggy program succeeds on original input {}"
                  "with exit code {}".format(input_file, rv))
        print("output:")
        lines = output[0].decode('ascii') + " ; " + output[1].decode('ascii')
        if update_db:
            db.session.add(Run(build_relationship=build, fuzzed=None, exitcode=rv,
                               output=lines,
                               success=True, validated=False))
    print("ORIG INPUT STILL WORKS\n")

    # second, try each of the fuzzed inputs and validate
    print("TESTING -- FUZZED INPUTS")
    real_bugs = []
    bugs_to_inject = db.session.query(Bug).filter(Bug.id.in_(bug_list)).all()
    for bug_index, bug in enumerate(bugs_to_inject):
        print("=" * 60)
        print("Validating bug {} of {} ".format(
            bug_index + 1, len(bugs_to_inject)))

        # We should always have solutions for multi-dua bugs
        if bug_solutions and bug.id in bug_solutions.keys():
            validated = validate_bug(db, lp, project, bug, build,
                                     arguments, update_db, unfuzzed_outputs,
                                     competition=competition,
                                     solution=bug_solutions[bug.id])
        else:
            print("No known solution for bug with id={}".format(bug.id))
            validated = validate_bug(db, lp, project, bug, build,
                                     arguments, update_db, unfuzzed_outputs,
                                     competition=competition)
        if validated:
            real_bugs.append(bug.id)
        print()
    # This is assert is needed in case injection fails to plant a bug, especially 50 times, should be flagged.
    assert len(real_bugs) > 0
    if len(bugs_to_inject) > 0:
        f = float(len(real_bugs)) / len(bugs_to_inject)
        print(u"yield {:.2f} ({} out of {}) real bugs (95% CI +/- {:.2f}) "
              .format(f, len(real_bugs), len(bugs_to_inject),
                      1.96 * math.sqrt(f * (1 - f) / len(bugs_to_inject))))
        print("A BOUNTIFUL CROP OF BUGS: %s" % (",".join(map(str, real_bugs))))
    else:
        print("yield to me")
    print("TESTING COMPLETE")

    if update_db:
        db.session.commit()

    return real_bugs


def process_crash(buf: str):
    """
    Process a buffer of output from target program
    Identify all LAVALOG lines

    returns list of bug_ids (ints) seen
    """
    bugs = []

    def get_bug_id(line_iterator: str):
        if len(line_iterator.split(":")) > 2:
            return int(line_iterator.split(": ")[1].split(": ")[0])
        return None

    for line in buf.split("\n"):
        if line.startswith("LAVALOG:"):
            bug_id = get_bug_id(line)
            if bug_id:
                bugs.append(bug_id)

    return bugs


def main(arguments: argparse.Namespace):
    project = parse_vars(arguments.project_name)
    dataflow = project.get("dataflow", False)

    allowed_bugtypes = get_allowed_bugtype_num(arguments)

    print("allowed bug types: " + (str(allowed_bugtypes)))

    # Set various paths
    lp = LavaPaths(project)
    db = LavaDatabase(project)

    os.makedirs(lp.bugs_top_dir, exist_ok=True)

    # this is where buggy source code will be
    get_bugs_parent(lp)

    # Remove all old YAML files
    run_cmd(["rm -f {}/*.yaml".format(lp.bugs_build)], project, None, 10, cwd="/", shell=True)

    # obtain list of bugs to inject based on cmd-line args and consulting db
    update_db, bug_list = get_bug_list(arguments, db, allowed_bugtypes)

    # add all those bugs to the source code and check that it compiles
    # TODO use bug_solutions and make inject_bugs return solutions for single-dua bugs?
    build, input_files, bug_solutions = inject_bugs(bug_list, db, lp,
                                                    project, arguments, update_db, dataflow=dataflow,
                                                    competition=arguments.competition)
    if build is None:
        raise RuntimeError("LavaTool failed to build target binary")

    try:
        # determine which of those bugs actually cause a seg fault
        real_bug_list = validate_bugs(bug_list, db, lp, project, input_files, build, arguments, update_db)

        def count_bug_types(id_list: list[int]):
            type_count = {}
            bug_dict = {}
            for bug in get_bugs(db, id_list):
                if not bug.type in type_count:
                    type_count[bug.type] = 0
                    bug_dict[bug.type] = []
                type_count[bug.type] += 1
                bug_dict[bug.type].append(bug.id)
            for t in type_count.keys():
                print("%d c(%s)=%d" % (t, BugKind(t).name, type_count[t]))
                print(str(bug_dict[t]))

        print("\nBug types in original, potential set")
        count_bug_types(bug_list)

        print("\nBug types in validated set")
        count_bug_types(real_bug_list)

    except Exception as e:
        print("TESTING FAIL")
        if update_db:
            db.session.add(Run(build_relationship=build, fuzzed=None, exitcode=-22,
                               output=str(e), success=False, validated=False))
            db.session.commit()
        raise

    print("inject complete %.2f seconds" % (time.time() - start_time))


if __name__ == "__main__":
    parent = get_inject_parser()
    parser = argparse.ArgumentParser(parents=[parent], description='Inject and test LAVA bugs.')
    parser.add_argument('-p', '--project_name', help='Project name')
    args = parser.parse_args()
    main(args)
