import math
import os
import shlex
import struct
import subprocess
import sys
import random
from subprocess import PIPE, check_call
from inject.process_compile_commands import get_c_files, process_compile_commands
from dotenv import load_dotenv
from utils.database_types import Bug, DuaBytes, Build, Run, BugKind, AtpKind
import argparse
from utils.vars import parse_vars

load_dotenv()
NUM_BUGTYPES = 3  # Make sure this matches what's in lavaTool


def parse_lava_args():
    parser = argparse.ArgumentParser(
        description="LAVA: Large-scale Automated Vulnerability Addition",
        usage="%(prog)s [options] [ProjectConfig]",
        add_help=False  # We will handle help manually to match your USAGE
    )

    # --- Common Options ---
    common = parser.add_argument_group("Common Options")
    common.add_argument("-h", "--help", action="store_true")
    common.add_argument("-a", "--all", action="store_true", help="Run all lava steps")
    common.add_argument("-k", "--force", action="store_true", help="Delete old data without confirmation")
    common.add_argument("-n", "--count", type=int, default=50, help="Number of bugs to inject at once")
    common.add_argument("-y", "--bug-types", default="ptr_add,rel_write,malloc_off_by_one",
                        help="Comma separated list of bug types")
    common.add_argument("-b", "--atp-type", choices=["mem_read", "fn_arg", "mem_write"],
                        help="Specify a single ATP type")

    # --- Step Flags ---
    steps = parser.add_argument_group("Specify Steps to Run")
    steps.add_argument("-r", "--reset", action="store_true", help="Run reset step")
    steps.add_argument("-c", "--clean", action="store_true", help="Run clean step (DB only)")
    steps.add_argument("-q", "--add-queries", action="store_true", help="Run add queries step")
    steps.add_argument("-m", "--make", action="store_true", help="Run make step")
    steps.add_argument("-t", "--taint", action="store_true", help="Run taint step")
    steps.add_argument("-i", "--inject", type=int, metavar="NUM_TRIALS",
                       help="Run inject step with specified number of trials")

    # --- Expert/Dev Options ---
    expert = parser.add_argument_group("Expert only options")
    expert.add_argument("--demo", action="store_true", help="Run lava demo")
    expert.add_argument("--test-data-flow", action="store_true", help="Inject data-flow only, 0 bugs")
    expert.add_argument("--curtail", type=int, default=0, help="Curtail bug-finding after count bugs")
    expert.add_argument("--enable-knob-trigger", help="Enable knob trigger")

    # --- Backwards Compatibility / Combined Flags ---
    # Argparse doesn't natively do '-ak', so we check sys.argv for it later
    # or define it as a hidden action.
    expert.add_argument("-ak", action="store_true", help=argparse.SUPPRESS)

    # --- Positional ---
    parser.add_argument("project_name", nargs='?', help="Name of the project or path to JSON")

    # If no args, show help
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    # Handle the help flag manually to match your exit behavior
    if args.help:
        parser.print_help()
        sys.exit(0)

    # --- Custom Logic Mapping (Replacing the 'case' logic in Bash) ---

    # Handle -ak and --all shortcuts
    if args.ak or args.all:
        args.reset = True
        args.clean = True
        args.add_queries = True
        args.make = True
        args.taint = True
        args.inject = 3 if args.inject is None else args.inject
        if args.ak:
            args.force = True

    # Handle positional project_name shorthand (lava.sh ProjectName)
    # Your bash script allowed: lava.sh myproject (with no flags)
    if len(sys.argv) == 2 and not sys.argv[1].startswith("-"):
        args.reset = True
        args.clean = True
        args.add_queries = True
        args.make = True
        args.taint = True
        args.inject = 3
        args.project_name = sys.argv[1]

    # Handle --test-data-flow logic
    if args.test_data_flow:
        args.inject = 1
        args.count = 0

    return args


def run_cmd(cmd, project, envv=None, timeout=30, cwd=None, shell=False):
    if type(cmd) in [str] and not shell:
        cmd = shlex.split(cmd)

    if project['debug']:
        env_string = ""
        if envv:
            env_string = " ".join(["{}='{}'".format(k, v)
                                   for k, v in envv.items()])
        if type(cmd) == list:
            print("run_cmd(" + env_string + " " +
                  subprocess.list2cmdline(cmd) + ")")
        else:
            print("run_cmd(" + env_string + " " +
                  cmd + ")")
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
        assert (knob < 2 ** 16 - 1)
        bug_trigger = bug.magic & 0xffff
        magic_val = struct.pack("<I", (knob << 16) | bug_trigger)
    else:
        magic_val = struct.pack("<I", bug.magic)
    # collect set of tainted offsets in file.
    with open(unfuzzed_filename, 'rb') as f:
        file_bytes = bytearray(f.read())
    # change first 4 bytes in dua to magic value

    if bug.type == BugKind.BUG_REL_WRITE:
        assert (len(fuzz_labels_list) == 3)  # Must have 3 sets of labels

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
def run_lavatool(bug_list, lp, project, filename,
                 knobTrigger=False, dataflow=False, competition=False,
                 randseed=0):
    lt_debug = False
    print("Running lavaTool on [{}]...".format(filename))
    if (len(bug_list)) == 0:
        print("\nWARNING: Running lavaTool but no bugs \
              selected for injection\n")
        print("Running with -debug to just inject data_flow")
        lt_debug = True

    db_name = project["db"]
    db_hostname = project['database']
    bug_list_str = ','.join([str(bug.id) for bug in bug_list])
    main_files = ','.join([os.path.join(lp.bugs_build, f)
                           for f in project['main_file']])

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
    cmd.append('-lava-wl=' + fninstr)

    if lt_debug:
        cmd.append("-debug")
    if dataflow:
        cmd.append('-arg_dataflow')
    if knobTrigger > 0:
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


class LavaPaths(object):

    def __init__(self, project):
        self.top_dir = project['output_dir']
        self.lava_dir = os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0])))
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

    def __str__(self):
        rets = ""
        rets += "top_dir =       %s\n" % self.top_dir
        rets += "lavadb =        %s\n" % self.lavadb
        rets += "lava_dir =      %s\n" % self.lava_dir
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
        self.bugs_install = os.path.join(self.bugs_build, 'lava-install')


# Given a list of bugs, return the IDs for a subset of bugs with
# `max_per_line` bugs on each line of source
def limit_atp_reuse(bugs, max_per_line=1):
    uniq_bugs = []
    seen = {}
    for bug in bugs:
        tloc = (bug.atp.loc.filename, bug.atp.loc.begin.line)
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
        if bug.trigger.dua.fake_dua:
            print("NON-BUG")
        else:
            print("BUG {} id={}".format(bug_index, bug.id))
        print("    ATP file: ", bug.atp.loc.filename)
        print("        line: ", bug.atp.loc.begin.line)
        print("DUA:")
        print("   ", bug.trigger.dua)
        print("      Src_file: ", bug.trigger_lval.loc.filename)
        print("      Filename: ", bug.trigger.dua.inputfile)

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
            bug.trigger.dua.max_tcn, bug.max_liveness))
        src_files.add(bug.trigger_lval.loc.filename)
        src_files.add(bug.atp.loc.filename)
    sys.stdout.flush()
    return src_files


# inject this set of bugs into the source place the resulting bugged-up
# version of the program in bug_dir
def inject_bugs(bug_list, db, lp, project, args,
                update_db, dataflow=False, competition=False,
                validated=False, lavatoolseed=0):
    # TODO: don't pass args, just pass the data we need to run
    # TODO: split into multiple functions, this is huge

    if not os.path.exists(lp.bugs_parent):
        os.makedirs(lp.bugs_parent)

    print("source_root = " + lp.source_root + "\n")

    # Make sure directories and btrace is ready for bug injection.
    def run(args, **kwargs):
        print("run(", subprocess.list2cmdline(args), ")")
        check_call(args, cwd=lp.bugs_build, **kwargs)

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
    try:
        dataflow |= args.arg_dataflow
    except Exception:  # arg_dataflow missing from args which is okay
        pass

    
    if not os.path.exists(os.path.join(lp.bugs_build, 'compile_commands.json')):
        run([os.path.join(lp.lava_dir, 'scripts', 'add_queries/sw-btrace-to-compiledb.py'),
             os.path.join(project["llvm-dir"], "lib/clang", project["llvm-version"], "include")])
        # also insert instr for main() fn in all files that need it

        process_compile_commands(
            os.path.join(lp.bugs_build, 'compile_commands.json'),
            os.path.join(lp.bugs_top_dir, '../extra_compile_commands.json')
        )

        run(['git', 'add', '-f', 'compile_commands.json'])
        run(['git', 'commit', '-m', 'Add compile_commands.json.'])
        # for make_cmd in project['make'].split('&&'):
        #    run(shlex.split(make_cmd))
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

        # for make_cmd in project['make'].split('&&'):
        #    run(shlex.split(make_cmd))
        run(shlex.split(project['make']))
        run(['find', '.', '-name', '*.[ch]', '-exec', 'git', 'add', '{}', ';'])
        try:
            run(['git', 'commit', '-m',
                 'Adding any make-generated source files'])
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
        return run_lavatool(bugs_to_inject, lp, project, directory_name, knobTrigger=args.knobTrigger,
                            dataflow=dataflow, competition=competition, randseed=lavatoolseed)

    bug_solutions = {}  # Returned by lavaTool

    for filename in all_files:
        # TODO call on directories instead of each file,
        # but still store results in bug_solutions
        bug_solutions.update(modify_source(filename))

    # TODO: Use our ThreadPool for modifying source and update bug_solutions
    # with results instead of single-thread
    # if pool:
    # pool.map(modify_source, all_files)
    clang_apply = os.path.join(project['llvm-dir'], 'bin', 'clang-apply-replacements')

    src_dirs = set()
    src_dirs.add("")  # Empty path for root
    for filename in all_files:
        src_dir = os.path.dirname(filename)
        if len(src_dir):
            src_dirs.add(src_dir.encode("ascii", "ignore"))

    # TODO use pool here as well

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

    # Ugh.  Lavatool very hard to get right
    # Permit automated fixups via script after bugs inject
    # but before make. TODO: consolidate these arguments into project.keys
    if "injfixupsscript" in project.keys():
        print("Running injfixupsscript: {}"
              .format(project["injfixupsscript"]
                      .format(bug_build=lp.bugs_build), cwd=lp.bugs_build))
        run_cmd(project["injfixupsscript"]
                .format(bug_build=lp.bugs_build), project, cwd=lp.bugs_build)

    if hasattr(args, "fixupscript"):
        print("Running fixupscript: {}"
              .format(args.fixupscript.format(bug_build=lp.bugs_build),
                      cwd=lp.bugs_build))
        run_cmd(args.fixupsscript.format(bug_build=lp.bugs_build), project,
                cwd=lp.bugs_build)

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

    build = Build(compile=(rv == 0), output=(output[0].decode('utf-8') + ";" + output[1].decode('utf-8')), bugs=bugs_to_inject)

    # add a row to the build table in the db
    if update_db:
        db.session.add(build)
        db.session.commit()
        assert build.id is not None
        try:
            run(['git', 'commit', '-am', 'Bugs for build {}.'.format(build.id)])
        except Exception:
            print("\nFatal error: git commit failed! \
                  This may be caused by lavaTool not modifying anything")
            raise

        run(['git', 'branch', 'build' + str(build.id), 'master'])
        run(['git', 'reset', 'HEAD~', '--hard'])

    return build, input_files, bug_solutions


def get_suffix(fn):
    split = os.path.basename(fn).split(".")
    if len(split) == 1:
        return ""
    else:
        return "." + split[-1]


# run the bugged-up program
def run_modified_program(project, install_dir, input_file,
                         timeout, shell=False):
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
def get_trigger_line(lp, bug):
    # TODO the triggers aren't a simple mapping from trigger of 0xlava - bug_id
    # But are the lava_get's still correlated to triggers?
    with open(os.path.join(lp.bugs_build, bug.atp.loc.filename), "r") as f:
        # TODO: should really check for lava_get(bug_id), but bug_id in db
        # isn't matching source for now, we'll just look for "(0x[magic]" since
        # that seems to always be there, at least for old bug types
        lava_get = "(0x{:x}".format(bug.magic)
        atp_lines = [line_num + 1 for line_num, line in enumerate(f) if
                     lava_get in line]  # and "lava_get" in line
        # return closest to original begin line.
        distances = [
            (abs(line - bug.atp.loc.begin.line), line) for line in atp_lines
        ]
        if not distances:
            return None
        return min(distances)[1]


def check_competition_bug(rv: int, output):
    assert (len(output) == 2)
    (out, err) = output

    if (rv % 256) <= 128:
        print("Clean exit (code {})".format(rv))
        return []  # No bugs unless you crash it

    # LAVALOG writes out to stderr
    return process_crash(err)


# use gdb to get a stacktrace for this bug
def check_stacktrace_bug(lp, project, bug, fuzzed_input):
    gdb_py_script = os.path.join(lp.lava_dir, "scripts/stacktrace_gdb.py")
    lib_path = project.get('library_path', '{install_dir}/lib')
    lib_path = lib_path.format(install_dir=lp.bugs_install)
    envv = {"LD_LIBRARY_PATH": lib_path}
    cmd = project['command'] \
        .format(install_dir=lp.bugs_install, input_file=fuzzed_input)
    gdb_cmd = "gdb --batch --silent -x {} --args {}".format(gdb_py_script, cmd)
    (rc, (out, err)) = run_cmd(gdb_cmd, project, cwd=lp.bugs_install, envv=envv)
    if project['debug']:
        for line in out.splitlines():
            print(line)
        for line in err.splitlines():
            print(line)
    prediction = " at {}:{}".format(os.path.basename(bug.atp.loc.filename),
                                    get_trigger_line(lp, bug))
    print("Prediction {}".format(prediction))
    for line in out.splitlines():
        if bug.type == BugKind.BUG_RET_BUFFER:
            # These should go into garbage code if they trigger.
            if line.startswith("#0") and line.endswith(" in ?? ()"):
                return True
        elif bug.type == BugKind.BUG_PRINTF_LEAK:
            # FIXME: Validate this!
            return True
        else:  # PTR_ADD or REL_WRITE for now.
            if line.startswith("#0") or \
                    bug.atp.typ == AtpKind.FUNCTION_CALL:
                # Function call bugs are valid if they happen anywhere in
                # call stack.
                if line.endswith(prediction):
                    return True

    return False


def unfuzzed_input_for_bug(project) -> list:
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


def fuzzed_input_for_bug(project, bug) -> str:
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


def validate_bug(db, lp, project, bug, build, args, update_db,
                 unfuzzed_outputs=None, competition=False, solution=None):
    unfuzzed_input_files = unfuzzed_input_for_bug(project)
    unfuzzed_input_file = random.choice(unfuzzed_input_files)
    fuzzed_input_file_name = fuzzed_input_for_bug(project, bug)
    print(str(bug))
    print("fuzzed = [%s]" % fuzzed_input_file_name)
    mutfile_kwargs = {}
    if args.knobTrigger:
        print("Knob size: {}".format(args.knobTrigger))
        mutfile_kwargs = {'kt': True, 'knob': args.knobTrigger}

    fuzz_labels_list = [bug.trigger.all_labels]
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
    if bug.trigger.dua.fake_dua is False:
        print("bug type is " + Bug.type)
        if bug.type == BugKind.BUG_PRINTF_LEAK:
            if output != unfuzzed_outputs[bug.trigger.dua.inputfile]:
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
                if args.checkStacktrace:
                    if check_stacktrace_bug(lp, project, bug, fuzzed_input_file_name):
                        print("... and stacktrace agrees with trigger line")
                        validated &= True
                    else:
                        print("... but stacktrace disagrees with trigger line")
                        validated &= False
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
        db.session.add(Run(build=build, fuzzed=bug, exitcode=rv,
                           output=(output[0].decode('ascii', 'ignore') + '\n' + output[1].decode('ascii', 'ignore')),
                           success=True, validated=validated))

    return validated


# validate this set of bugs
def validate_bugs(bug_list, db, lp, project, input_files, build,
                  args, update_db, competition=False, bug_solutions=None):
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
                                          unfuzzed_input, timeout, shell=True)
        unfuzzed_outputs[os.path.basename(input_file)] = output
        if rv != args.exitCode:
            print("***** buggy program fails on original input - \
                  Exit code {} does not match expected {}"
                  .format(rv, args.exitCode))
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
            db.session.add(Run(build=build, fuzzed=None, exitcode=rv,
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
                                     args, update_db, unfuzzed_outputs,
                                     competition=competition,
                                     solution=bug_solutions[bug.id])
        else:
            print("No known solution for bug with id={}".format(bug.id))
            validated = validate_bug(db, lp, project, bug, build,
                                     args, update_db, unfuzzed_outputs,
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


def get_bugs(db, bug_id_list):
    bugs = []
    for bug_id in bug_id_list:
        bugs.append(db.session.query(Bug).filter(Bug.id == bug_id).all()[0])
    return bugs


def get_allowed_bugtype_num(args) -> list[int]:
    allowed_bugtype_nums = []

    # Safety check if arg is empty
    if not args.bugtypes:
        return allowed_bugtype_nums

    for bugtype_name in args.bugtypes.split(","):
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


def lava_main():
    # 1. Parse arguments using the logic we refactored
    args = parse_lava_args()

    # 2. Handle the "Can of Worms": Remote/Docker logic
    # Since you're sticking to local CI/CD for now, we just verify
    if args.force:
        print(f"DEBUG: Force flag detected. Proceeding with deletions...")

    # 3. Step Dispatcher
    # This replaces the 'if [ $add_queries -eq 1 ]' blocks in lava.sh

    if args.reset:
        print(">>> Starting Reset Step")
        # For now, put reset logic here or in a small helper in queries.py
        # Porting 'deldir' and 'RESET_DB' logic

    if args.add_queries:
        print(">>> Starting Add Queries Step")
        # We pass the 'args' object directly so QueryManager
        # has everything (atp_type, project_name, etc.)
        # qm = QueryManager(args)
        # qm.step_add_queries()

    if args.taint:
        print(">>> Starting Taint Step (PANDA)")
        # This will eventually call your refactored bug_mining.py

    if args.inject:
        print(f">>> Starting Injection Step ({args.inject} trials)")
        # Loop trials as seen in lava.sh
        for i in range(1, args.inject + 1):
            print(f"--- Trial {i} ---")
            # Call your refactored inject.py logic

    print(">>> All requested LAVA steps finished.")


if __name__ == "__main__":
    lava_main()
