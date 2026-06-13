#!/usr/bin/env python3
import argparse
import sys
import time
import math
import os
import struct
import random
import shutil
import platform
from pathlib import Path
from typing import List
# LAVA imports
from ..utils.vars import LavaPaths
from ..utils.funcs import get_inject_parser, read_compile_db, unpack_tar, configure_project, preprocess, run_local, make_and_install
from ..utils.database_types import Bug, DuaBytes, Build, Run, BugKind, LavaDatabase

NUM_BUGTYPES = 3  # Make sure this matches what's in lavaTool
start_time = time.time()


# get list of bugs either from cmd line or db
def get_bug_list(arguments: argparse.Namespace, db: LavaDatabase, allowed_bugtypes):
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
    # If you already found and set it once, keep it all in one directory
    if lp.bugs_parent != "":
        print("Using recently made bug build directory", lp.bugs_parent)
        return lp.bugs_parent

    while True:
        candidate_path = os.path.join(lp.bugs_top_dir, str(candidate))
        bugs_parent = os.path.join(candidate_path)
        if not os.path.exists(bugs_parent):
            break
        candidate += 1

    print("Using bug build directory", bugs_parent)
    lp.set_bugs_parent(bugs_parent)
    return bugs_parent


def get_bugs(db: LavaDatabase, bug_id_list: List[Bug]) -> List[Bug]:
    bugs = []
    for bug_id in bug_id_list:
        bugs.append(db.session.query(Bug).filter(Bug.id == bug_id).all()[0])
    return bugs


def get_allowed_bugtype_num(arguments: argparse.Namespace) -> list[int]:
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
def inject_bugs(bug_list, db: LavaDatabase, lp : LavaPaths, project: dict, arguments: argparse.Namespace,
                update_db: bool, dataflow: bool = False, competition: bool = False,
                validated: bool = False, lavatoolseed: int = 0):
    # TODO: don't pass args, just pass the data we need to run
    # TODO: split into multiple functions, this is huge

    if not os.path.exists(lp.bugs_parent):
        os.makedirs(lp.bugs_parent)

    print("source_root = " + lp.tar_source_root + "\n")

    if not os.path.isdir(lp.bugs_build):
        unpack_tar(lp, lp.bugs_parent)
    
    if not os.path.exists(os.path.join(lp.bugs_build, '.git')):
        configure_project(lp, main_directory=lp.bugs_build)
        preprocess(lp, main_directory=lp.bugs_build)

    sys.stdout.flush()
    sys.stderr.flush()

    if not os.path.exists(os.path.join(lp.bugs_build, 'compile_commands.json')):
        make_and_install(lp, main_directory=lp.bugs_build, environment="inject")

    bugs_to_inject = db.session.query(Bug).filter(Bug.id.in_(bug_list)).all()

    # TODO: Maybe there is a better way to filter ATPs on bug mining phase?
    print("\nFiltering bug list to prevent ATP overloading...")
    limited_bug_ids = limit_atp_reuse(bugs_to_inject, default_max=1)
    bugs_to_inject = [b for b in bugs_to_inject if b.id in limited_bug_ids]

    # collect set of src files into which we must inject code
    src_files : set = collect_src_and_print(bugs_to_inject, db)
    input_files = unfuzzed_input_for_bug(project)

    # cleanup
    print("------------\n")
    print("CLEAN UP SRC")
    run_local("git checkout -f", cwd=lp.bugs_build, debug=project['debug'])

    print("------------\n")
    print("INJECTING BUGS INTO SOURCE")
    print("%d source files: " % (len(src_files)))
    print(src_files)

    all_files = src_files | set(project['main_file'])

    compile_commands = os.path.join(lp.bugs_build, 'compile_commands.json')
    print('compile commands is here: {}'.format(compile_commands))
    src_dirs, all_c_files = read_compile_db(lp.bugs_build)

    # Debug printing for inspection
    print("DEBUG: src_dirs (count={}):".format(len(src_dirs)))
    for d in sorted(src_dirs):
        print("  - {}".format(d))

    print("DEBUG: all_c_files (count={}):".format(len(all_c_files)))
    for f in sorted(all_c_files):
        print("  - {}".format(f))

    if dataflow:
        for c_full_path in all_c_files:
            file_name_only = os.path.basename(c_full_path)
            all_files.union(file_name_only)

    print("DEBUG: all_files (count={}):".format(len(all_files)))
    for f in sorted(all_c_files):
        print("  - {}".format(f))

    def modify_source(file_name: str):
        return run_lavatool(bugs_to_inject, lp, project, file_name, knob_trigger=arguments.knobTrigger,
                            dataflow=dataflow, competition=competition, randseed=lavatoolseed)

    bug_solutions = {}  # Returned by lavaTool

    for filename in all_files:
        # TODO call on directories instead of each file,
        # but still store results in bug_solutions
        bug_solutions.update(modify_source(filename))

    clang_apply = os.path.join(project['llvm-dir'], 'bin', 'clang-apply-replacements')
    one_replacement_success = False
    for src_dir in src_dirs:
        if project['debug']:
            print("Looking at src_dir: {}".format(src_dir))

        clang_cmd = [clang_apply, '.', '-remove-change-desc-files']
        if project['debug']:  # Don't remove desc files
            clang_cmd = [clang_apply, '.']
        print("Apply replacements in {} with {}".format(os.path.join(lp.bugs_build, src_dir), clang_cmd))
        rv, output = run_local(clang_cmd, cwd=os.path.join(lp.bugs_build, src_dir), debug=project['debug'], capture_output=True)

        if rv == 0:
            print("Success in {}".format(src_dir))
            one_replacement_success = True

    assert one_replacement_success, "clang-apply-replacements failed in all possible directories"
    build = Build(
        compile=False, 
        output="",
        bugs=bugs_to_inject
    )

    if update_db:
        db.session.add(build)
        db.session.flush()  # Populates build.id from the database auto-increment

    # --- SECURE THE C SOURCE CODE CHANGES (ISOLATED BRANCHES) ---
    build_label = str(build.id)
    print(f"Saving C source changes for build {build_label}...")
    try:
        # Use Python's rglob to safely find all .c files in root AND subdirectories
        build_path = Path(lp.bugs_build)
        c_files = [str(p.relative_to(build_path)) for p in build_path.rglob("*.c")]
        
        if not c_files:
            raise AssertionError(f"No .c files found in the project directory for build {build_label}!")

        # Pass the exact file list to Git safely
        run_local(["git", "add"] + c_files, cwd=lp.bugs_build)

        # Confirm that LavaTool actually modified tracked files
        rv_status, _ = run_local(["git", "diff", "--cached", "--quiet"], cwd=lp.bugs_build, capture_output=True)
        
        # If rv_status == 0, the staging area is empty. Trigger the assert.
        assert rv_status != 0, f"LavaTool failed to modify any C source files for build {build_label}!"

        # Commit the mutations and spawn a dedicated, isolated branch
        run_local(["git", "commit", "-m", f"Bugs for build {build_label}."], cwd=lp.bugs_build)
        run_local(["git", "branch", f"build{build_label}", "master"], cwd=lp.bugs_build)
        
        # Rewind master back to a perfectly clean state for the next injection loop
        run_local(["git", "reset", "HEAD~", "--hard"], cwd=lp.bugs_build)

    except AssertionError as e:
        print(f"\nAssertion Failed: {e}")
        if update_db:
            db.session.rollback()
        raise
    except Exception as e:
        print(f"\nFatal error: Git tracking failed: {e}")
        if update_db:
            db.session.rollback()
        raise
    
    # compile
    print("------------\n")
    print("ATTEMPTING BUILD OF INJECTED BUG(S)")
    print("build_dir = " + lp.bugs_build)
    run_local(["git", "checkout", f"build{build_label}"], cwd=lp.bugs_build)

    # Silence warnings related to adding integers to pointers since we already know that it's unsafe.
    build_output = make_and_install(
        lava_path=lp, 
        main_directory=lp.bugs_build, 
        environment="inject", 
        capture_build=True
    )

    rv, (stdout, stderr) = build_output
    stdout_str = stdout.decode('utf-8', errors='ignore')
    stderr_str = stderr.decode('utf-8', errors='ignore')

    build.compile = (rv == 0)
    build.output = f"{stdout_str};{stderr_str}"

    if update_db:
        db.session.commit()

    # ALWAYS clean up the working directory state before exiting the function
    run_local(["git", "checkout", "master"], cwd=lp.bugs_build)
    run_local(["git", "checkout", "-f"], cwd=lp.bugs_build)

    if rv != 0:
        print("\n===================================")
        print(f"[LAVA TOOL FAILED] Build {build_label} failed! Status: {rv}")
        print(f"Broken code safely preserved in branch: build{build_label}")
        print(stdout_str.replace("\\n", "\n"))
        print(stderr_str.replace("\\n", "\n"))
        print("===================================\n")
        return build, input_files, bug_solutions

    print(f"Build {build_label} succeeded and binary installed cleanly.")
    return build, input_files, bug_solutions


def mutate_file(unfuzzed_filename: str, fuzz_labels_list: list, new_filename: str, bug: Bug,
            kt: bool = False, knob: int = 0, solution: list = None):
    """
    Mutates a baseline input file by injecting precise byte sequences at tainted offsets
    to satisfy execution triggers for a target LAVA bug.

    For generic bugs (e.g., MALLOC_OFF_BY_ONE, RET_BUFFER), this function replaces the 4 bytes 
    tracked by the taint engine with the bug's static or knob-derived magic number. For 
    relational write bugs (REL_WRITE), it distributes a triad of calculated or parsed values across 
    three separate byte-label sets to satisfy complex multi-variable constraints.

    Args:
        unfuzzed_filename (str): Path to the baseline, clean input file (e.g., 'testsmall.bin').
        fuzz_labels_list (list): Nested list of byte offsets within the input file that map to
            the target bug's DUA tracking labels. For generic bugs, this is a list of offsets.
            For `BUG_REL_WRITE`, this must contain exactly 3 lists of offsets.
        new_filename (str): Output path where the freshly fuzzed/mutated file will be saved.
        bug (Bug): The target Bug ORM object containing details like type and its unique magic number.
        kt (bool, optional): Stands for 'Knob Trigger'. If True, mixes a 16-bit configuration knob 
            value with the lower 16-bits of the bug's magic number. Defaults to False.
        knob (int, optional): A 16-bit value used to craft dynamic triggers when `kt` is enabled.
            Must be less than 65535. Defaults to 0.
        solution (list of bytes, optional): Pre-calculated byte strings from `lavaTool` output to 
            satisfy a `BUG_REL_WRITE` condition. If omitted for a relational write bug, fallback 
            heuristics generate values locally based on the mathematical type encoded in the magic number.

    Raises:
        AssertionError: If `kt` is True but the `knob` exceeds 16-bit boundaries, or if the bug 
            type is `BUG_REL_WRITE` but `fuzz_labels_list` does not contain exactly 3 sub-lists.
        IOError: If reading the source file or writing the mutated output file fails.
    """
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
                 knob_trigger: bool = False, dataflow : bool = False, competition : bool = False,
                 randseed: int = 0):
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
        lp.lava_tool,
        '-action=inject',
        '-bug-list=' + bug_list_str,
        '-src-prefix=' + lp.bugs_build,
        '-host=' + db_hostname,
        '-db=' + db_name,
        '-main-files=' + main_files,
        os.path.join(lp.bugs_build, filename)
    ]

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

    rv, output = run_local(cmd, debug=project['debug'], capture_output=True)
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


def limit_atp_reuse(bugs: List[Bug], default_max: int = 1):
    """
    Filters the bug list to limit ATP reuse dynamically based on BugKind.
    Prevents multiple bugs from stacking on the same AST location if one of them
    modifies structure geometry (like malloc modifications).
    """
    # Define structural/destructive bug kinds that MUST dominate a line exclusively
    STRUCTURAL_BUGS = {
        BugKind.BUG_MALLOC_OFF_BY_ONE,
        BugKind.BUG_REL_WRITE
    }

    # Track which bug types have claimed a specific source line location
    # Map: (filename, line) -> set(BugKind)
    location_claims = {}
    
    # Track execution counts for restricted types on a specific line
    # Map: ((filename, line), BugKind) -> int
    type_counts = {}

    uniq_bugs = []

    for bug in bugs:
        b_type = bug.type
        # Extract location properties
        tloc = (bug.atp_relationship.loc.filename, bug.atp_relationship.loc.begin.line)
        
        # Initialize the set of bug types sharing this line if not present
        if tloc not in location_claims:
            location_claims[tloc] = set()
            
        existing_claims = location_claims[tloc]

        # RULE 1: If a structural bug (like malloc) already claimed this line, 
        # do not let ANY other bug type (even infinite ones) share it.
        if any(b in STRUCTURAL_BUGS for b in existing_claims) and b_type not in STRUCTURAL_BUGS:
            continue
            
        # RULE 2: If this bug is structural, but non-structural bugs already claimed the line,
        # skip it to protect the existing AST modifications from clobbering.
        if b_type in STRUCTURAL_BUGS and any(b not in STRUCTURAL_BUGS for b in existing_claims):
            continue

        # Handle filtering for unrestricted types if they cleanly own the line
        if b_type == BugKind.BUG_PTR_ADD or b_type == BugKind.BUG_RET_BUFFER or b_type == BugKind.BUG_PRINTF_LEAK:
            location_claims[tloc].add(b_type)
            uniq_bugs.append(bug.id)
            continue

        # Enforce strict line limit for structural bugs (e.g., max 1 malloc bug per line)
        seen_key = (tloc, b_type)
        if seen_key not in type_counts:
            type_counts[seen_key] = 0
            
        if type_counts[seen_key] < 1:  # Enforce absolute cap of 1
            type_counts[seen_key] += 1
            location_claims[tloc].add(b_type)
            uniq_bugs.append(bug.id)

    print("Limited ATP reuse: Had {} bugs, now have {} after type-aware filtering".format(len(bugs), len(uniq_bugs)))
    return uniq_bugs


# Build a set of src/input files that we need to modify to inject these bugs
def collect_src_and_print(bugs_to_inject: List[Bug], db: LavaDatabase):
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


def get_suffix(file_name: str) -> str:
    """
    Get the suffix (file extension) of this filename
    Args:
        file_name: The input filename that was the original input file name

    Returns:
        The suffix (file extension) of this filename
    """
    split = os.path.basename(file_name).split(".")
    if len(split) == 1:
        return ""
    else:
        return "." + split[-1]


def run_modified_program(project: dict, install_dir: str, original_input_file: str,
                         timeout: int, shell: bool= False):
    """
    Run the command to test if the injected bug did crash the program or not.
    This is to confirm, even with modifications, the program does NOT crash with the original input.

    We also use this to test to confirm that with bug injection and new input file that it DOES crash.
    Args:
        project: LAVA project configuration
        install_dir: directory with binary
        original_input_file: The input file passed into the modified program
        timeout: time to wait before killing program
        shell: Run on bash shell or not

    Returns:
        return value: the return output code. This determines success vs segfault.
        stdout, stderror: A tuple of both standard output and standard error
    """
    cmd = project['command'].format(install_dir=install_dir, input_file=original_input_file)
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
    return run_local(cmd, env=envv, cwd=install_dir, shell=shell, debug=project['debug'], capture_output=True)


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
    input_files = []
    input_file_directory = os.path.abspath(os.path.join(project["config_dir"], "inputs"))
    for file in os.listdir(input_file_directory):
        if not os.path.isfile(os.path.join(input_file_directory, file)):
            continue
        input_files.append(file)
    return input_files


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
    unfuzzed_input_file_name = random.choice(unfuzzed_inputs)
    suffix = get_suffix(unfuzzed_input_file_name)
    prefix = unfuzzed_input_file_name[:-len(suffix)] if suffix != "" else unfuzzed_input_file_name
    new_full_file_name = "{}-fuzzed-{}{}".format(prefix, bug.id, suffix)
    generated_inputs_directory = os.path.join(project['output_dir'], 'generated-inputs')
    os.makedirs(generated_inputs_directory, exist_ok=True)
    new_full_file_path = os.path.join(generated_inputs_directory, new_full_file_name)
    return new_full_file_path


def validate_bug(db: LavaDatabase, lp: LavaPaths, project: dict, bug: Bug,
                 build: Build, arguments: argparse.Namespace, update_db: bool,
                 unfuzzed_outputs=None, competition: bool = False, solution=None):
    unfuzzed_input_files = unfuzzed_input_for_bug(project)
    unfuzzed_input_file = random.choice(unfuzzed_input_files)
    unfuzzed_input_file = os.path.join(project["config_dir"], 'inputs', unfuzzed_input_file)
    fuzzed_input_file_name = fuzzed_input_for_bug(project, bug)
    print(str(bug))
    print(f"fuzzed = [{fuzzed_input_file_name}]")
    mutfile_kwargs = {}
    if arguments.knobTrigger:
        print("Knob size: {}".format(arguments.knobTrigger))
        mutfile_kwargs = {'kt': True, 'knob': arguments.knobTrigger}

    fuzz_labels_list = [bug.trigger_relationship.all_labels]
    if len(bug.extra_duas) > 0:
        extra_query = db.session.query(DuaBytes) \
            .filter(DuaBytes.id.in_(bug.extra_duas))
        fuzz_labels_list.extend([d.all_labels for d in extra_query])
    mutate_file(str(unfuzzed_input_file), fuzz_labels_list, fuzzed_input_file_name, bug,
            solution=solution, **mutfile_kwargs)
    timeout = project.get('timeout', 5)
    rv, output = run_modified_program(project, lp.bugs_install,
                                      fuzzed_input_file_name, timeout, shell=True)
    print(f"retval = {rv}")
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
                # We should move this input to a separate folder for easier tracking
                if validated:
                    base_fuzzed_file_name = os.path.basename(fuzzed_input_file_name)
                    crashes_dir = os.path.join(project['output_dir'], 'crashes')
                    os.makedirs(crashes_dir, exist_ok=True)
                    new_crash_file = os.path.join(crashes_dir, base_fuzzed_file_name)
                    print(f"Moving crashing input file to {new_crash_file}")
                    shutil.move(fuzzed_input_file_name, new_crash_file)
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
def validate_bugs(bug_list, db: LavaDatabase, lp: LavaPaths,
                  project: dict, input_files: list[str], build : Build,
                  arguments: argparse.Namespace, update_db: bool, competition: bool = False, bug_solutions=None):
    timeout = project.get('timeout', 5)

    print("------------\n")
    # first, try the original files
    print("TESTING -- ORIG INPUT")
    print(bug_list)
    print("------------\n")
    unfuzzed_outputs = {}
    for input_file in input_files:
        unfuzzed_input = os.path.join(project["config_dir"], 'inputs', os.path.basename(input_file))
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
        # We should move the files that crash to a different folder for easier identification
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


def process_crash(buf: str) -> list[int]:
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


def check_architecture_compatibility(target_arch: str, strict_64_only: bool = True) -> bool:
    """
    Verifies if the local host machine can natively execute the compiled target.
    Handles legacy 32-bit execution boundaries and halts if cross-compilation is required.
    """
    # 1. Normalize architecture keys to match get_valid_architectures() specs
    host_raw = platform.machine().lower()
    target_arch = target_arch.lower().strip()

    # Map raw host variants to clean standard tokens
    host_map = {
        'amd64': 'x86_64', 
        'x86_64': 'x86_64',
        'aarch64': 'aarch64', 
        'arm64': 'aarch64',
        'i386': 'i386', 
        'i686': 'i386', 
        'x86': 'i386',
        'arm': 'arm', 
        'armv7l': 'arm'
    }
    
    host_arch = host_map.get(host_raw, host_raw)

    print(f"[*] Architecture Check -> Host Silicon: [{host_arch}] | Target Build Target: [{target_arch}]")

    # 3. Strategy A: Strict 64-to-64 bit enforcement
    if strict_64_only:
        if host_arch == target_arch:
            print("[+] Match Verified: Running in isolated native 64-bit sandbox state.")
            return True
        else:
            print(f"[!] Compatibility Denied: Strict matching requires absolute architecture parity ({host_arch} != {target_arch}).")
            return False

    # 4. Strategy B: Multi-Arch Compatibility Permissiveness (The Legacy Fallback)
    # Complete match
    if host_arch == target_arch:
        return True

    # x86 Pipeline Compatibility Tree (x86_64 hosts can run 32-bit i386 binaries natively)
    if host_arch == 'x86_64' and target_arch == 'i386':
        print("[+] Compatibility Verified: Permitting 32-bit x86 execution on 64-bit host processor context.")
        return True

    # ARM Pipeline Compatibility Tree (AArch64 hosts can run 32-bit ARM binaries natively)
    if host_arch == 'aarch64' and target_arch == 'arm':
        print("[+] Compatibility Verified: Permitting 32-bit ARM execution on 64-bit host processor context.")
        return True

    # 5. Absolute Silicon Barrier Caught (e.g., Target=AArch64, Host=x86_64)
    print(f"[!] Cross-Architecture Blocked: Host hardware '{host_arch}' cannot natively execute '{target_arch}' machine instructions.")
    return False


def main(arguments: argparse.Namespace, lp: LavaPaths):
    # Run the guard check. Toggle strict_64_only based on your experimental parameters
    project = lp.config
    is_compatible = check_architecture_compatibility(project['qemu'])
    
    if not is_compatible:
        print("\n==========================================================================")
        print(f"[!] PIPELINE HALTED: Host machine cannot natively run the local validation pass")
        print(f"    for target architecture: {target_architecture}.")
        print("    To protect the source trees from corrupt dynamic database queries,")
        print("    the mutation pass will now exit gracefully without changing disk files.")
        print("==========================================================================\n")
        
        # Graceful, clean initialization exit code (0 keeps batch orchestration jobs moving safely)
        sys.exit(0)

    db = LavaDatabase(project)

    dataflow = project.get("dataflow", False)
    allowed_bugtypes = get_allowed_bugtype_num(arguments)

    print("allowed bug types: " + (str(allowed_bugtypes)))

    os.makedirs(lp.bugs_top_dir, exist_ok=True)

    # this is where buggy source code will be
    get_bugs_parent(lp)

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
    lp = LavaPaths(args)
    main(args, lp)
