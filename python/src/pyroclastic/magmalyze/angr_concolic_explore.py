#!/usr/bin/env python

import angr
import claripy
import os
import random
import argparse
import logging
import shlex
import time
from pyroclastic.magmalyze.KLEERandomSearch import KLEERandomSearch
from pyroclastic.magmalyze.coverage import setup, compile
from pyroclastic.utils.vars import Paths

logging.getLogger('angr').setLevel(logging.ERROR)
logging.getLogger('pyvex').setLevel(logging.ERROR)
logging.getLogger('claripy').setLevel(logging.ERROR)
logging.getLogger('KLEERandomSearch').setLevel(logging.INFO)

logger = logging.getLogger(__name__)
SYMBOLIC_FS_PATH = '/tmp/input.txt'


def create_state_for_file(project, actual_argv: list[str], input_file_path: str, symbolic_bytes_count: int):
    """
    Helper function to create a single Angr state for a specific input file.
    Supports hybrid symbolic execution and custom argv.
    """
    # 1. Read the concrete seed
    with open(input_file_path, 'rb') as fd:
        concrete_seed_content = fd.read()

    actual_file_size = len(concrete_seed_content)

    # 2. Hybrid Symbolic Generation
    symbolic_bytes_to_make = min(symbolic_bytes_count, actual_file_size)

    if actual_file_size > 0 and (actual_file_size - symbolic_bytes_to_make) >= 0:
        symbolic_start_offset = random.randint(0, actual_file_size - symbolic_bytes_to_make)
    else:
        symbolic_start_offset = 0

    parts = []
    # Layout Tracking for Logging
    layout = []

    # Prefix (Concrete)
    if symbolic_start_offset > 0:
        parts.append(claripy.BVV(concrete_seed_content[:symbolic_start_offset]))
        layout.append(f"[0-{symbolic_start_offset}] Concrete")

    # Middle (Symbolic)
    symbolic_label = f'sym_{os.path.basename(input_file_path)}_{symbolic_start_offset}'
    symbolic_chunk = claripy.BVS(symbolic_label, symbolic_bytes_to_make * 8)
    parts.append(symbolic_chunk)
    layout.append(f"[{symbolic_start_offset}-{symbolic_start_offset + symbolic_bytes_to_make}] SYMBOLIC")

    # Suffix (Concrete)
    if (symbolic_start_offset + symbolic_bytes_to_make) < actual_file_size:
        parts.append(claripy.BVV(concrete_seed_content[symbolic_start_offset + symbolic_bytes_to_make:]))
        layout.append(f"[{symbolic_start_offset + symbolic_bytes_to_make}-{actual_file_size}] Concrete")

    # Handle empty files
    if not parts:
        symbolic_file_content = claripy.BVS(f'sym_empty_{os.path.basename(input_file_path)}', 8)
        actual_file_size = 1
        layout = [" [0-1] SYMBOLIC (Empty File Fallback)"]
    else:
        symbolic_file_content = claripy.Concat(*parts)

    # 3. Create SimFile
    symbolic_sim_file = angr.SimFile(
        SYMBOLIC_FS_PATH,
        content=symbolic_file_content,
        size=actual_file_size
    )

    # 4. Create State
    state = project.factory.full_init_state(
        args=actual_argv,
        fs={SYMBOLIC_FS_PATH: symbolic_sim_file},
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ALL_FILES_EXIST
        }
    )

    # Store metadata for later extraction
    state.globals['sym_content'] = symbolic_file_content
    state.globals['origin_seed'] = os.path.basename(input_file_path)

    # Detailed Log for newbie understanding
    layout_str = " | ".join(layout)
    print(f"[*] State Initialized: {os.path.basename(input_file_path)}")
    print(f"    - Total Size: {actual_file_size} bytes")
    print(f"    - Layout:     {layout_str}")
    if actual_file_size == symbolic_bytes_to_make:
        print(f"    - Note:       Full file is symbolic.")

    return state

def perform_batch_concolic_exploration(project_paths: Paths, symbolic_bytes_count: int = 64, timeout: int = 3600):
    """
    Performs batch concolic execution with progress tracking and timeouts.
    Supports complex binaries like 'file' that require multiple arguments.
    """
    # 1. Setup Binary and Arguments
    # Placeholder for the simulated FS path used in the command template
    full_cmd_str = project_paths.config['command'].format(
        install_dir=shlex.quote(str(project_paths.generate_executable_install_dir)),
        input_file="{SYMBOLIC_FILE_PATH}"
    ).strip()

    argv_template = shlex.split(full_cmd_str)
    binary_path = argv_template[0]

    # Load the binary into the project
    p = angr.Project(binary_path, auto_load_libs=True, load_debug_info=True)

    # 2. Gather Input Seeds
    inputs_directory = project_paths.generate_directory_inputs_path
    files_to_process = []
    if os.path.isdir(inputs_directory):
        for f in os.listdir(inputs_directory):
            full_path = os.path.join(inputs_directory, f)
            if os.path.isfile(full_path):
                files_to_process.append(full_path)

    if not files_to_process:
        print("[!] No input files found in inputs directory.")
        return None

    # 3. Initialize States
    initial_states = []
    print(f"[*] Initializing fleet with {len(files_to_process)} seeds...")

    # Prepare the argv list once, replacing our placeholder with the Angr internal path
    actual_argv = [arg.replace("{SYMBOLIC_FILE_PATH}", SYMBOLIC_FS_PATH) for arg in argv_template]

    for file_path in files_to_process:
        state = create_state_for_file(p, actual_argv, file_path, symbolic_bytes_count)
        initial_states.append(state)

    # 4. Simulation Manager
    sm = p.factory.simulation_manager(initial_states)
    sm.use_technique(KLEERandomSearch(project=p))

    # 5. Progress Tracking Callback
    start_time = time.time()
    last_print = 0
    step_counter = 0
    def progress_callback(mgr):
        nonlocal last_print, step_counter, start_time
        step_counter += 1
        now = time.time()
        if now - last_print > 30:
            elapsed = int(now - start_time)
            # Single line status update
            print(f"[*] Progress: {elapsed}s | Active Paths: {len(mgr.active)} | Found: {len(mgr.deadended)} | Steps: {step_counter}", end='\r')
            last_print = now
        return mgr

    def check_timeout(mgr):
        """Returns True if the simulation should stop."""
        nonlocal start_time
        return (time.time() - start_time) > timeout

    print(f"[*] Starting exploration (Timeout: {timeout}s). Press CTRL+C to stop early.")

    try:
        # Using 'until' is the standard way to stop simgr.run based on a condition
        # We also pass the progress_callback to keep the UI updated
        sm.run(until=check_timeout, step_func=progress_callback)

        if (time.time() - start_time) > timeout:
            print(f"\n[!] Time limit reached ({timeout}s). Wrapping up...")

    except KeyboardInterrupt:
        print(f"\n[!] User interrupted (CTRL+C). Proceeding to save discovered paths...")
    except Exception as e:
        print(f"\n[!] Simulation error: {e}")

    print(f"[*] Exploration ended. Found {len(sm.deadended)} paths. Solving symbolic constraints...")

    # 6. Saving results
    for i, state in enumerate(sm.deadended):
        sym_var = state.globals.get('sym_content')
        origin = state.globals.get('origin_seed', 'unknown')
        if sym_var is not None:
            try:
                solved = state.solver.eval(sym_var, cast_to=bytes)
                out_name = f"gen_{origin}_{hex(state.addr)}_{i}.bin"
                with open(os.path.join(inputs_directory, out_name), "wb") as fd:
                    fd.write(solved)
            except Exception:
                pass
    return sm


def main():
    parser = argparse.ArgumentParser(description="Perform initial concolic exploration and report path history.")
    parser.add_argument("--project", "-p", required=True, dest="project_name",
                        help="Provide the LAVA project name")
    parser.add_argument("--symbolic-bytes", "-s", type=int, default=64)
    parser.add_argument("--timeout", "-t", type=int, default=3600)
    args = parser.parse_args()

    lava_paths = Paths(args)
    setup(lava_paths)
    compile(lava_paths)

    # Call the main exploration function
    # We now return the simgr, symbolic_file_content, and project for potential future steps
    perform_batch_concolic_exploration(lava_paths, symbolic_bytes_count=args.symbolic_bytes, timeout=args.timeout)


if __name__ == '__main__':
    main()
