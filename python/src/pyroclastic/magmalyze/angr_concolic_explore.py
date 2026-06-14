#!/usr/bin/env python

import angr
import claripy
import os
import argparse
import shlex
import time
import logging
import random
from angr.exploration_techniques import ExplorationTechnique
# https://github.com/angr/angr/blob/9fa64a7ce22a4ca3f43e159cb4a831ce586a3241/angr/sim_manager.py#L27
from angr.sim_manager import SimulationManager
# https://github.com/angr/angr/blob/9fa64a7ce22a4ca3f43e159cb4a831ce586a3241/angr/sim_state.py#L60
from angr.sim_state import SimState
from pyroclastic.magmalyze.coverage import setup, compile
from pyroclastic.utils.vars import LavaPaths

logging.getLogger('angr').setLevel(logging.ERROR)
logging.getLogger('pyvex').setLevel(logging.ERROR)
logging.getLogger('claripy').setLevel(logging.ERROR)
logging.getLogger('KLEERandomSearch').setLevel(logging.INFO)

logger = logging.getLogger(__name__)
SYMBOLIC_FS_PATH = '/tmp/input.txt'


class KLEERandomSearch(ExplorationTechnique):
    """
    KLEE Random Path Selection (General Purpose Version)
    Paper: https://hci.stanford.edu/cstr/reports/2008-03.pdf
    """

    def __init__(self, **kwargs):
        super(KLEERandomSearch, self).__init__()

    def step(self, simgr: SimulationManager, stash: str = 'active', **kwargs):
        # 1. Execute the next step
        simgr : SimulationManager = simgr.step(stash=stash, **kwargs)

        # 2. Pool all states (Active + Deferred) to make a global weighted choice
        simgr.move(from_stash=stash, to_stash='deferred')

        # Adding the type hint as requested: list[SimState]
        # In Angr, the stashes are essentially lists of SimState objects.
        deferred: list[SimState] = simgr.stashes['deferred']

        if not deferred:
            return simgr

        # 3. Calculate weights
        weights: list[float] = []
        for state in deferred:
            # FIX: Using 'state.history.depth' as a fallback,
            # or specifically counting 'branch' events in the history.
            # Most robust way across angr versions to find "how many times have I branched":
            fork_count = sum(1 for ev in state.history.events if ev.type == 'branch')

            # If for some reason 'branch' events aren't being logged in your config,
            # we use state.history.depth (block count) as a fallback, though it's less 'pure' KLEE.
            if fork_count == 0 and state.history.depth > 0:
                # We'll use a scaled version of depth if no explicit branches found
                weight = 0.5 ** min(state.history.depth // 10, 1022)
            else:
                weight = 0.5 ** min(fork_count, 1022)

            weights.append(weight)

        # 4. Weighted Random Selection
        try:
            selected_state: SimState = random.choices(deferred, weights=weights, k=1)[0]
        except (ValueError, IndexError):
            selected_state: SimState = random.choice(deferred)

        # 5. Restore the chosen state to active
        simgr.stashes['deferred'].remove(selected_state)
        simgr.stashes[stash] = [selected_state]

        # Detailed logging for your debugging
        logger.debug(f"KLEE Select: Pool={len(deferred)} | Chosen Depth={selected_state.history.depth}")

        return simgr

    def setup(self, simgr: SimulationManager):
        if 'deferred' not in simgr.stashes:
            simgr.stashes['deferred'] = []


def create_state_for_file(project: angr.Project, actual_argv: list[str], input_file_path: str,
                          symbolic_bytes_count: int):
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
    layout = []

    if symbolic_start_offset > 0:
        parts.append(claripy.BVV(concrete_seed_content[:symbolic_start_offset]))
        layout.append(f"[0-{symbolic_start_offset}] Concrete")

    symbolic_label = f'sym_{os.path.basename(input_file_path)}_{symbolic_start_offset}'
    symbolic_chunk = claripy.BVS(symbolic_label, symbolic_bytes_to_make * 8)
    parts.append(symbolic_chunk)
    layout.append(f"[{symbolic_start_offset}-{symbolic_start_offset + symbolic_bytes_to_make}] SYMBOLIC")

    if (symbolic_start_offset + symbolic_bytes_to_make) < actual_file_size:
        parts.append(claripy.BVV(concrete_seed_content[symbolic_start_offset + symbolic_bytes_to_make:]))
        layout.append(f"[{symbolic_start_offset + symbolic_bytes_to_make}-{actual_file_size}] Concrete")

    if not parts:
        symbolic_file_content = claripy.BVS(f'sym_empty_{os.path.basename(input_file_path)}', 8)
        actual_file_size = 1
        layout = [" [0-1] SYMBOLIC (Empty File Fallback)"]
    else:
        symbolic_file_content = claripy.Concat(*parts)

    symbolic_sim_file = angr.SimFile(
        SYMBOLIC_FS_PATH,
        content=symbolic_file_content,
        size=actual_file_size
    )

    state = project.factory.full_init_state(
        args=actual_argv,
        fs={SYMBOLIC_FS_PATH: symbolic_sim_file},
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ALL_FILES_EXIST
        }
    )

    state.globals['sym_content'] = symbolic_file_content
    state.globals['origin_seed'] = os.path.basename(input_file_path)

    layout_str = " | ".join(layout)
    print(f"[*] State Initialized: {os.path.basename(input_file_path)}")
    print(f"    - Total Size: {actual_file_size} bytes")
    print(f"    - Layout:     {layout_str}")

    return state


def perform_batch_concolic_exploration(project_paths: LavaPaths, symbolic_bytes_count: int = 64, timeout: int = 3600,
                                       strategy: str = "klee"):
    full_cmd_str = project_paths.config['command'].format(
        install_dir=shlex.quote(str(project_paths.generate_executable_install_dir)),
        input_file="{SYMBOLIC_FILE_PATH}"
    ).strip()

    argv_template = shlex.split(full_cmd_str)
    binary_path = argv_template[0]

    p = angr.Project(binary_path, auto_load_libs=True, load_debug_info=True)

    inputs_directory = project_paths.generate_directory_inputs_path

    # NEW: Create the backup directory
    backup_directory = os.path.join(project_paths.config['config_dir'], 'generated_inputs')
    os.makedirs(backup_directory, exist_ok=True)

    files_to_process = []
    if os.path.isdir(inputs_directory):
        for f in os.listdir(inputs_directory):
            full_path = os.path.join(inputs_directory, f)
            if os.path.isfile(full_path):
                files_to_process.append(full_path)

    if not files_to_process:
        print("[!] No input files found in inputs directory.")
        return None

    initial_states = []
    print(f"[*] Initializing fleet with {len(files_to_process)} seeds...")

    actual_argv = [arg.replace("{SYMBOLIC_FILE_PATH}", SYMBOLIC_FS_PATH) for arg in argv_template]

    for file_path in files_to_process:
        state = create_state_for_file(p, actual_argv, file_path, symbolic_bytes_count)
        initial_states.append(state)

    sm = p.factory.simulation_manager(initial_states)

    # Allow toggling strategy for the CI/CD proof
    if strategy.lower() == "dfs":
        print("[*] Strategy: Angr Default DFS")
        sm.use_technique(angr.exploration_techniques.DFS())
    else:
        print("[*] Strategy: KLEE Random Search")
        sm.use_technique(KLEERandomSearch())

    start_time = time.time()
    last_print = 0
    step_counter = 0

    def progress_callback(mgr):
        nonlocal last_print, step_counter, start_time
        step_counter += 1
        now = time.time()
        if now - last_print > 30:
            elapsed = int(now - start_time)
            print(
                f"[*] Progress: {elapsed}s | Active Paths: {len(mgr.active)} | Deferred: {len(mgr.stashes.get('deferred', []))} | Found: {len(mgr.deadended)} | Steps: {step_counter}",
                end='\r')
            last_print = now
        return mgr

    def check_timeout(mgr):
        nonlocal start_time
        return (time.time() - start_time) > timeout

    print(f"[*] Starting exploration (Timeout: {timeout}s). Press CTRL+C to stop early.")

    try:
        sm.run(until=check_timeout, step_func=progress_callback)
        if (time.time() - start_time) > timeout:
            print(f"\n[!] Time limit reached ({timeout}s). Wrapping up...")
    except KeyboardInterrupt:
        print(f"\n[!] User interrupted (CTRL+C). Proceeding to save discovered paths...")
    except Exception as e:
        print(f"\n[!] Simulation error: {e}")

    # Combine dead ended and deferred states for extraction
    all_finished = sm.deadended + sm.stashes.get('deferred', [])
    print(f"\n[*] Exploration ended. Extracting constraints from {len(all_finished)} paths...")

    unique_outputs = set()
    saved_count = 0

    # 6. Saving results and Printing STDOUT paths
    print("\n" + "=" * 40)
    print("      PATH DISCOVERY TRACE")
    print("=" * 40)

    for i, state in enumerate(all_finished):
        sym_var = state.globals.get('sym_content')
        origin = state.globals.get('origin_seed', 'unknown')

        if sym_var is not None:
            try:
                solved = state.solver.eval(sym_var, cast_to=bytes)

                if solved in unique_outputs:
                    continue
                unique_outputs.add(solved)

                # EXTRACT STDOUT: This pulls the "LLRLL..." string from the state
                stdout_bytes = state.posix.dumps(1)
                stdout_str = stdout_bytes.strip()
                # Clean up string to just show the Labyrinth path
                path_str = "".join([c for c in stdout_str if c in "LR"])

                # Format output file names
                out_name = f"gen_{origin}_{hex(state.addr)}_{i}.bin"
                primary_path = os.path.join(inputs_directory, out_name)
                backup_path = os.path.join(backup_directory, out_name)

                # Dual Save
                with open(primary_path, "wb") as fd:
                    fd.write(solved)
                with open(backup_path, "wb") as fd:
                    fd.write(solved)

                saved_count += 1

                # Print the pattern!
                if path_str:
                    print(f"[{saved_count:03d}] Path: {path_str}  <- ({out_name})")

            except Exception:
                pass

    print("=" * 40)
    print(f"[*] Successfully saved {saved_count} unique input files.")
    print(f"[*] Backups stored in: {backup_directory}")
    return sm


def main():
    parser = argparse.ArgumentParser(description="Perform initial concolic exploration and report path history.")
    parser.add_argument("--project", "-p", required=True, dest="project_name", help="Provide the LAVA project name")
    parser.add_argument("--symbolic-bytes", "-s", type=int, default=64)
    parser.add_argument("--timeout", "-t", type=int, default=3600)
    parser.add_argument("--strategy", choices=["dfs", "klee"], default="klee", help="Choose exploration strategy")
    args = parser.parse_args()
    lava_paths = LavaPaths(args)
    setup(lava_paths)
    compile(lava_paths)

    perform_batch_concolic_exploration(
        lava_paths,
        symbolic_bytes_count=args.symbolic_bytes,
        timeout=args.timeout,
        strategy=args.strategy
    )


if __name__ == '__main__':
    main()
