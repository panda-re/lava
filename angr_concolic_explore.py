import os
import tarfile
import subprocess
import argparse
import angr
import claripy
import logging

# We want to see angr's logs for debugging purposes.
# You can comment this out for a cleaner output.
logging.getLogger('angr').setLevel(logging.WARN)


def search_and_extract(keyword: str, source_dir: str) -> str:
    """
    Search for a .tar.gz file in 'target_bins/' matching the keyword,
    extract it to 'target_injections/', and run `make install` inside.

    Args:
        keyword: The project name, e. g. 'toy', 'file, etc.
        source_dir: The directory with the tar file to unpack
    Returns:
        Str: The path to the extracted directory if successful, None otherwise.
    """
    dest_dir = os.path.join("target_injections", keyword)
    os.makedirs(dest_dir, exist_ok=True)

    for root, _, files in os.walk(source_dir):
        for file in files:
            if file.endswith(".tar.gz") and keyword in file:
                file_path = os.path.join(root, file)
                print(f"Found matching file: {file_path}")

                file_name = os.path.basename(file_path)
                base_name = file_name.split('-pre.tar.gz')[0]

                with tarfile.open(file_path, "r:gz") as tar:
                    tar.extractall(dest_dir)
                    print(f"Extracted contents to: {dest_dir}")

                try:
                    # Extend CFLAGS and CXXFLAGS
                    # We need static compilation and debug for Angr to work properly with the binary
                    env = os.environ.copy()
                    extra_flags = "-g"
                    
                    # Build CFLAGS and CXXFLAGS for explicit passing to make
                    cflags = env.get("CFLAGS", "") + " " + extra_flags
                    cxxflags = env.get("CXXFLAGS", "") + " " + extra_flags

                    print(f"[*] Running make with:")
                    print(f"    CFLAGS='{cflags.strip()}'")
                    print(f"    CXXFLAGS='{cxxflags.strip()}'")

                    subprocess.run(
                        ["make", f"CFLAGS={cflags.strip()}", f"CXXFLAGS={cxxflags.strip()}"],
                        cwd=os.path.join(dest_dir, base_name),
                        check=True,
                        env=env,
                    )
                    subprocess.run(
                        ["make", "install", f"CFLAGS={cflags.strip()}", f"CXXFLAGS={cxxflags.strip()}"],
                        cwd=os.path.join(dest_dir, base_name),
                        check=True,
                        env=env,
                    )
                    print("Make command executed successfully.")
                    return os.path.join(dest_dir, base_name)
                except subprocess.CalledProcessError as e:
                    print(f"Error while running 'make': {e}")
                    return None

    print(f"No .tar.gz file with keyword '{keyword}' found in {source_dir}.")
    return None



def get_initial_coverage(project, binary_path: str, initial_inputs: list, angr_state_options: set) -> set:
    """
    Runs the binary with existing inputs to find the baseline coverage.
    This version correctly simulates file I/O via argv.
    Args:
        project: Angr Project
        binary_path: The path of the statically compiled executable
        initial_inputs: The list of all files to use as initial inputs for coverage
        angr_state_options: A set of Angr options to apply to the initial state.
    Returns:
        Set: The set of covered basic block addresses.
    """
    covered_blocks = set()
    print(f"[*] Calculating baseline coverage with {len(initial_inputs)} seed inputs...")

    # Define a consistent virtual path for the input file inside the simulation
    VIRTUAL_INPUT_PATH = '/tmp/input.bin'

    for seed_content in initial_inputs:
        # Create a "SimFile" - a virtual file for angr's simulated filesystem
        sim_file = angr.SimFile(VIRTUAL_INPUT_PATH, content=seed_content)
        
        # Create the initial state using full_init_state, which is more robust.
        # Provide the command-line arguments and the virtual filesystem.
        state = project.factory.full_init_state(
            args=[binary_path, VIRTUAL_INPUT_PATH],
            fs={VIRTUAL_INPUT_PATH: sim_file},
            pylgr_options=angr_state_options
        )
        simgr = project.factory.simulation_manager(state)
        
        # Run until the program exits or gets stuck
        simgr.run()

        # We are interested in states that have finished (deadended)
        for deadended_state in simgr.deadended:
            # Get all the basic block addresses from the execution history
            for addr in deadended_state.history.bbl_addrs:
                covered_blocks.add(addr)
    
    print(f"[*] Baseline coverage calculated. Found {len(covered_blocks)} unique basic blocks.")
    return covered_blocks


def run_angr_concolic_analysis(binary_path: str, inputs_folder: str):
    """
    Run concolic analysis on a binary using Angr, exploring symbolic file input paths
    to reach a function or hard-to-fuzz condition.

    Parameters:
        binary_path (str): Path to the executable binary.
        inputs_folder (str): Path of folder with all inputs for binary.
    """
    print("[*] Loading project")
    # --- Step 1: Load the project and get baseline coverage ---
    # auto_load_libs=False is a performance optimization for this use case
    project = angr.Project(binary_path, auto_load_libs=False)

    initial_inputs = []
    for filename in os.listdir(inputs_folder):
        filepath = os.path.join(inputs_folder, filename)
        if os.path.isfile(filepath):
            with open(filepath, 'rb') as f:
                initial_inputs.append(f.read())

    # Define Angr state options for performance
    angr_state_options = set()

    # This option makes unconstrained memory concrete (zero-filled).
    # It can significantly speed up analysis by reducing the number of symbolic variables,
    # but it sacrifices soundness by assuming uninitialized memory is zero.
    # Use with caution, as it might miss paths that depend on non-zero uninitialized values.
    angr_state_options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    print("[*] ZERO_FILL_UNCONSTRAINED_MEMORY enabled for performance.")
    
    # You can add other Angr options here for further tuning, e.g.:
    # angr_state_options.add(angr.options.LAZY_SOLVES) # Solves constraints lazily, can be faster but might lead to more paths
    # angr_state_options.add(angr.options.REPLACEMENT_UNCONSTRAINED_REGISTERS) # Replaces unconstrained registers with concrete values
    # angr_state_options.add(angr.options.STRICT_PAGE_ACCESS) # More strict memory access checking, might be slower

    print("[*] Get Initial Coverage")
    total_coverage = get_initial_coverage(project, binary_path, initial_inputs, angr_state_options)
    print("[*] Coverage Complete")

     # --- Step 2: Set up the main symbolic exploration ---

    # Define the path for the symbolic input file inside the simulation
    SYMBOLIC_INPUT_PATH = '/tmp/symbolic_input.bin'
    symbolic_input_size = 512  # Increased size for structured binary data

    # Create a symbolic bitvector that will represent the file's content
    symbolic_content = claripy.BVS('symbolic_content', 8 * symbolic_input_size)
    symbolic_file = angr.SimFile(SYMBOLIC_INPUT_PATH, content=symbolic_content)
    
    # Create the initial state, providing the symbolic file to the simulated FS
    state = project.factory.full_init_state(
        args=[binary_path, SYMBOLIC_INPUT_PATH],
        fs={SYMBOLIC_INPUT_PATH: symbolic_file}
    )
    
    simgr = project.factory.simulation_manager(state)
    print("\n[*] Starting symbolic exploration to find new paths...")
    found_count = 0

    # --- Step 3: Explore and generate new inputs ---    
    while simgr.active:
        simgr.step()

        newly_found_states = []
        for active_state in simgr.active:
            current_addr = active_state.addr
            if current_addr not in total_coverage:
                print(f"\n[+] New coverage found at address: {hex(current_addr)}")
                found_count += 1
                
                try:
                    line_info = project.loader.find_line_by_addr(current_addr)
                    print(f"    -> Source Location: {line_info}")
                except Exception:
                    print(f"    -> Could not determine source line. Compile with -g for this feature.")

                if active_state.satisfiable():
                    print("    -> State is satisfiable. Solving for new input...")
                    # Solve for the symbolic content of the file
                    solved_input = active_state.solver.eval(symbolic_content, cast_to=bytes)

                    new_filename = f"new_input_{found_count}_{hex(current_addr)}.bin"
                    new_filepath = os.path.join(inputs_folder, new_filename)
                    with open(new_filepath, 'wb') as f:
                        f.write(solved_input)
                    print(f"    -> New input saved to: {new_filepath}")

                    for addr in active_state.history.bbl_addrs:
                        total_coverage.add(addr)
                    
                    newly_found_states.append(active_state)
                else:
                    print("    -> State is NOT satisfiable. Cannot generate input.")
        
        for found_state in newly_found_states:
            simgr.active.remove(found_state)
            simgr.stashes.setdefault('found', []).append(found_state)

    print(f"\n[*] Exploration complete. Found {found_count} new inputs.")


def main():
    """
    Main entry point: parses arguments, extracts project, and runs Angr analysis.
    """
    parser = argparse.ArgumentParser(description="Search and concolically analyze binaries.")
    parser.add_argument("--project", "-p", required=True, help="Keyword for project archive in target_bins/")
    parser.add_argument("--dir", "-d", default="target_bins", help="Folder containing the TAR file with the source code")
    parser.add_argument("--input-folder", "-i", default="target_injections", help="Folder containing input files for the project.")
    args = parser.parse_args()

    # Note that inputs are in target_configs folder. Update this folder with more inputs
    binary_dir = os.path.join(args.dir, args.project)
    binary_path = os.path.join(binary_dir, args.project)
    if not os.path.exists(binary_path):
        binary_dir = search_and_extract(args.project, args.dir)
        if not binary_dir:
            return

        # Guess binary name
        binary_path = os.path.join(binary_dir, args.project)
        if not os.path.exists(binary_path):
            print(f"[!] Expected binary {binary_path} not found.")
            return
    
    run_angr_concolic_analysis(
        binary_path=binary_path,
        inputs_folder=args.input_folder
    )


if __name__ == "__main__":
    main()
