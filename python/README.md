# Pyraflow
This package contains all the Python code for LAVA. 

## Code Coverage
A metric we collect is code coverage.

We suggest updating your Makefile to have a coverage target where you need to pass the following arguments `-g -O0 -fprofile-arcs -ftest-coverage`, 
to your binary compilation command. For example, if you are compiling a binary called `toy`, your Makefile should have a target like this:

```makefile
coverage:
	$(CC) $(CFLAGS) -DHAVE_CONFIG_H -g -O0 -fprofile-arcs -ftest-coverage -o toy toy.c
```

Once you have the binary, you can use the `coverage.py` script to run the binary and collect coverage data.

## Generating new inputs

Right now, these are some inputs to run for testing:

```bash
python3 coverage.py --input_dir ./tests/inputs --output_dir ./tests/outputs
```

## Bug Injection

## Graveyard code

I am saving the broken workflow of exploring angr. The logic might be helpful later for future exploration

```python
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

```
