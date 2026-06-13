import os
import tarfile
import argparse
from pathlib import Path
import shutil
import shlex
import re
import subprocess

from pyroclastic.utils.vars import parse_vars, LavaPaths
from pyroclastic.add_queries.add_queries import run_local
from pyroclastic.utils.funcs import unpack_tar, configure_project, make_and_install


def setup(lava_path: LavaPaths):
    """
    Copy the inputs folder from the config_dir into the `target_generation`/<project> folder.
    We use this so when we generate new inputs, it is in target_generation/<project>/inputs folder
    """
    # 1. Setup Directories
    if not lava_path.generate_project_root_directory.exists():
        lava_path.generate_project_root_directory.mkdir(parents=True)

    os.chdir(lava_path.generate_project_root_directory)
    unpack_tar(lava_path)

    print(f"Changing to source directory to {lava_path.generate_project_root_unpacked_tar_directory}")
    os.chdir(lava_path.generate_project_root_unpacked_tar_directory)


def compile(lava_path: LavaPaths, coverage: bool = False):
    """
    Compiles the project using `make` and installs it.
    Args:
        coverage: if True, use coverage environment variables for compilation.
    """
    if coverage:
        lava_path.generate_executable_install_dir = configure_project(lava_path, environment='llvm_cov', main_directory=str(lava_path.generate_project_root_unpacked_tar_directory))
        make_and_install(lava_path, environment='llvm_cov', main_directory=str(lava_path.generate_project_root_unpacked_tar_directory))
    else:
        lava_path.generate_executable_install_dir = configure_project(lava_path, main_directory=str(lava_path.generate_project_root_unpacked_tar_directory))
        make_and_install(lava_path, main_directory=str(lava_path.generate_project_root_unpacked_tar_directory))

    # Copy the inputs from the original project to the generation folder to make new inputs
    input_file_directory = os.path.abspath(os.path.join(lava_path.config["config_dir"], "inputs"))
    lava_path.generate_directory_inputs_path = os.path.join(lava_path.generate_executable_install_dir, 'inputs')
    if os.path.exists(lava_path.generate_directory_inputs_path):
        shutil.rmtree(lava_path.generate_directory_inputs_path)
    shutil.copytree(input_file_directory, lava_path.generate_directory_inputs_path)


def get_coverage(lava_path: LavaPaths) -> float:
    """
    Calculates code coverage using GCC's GCOV/LCOV profiling tools.

    This function assumes:
    1. The C source code for the binary was compiled with GCC's coverage flags
        (e.g., `gcc -g --coverage -fprofile-arcs -ftest-coverage your_program.c -o your_program`).
    2. 'Lcov' and 'genhtml' tools are installed and available in your system's PATH.

    Returns:
        float: The calculated overall line coverage percentage, or -1.0 if calculation fails.
    """
    compile(lava_path, coverage=True)
    print(f"[*] Executing binary with inputs to collect LLVM coverage data...")

    # Modern LLVM coverage uses environment variables to define output paths
    # We'll collect all raw profiles in a temporary folder
    profraw_dir = os.path.join(lava_path.generate_project_root_directory, "profraw")
    if os.path.exists(profraw_dir):
        shutil.rmtree(profraw_dir)
    os.makedirs(profraw_dir)

    # Set the pattern for raw profile output
    # %p = pid, %m = binary signature. This ensures multi-run data is preserved.
    env = os.environ.copy()
    env["LLVM_PROFILE_FILE"] = os.path.join(profraw_dir, "data-%p.profraw")

    # --- Step 1: Execute binary with all inputs to generate .gcda files ---
    for filename in os.listdir(lava_path.generate_directory_inputs_path):
        filepath = os.path.join(lava_path.generate_directory_inputs_path, filename)
        if os.path.isfile(filepath):
            # Using the compiled binary from the installation path
            full_command = lava_path.config['command'].format(
                install_dir=shlex.quote(str(lava_path.generate_executable_install_dir)),
                input_file=shlex.quote(filepath)
            ).strip()

            print(f"    - Running {full_command}")
            try:
                subprocess.run(full_command.split(),
                                cwd=lava_path.generate_project_root_directory,
                                env=env,
                                capture_output=True, text=True, check=False)
            except Exception as e:
                print(f"[-] Error running coverage execution: {e}")

    # --- Step 2: Merge raw profiles using llvm-profdata ---
    # lcov/gcov is no longer needed. We use LLVM's internal tools.
    profdata_tool = os.path.join(lava_path.config['llvm-dir'], "bin", "llvm-profdata")
    cov_tool = os.path.join(lava_path.config['llvm-dir'], "bin", "llvm-cov")
    indexed_profdata = os.path.join(lava_path.generate_project_root_directory, "coverage.profdata")

    print(f"[*] Merging profraw files into {indexed_profdata}...")
    try:
        # Note: globbing *.profraw needs a shell or manual expansion
        import glob
        raw_files = glob.glob(os.path.join(profraw_dir, "*.profraw"))

        if not raw_files:
            print("[-] Error: No .profraw files were generated. Did the binary run correctly?")
            return -1.0

        # Construct command list: [tool, merge, -sparse, file1, file2, ..., -o, output]
        merge_cmd = [profdata_tool, "merge", "-sparse"] + raw_files + ["-o", indexed_profdata]

        # Execute without shell=True for a list of arguments
        subprocess.run(merge_cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"[-] Error merging profile data: {e}")
        return -1.0

    # --- Step 3: Generate HTML report using llvm-cov ---
    # We need the path to the actual instrumented binary to read coverage mapping
    instrumented_binary = lava_path.config['command'].format(
        install_dir=str(lava_path.generate_executable_install_dir),
        input_file=""
        ).split()[0].strip()

    html_output = os.path.join(lava_path.generate_project_root_directory, "html")
    show_cmd = [
        cov_tool, "show",
        instrumented_binary,
        "-instr-profile=" + indexed_profdata,
        "-format=html",
        "-output-dir=" + html_output,
        "-show-line-counts-or-regions",
        "-show-instantiations"
    ]

    print(f"[*] Generating HTML report via llvm-cov...")
    try:
        subprocess.run(show_cmd, check=True)
        print(f"[+] HTML coverage report generated: file://{os.path.abspath(os.path.join(html_output, 'index.html'))}")
    except subprocess.CalledProcessError as e:
        print(f"[-] Error generating HTML report: {e}")
        return -1.0

    # --- Step 4: Parse overall coverage percentage ---
    report_cmd = [
        cov_tool, "report",
        instrumented_binary,
        "-instr-profile=" + indexed_profdata
    ]

    try:
        report_result = subprocess.run(report_cmd, capture_output=True, text=True, check=True)
        print(report_result.stdout)

        # Extract TOTAL percentage from the last line of the report
        # Usually looks like: TOTAL 23 12 52.17%
        lines = report_result.stdout.strip().split('\n')
        if lines:
            last_line = lines[-1]
            match = re.search(r'(\d+\.\d+)%', last_line)
            if match:
                line_coverage = float(match.group(1))
                return line_coverage
    except Exception as e:
        print(f"[-] Could not parse coverage summary: {e}")

    return -1.0


def main():
    parser = argparse.ArgumentParser(description="Calculate code coverage using LLVM-COV.")
    parser.add_argument("--project", "-p", required=True, dest="project_name", help="Provide the LAVA project name")
    args = parser.parse_args()

    # Check for existence of local host.json. If it doesn't exist, prompt the user to create one and exit.
    current_workspace = Path.cwd()
    local_config_path = current_workspace / "host.json"
    if not local_config_path.is_file():
        print(f"[!] No local host.json found in {current_workspace}. Run `lava-init` on this workspace.")
        sys.exit(1)

    lava_paths = LavaPaths(args)
    setup(lava_paths)
    coverage_percentage = get_coverage(lava_paths)

    if coverage_percentage >= 0:
        print(f"\nFinal calculated coverage: {coverage_percentage:.2f}%")
    else:
        print("\nCoverage calculation failed.")


if __name__ == '__main__':
    main()