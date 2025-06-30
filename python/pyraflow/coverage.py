import os
import subprocess
import re
import sys


def calculate_gcc_coverage(binary_path: str, inputs_folder: str, output_dir: str = "lcov_coverage_report"):
    """
    Calculates code coverage using GCC's GCOV/LCOV profiling tools.
    
    This function assumes:
    1. The C source code for the binary was compiled with GCC's coverage flags
       (e.g., `gcc -g --coverage -fprofile-arcs -ftest-coverage your_program.c -o your_program`).
    2. 'Lcov' and 'genhtml' tools are installed and available in your system's PATH.
    
    Args:
        binary_path (str): The path to the compiled binary (e.g., './complex_auth').
        inputs_folder (str): The path to the folder containing input files for the binary.
        output_dir (str): The directory where the LCOV HTML report will be generated.
    
    Returns:
        float: The calculated overall line coverage percentage, or -1.0 if calculation fails.
    """
    print(f"[*] Starting GCC/LCOV code coverage analysis for: {binary_path}")
    print(f"[*] Using inputs from: {inputs_folder}")

    # Ensure the output directory exists
    os.makedirs(output_dir, exist_ok=True)

    # Get the directory where the binary resides (needed for .gcda, .gcno files)
    binary_dir = os.path.dirname(binary_path)
    if not binary_dir: # If binary_path is just a filename, assume the current directory
        binary_dir = "."
    
    # Clean up any previous .gcda files (execution data)
    # .gcno files (notes files) are generated at compilation and persist, so we don't delete them here.
    print("[*] Cleaning up previous .gcda files...")
    for root, _, files in os.walk(binary_dir):
        for file in files:
            if file.endswith(".gcda"):
                try:
                    os.remove(os.path.join(root, file))
                except OSError as e:
                    print(f"[-] Error removing {os.path.join(root, file)}: {e}")

    # --- Step 1: Execute binary with all inputs to generate .gcda files ---
    print(f"[*] Executing binary with inputs to collect coverage data...")
    input_files_processed = 0
    for filename in os.listdir(inputs_folder):
        filepath = os.path.join(inputs_folder, filename)
        if os.path.isfile(filepath):
            print(f"    - Running {binary_path} with input: {filepath}")
            try:
                # Execute the binary, passing the input file as an argument
                # Redirect stdout/stderr to avoid clutter, unless debugging
                subprocess.run([binary_path, filepath], 
                               cwd=binary_dir, # Run from binary's directory for .gcda generation
                               capture_output=True, text=True, check=False)
                input_files_processed += 1
            except FileNotFoundError:
                print(f"[-] Error: Binary not found at '{binary_path}'. Make sure it's compiled and accessible.")
                return -1.0
            except Exception as e:
                print(f"[-] Error running {binary_path} with {filepath}: {e}")
    
    if input_files_processed == 0:
        print("[!] No input files found or processed. Coverage data will be empty.")
        return 0.0

    print(f"[*] Finished executing with {input_files_processed} inputs.")

    # --- Step 2: Use lcov to generate coverage info file ---
    # --capture: capture coverage data
    # --directory: specify directory containing source and .gcno/.gcda files
    # --output-file: specify an output info file
    lcov_cmd = ["lcov", "--capture",
                "--rc",
                "lcov_branch_coverage=1",
                "--directory", binary_dir,
                "--output-file", os.path.join(output_dir, "coverage.info")]
    print(f"[*] Running lcov to generate coverage.info...")
    try:
        lcov_result = subprocess.run(lcov_cmd, capture_output=True, text=True, check=True)
        print(lcov_result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"[-] Error running lcov: {e}")
        print(e.stderr)
        return -1.0
    except FileNotFoundError:
        print("[-] Error: 'lcov' command not found. Please install LCOV (e.g., 'sudo apt-get install lcov').")
        return -1.0

    # --- Step 3: Use genhtml to create human-readable HTML report ---
    # --output-directory: specifies where to put the HTML files
    genhtml_cmd = ["genhtml", os.path.join(output_dir, "coverage.info"),
                   "--rc",
                   "genhtml_branch_coverage=1",
                   "--output-directory", os.path.join(output_dir, "html")]
    print(f"[*] Running genhtml to create HTML report in '{os.path.join(output_dir, 'html')}'...")
    try:
        genhtml_result = subprocess.run(genhtml_cmd, capture_output=True, text=True, check=True)
        print(genhtml_result.stdout)
        print(f"[+] HTML coverage report generated: file://{os.path.abspath(os.path.join(output_dir, 'html', 'index.html'))}")
    except subprocess.CalledProcessError as e:
        print(f"[-] Error running genhtml: {e}")
        print(e.stderr)
        return -1.0
    except FileNotFoundError:
        print("[-] Error: 'genhtml' command not found. Please install LCOV (e.g., 'sudo apt-get install lcov').")
        return -1.0
    
    # --- Step 4: Parse overall coverage percentage from lcov output ---
    # The lcov --capture output often contains a summary line like:
    # "Total: 85.7% of 7 lines (1 of 3 branches, 1 of 1 functions)"
    line_coverage = 0.0
    match = re.search(r'lines\.\.\.\.\.\.: (\d+\.\d+)%', genhtml_result.stdout)
    if match:
        line_coverage = float(match.group(1))
        print(f"\n[+] Overall Line Coverage: {line_coverage:.2f}%")
    else:
        print("[-] Could not parse overall line coverage percentage from lcov output.")
    
    return line_coverage


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="Calculate code coverage using GCC/LCOV.")
    parser.add_argument("--binary", "-b", required=True, dest="binary",
                        help="Path to the compiled binary")
    parser.add_argument("--inputs-folder", "-i", required=True, dest="inputs_folder",
                        help="Folder containing input files for the binary.")
    parser.add_argument("--output-dir", "-o", default="lcov_coverage_report", dest="output_dir",
                        help="Directory to store LCOV output (coverage.info, html report). (Default: lcov_coverage_report)")
    args = parser.parse_args()

    # Ensure the binary path is relative or absolute
    if not os.path.exists(args.binary) and not os.path.isfile(args.binary):
        print(f"Error: Binary '{args.binary}' not found. Please provide a correct path.")
        sys.exit(1)

    coverage_percentage = calculate_gcc_coverage(
        binary_path=args.binary,
        inputs_folder=args.inputs_folder,
        output_dir=args.output_dir
    )

    if coverage_percentage >= 0:
        print(f"\nFinal calculated coverage: {coverage_percentage:.2f}%")
    else:
        print("\nCoverage calculation failed.")
