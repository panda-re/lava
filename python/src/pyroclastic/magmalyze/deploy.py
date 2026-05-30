import os
import tarfile
import argparse
from pathlib import Path
import shutil
import shlex
import re
import subprocess

from ..utils.vars import parse_vars
from ..add_queries.add_queries import run_cmd

# Should Squash with the one in add_queries.py and lava.py
class GenerationManager:
    def __init__(self, args: argparse.Namespace):
        self.config = parse_vars(args.project_name)
        self.name = self.config['name']
        self.directory = Path(self.config['generation_dir'])
        self.project_dir = self.directory / self.name
        self.tarfile_path = Path(self.config['tarfile'])
        self.source_path = ''
        self.install_dir = ''
        self.guest_directory_inputs_path = ''
        self.unpack()
        self.copy_inputs()

    def unpack(self):
        """
        This is used within the initialization but completes the following steps:
        1. Create the project directory in the target_generation
        2. unpack the Tar package, it deletes any existing unpacking
        3. Create the installation directory which will be used for code coverage and/or generating inputs
        """
        # 1. Setup Directories
        if not self.project_dir.exists():
            self.project_dir.mkdir(parents=True)

        os.chdir(self.project_dir)

        # 2. Extract Tarball
        with tarfile.open(self.tarfile_path) as tar:
            # Get top level directory name of the tar-ball
            source_dirname = tar.getnames()[0].split(os.path.sep)[0]
            self.source_path = self.project_dir / source_dirname

            if self.source_path.exists():
                print(f"Deleting existing source: {self.source_path}")
                shutil.rmtree(self.source_path)

            print(f"Extracting {self.tarfile_path}...")
            tar.extractall(path=self.project_dir)

        print(f"Changing to source directory to {self.source_path}")
        os.chdir(self.source_path)

        # 3. Configure
        install_dir = self.source_path / "lava-install"
        install_dir.mkdir(exist_ok=True)
        self.install_dir = install_dir


    def copy_inputs(self):
        """
        Copy the inputs folder from the config_dir into the `target_generation`/<project> folder.
        We use this so when we generate new inputs, it is in target_generation/<project>/inputs folder
        """
        input_file_directory = os.path.abspath(os.path.join(self.config["config_dir"], "inputs"))
        self.guest_directory_inputs_path = os.path.join(self.install_dir, 'inputs')
        if os.path.exists(self.guest_directory_inputs_path):
            shutil.rmtree(self.guest_directory_inputs_path)
        shutil.copytree(input_file_directory, self.guest_directory_inputs_path)

    def compile(self, coverage: bool = False):
        """
        Compiles the project using `make` and installs it.
        Args:
            coverage: if True, use coverage environment variables for compilation.
        """
        if coverage:
            envv = self.config['llvm_cov']
        else:
            envv = self.config['env_var']

        configure_command = self.config.get('configure', '')
        if configure_command != '':
            print('Configuring...')
            full_config = f"{configure_command} --prefix={self.install_dir}"
            run_cmd(shlex.split(full_config), env=envv, cwd=self.source_path)
        run_cmd(self.config['make'], env=envv, shell=True, cwd=self.source_path)
        run_cmd(self.config['install'], env=envv, shell=True, cwd=self.source_path)

    def get_coverage(self) -> float:
        """
        Calculates code coverage using GCC's GCOV/LCOV profiling tools.

        This function assumes:
        1. The C source code for the binary was compiled with GCC's coverage flags
           (e.g., `gcc -g --coverage -fprofile-arcs -ftest-coverage your_program.c -o your_program`).
        2. 'Lcov' and 'genhtml' tools are installed and available in your system's PATH.

        Returns:
            float: The calculated overall line coverage percentage, or -1.0 if calculation fails.
        """
        self.compile(coverage=True)
        print(f"[*] Executing binary with inputs to collect LLVM coverage data...")

        # Modern LLVM coverage uses environment variables to define output paths
        # We'll collect all raw profiles in a temporary folder
        profraw_dir = os.path.join(self.project_dir, "profraw")
        if os.path.exists(profraw_dir):
            shutil.rmtree(profraw_dir)
        os.makedirs(profraw_dir)

        # Set the pattern for raw profile output
        # %p = pid, %m = binary signature. This ensures multi-run data is preserved.
        env = os.environ.copy()
        env["LLVM_PROFILE_FILE"] = os.path.join(profraw_dir, "data-%p.profraw")

        # --- Step 1: Execute binary with all inputs to generate .gcda files ---
        for filename in os.listdir(self.guest_directory_inputs_path):
            filepath = os.path.join(self.guest_directory_inputs_path, filename)
            if os.path.isfile(filepath):
                # Using the compiled binary from the installation path
                full_command = self.config['command'].format(
                    install_dir=shlex.quote(str(self.install_dir)),
                    input_file=shlex.quote(filepath)
                ).strip()

                print(f"    - Running {full_command}")
                try:
                    subprocess.run(full_command.split(),
                                   cwd=self.source_path,
                                   env=env,
                                   capture_output=True, text=True, check=False)
                except Exception as e:
                    print(f"[-] Error running coverage execution: {e}")

        # --- Step 2: Merge raw profiles using llvm-profdata ---
        # lcov/gcov is no longer needed. We use LLVM's internal tools.
        profdata_tool = os.path.join(self.config['llvm-dir'], "bin", "llvm-profdata")
        cov_tool = os.path.join(self.config['llvm-dir'], "bin", "llvm-cov")
        indexed_profdata = os.path.join(self.project_dir, "coverage.profdata")

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
        instrumented_binary = self.config['command'].format(
            install_dir=str(self.install_dir),
            input_file=""
            ).split()[0].strip()

        html_output = os.path.join(self.project_dir, "html")
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