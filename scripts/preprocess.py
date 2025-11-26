#!/usr/bin/env python3
import argparse
import os
import re
import subprocess
from shlex import split as shlex_split
import tarfile


def run_make_verbose(project_dir: str, debug=False) -> str:
    """
    Runs the `make` command with verbose output (V=1) in the specified project directory.
    Captures the output of the `make` command and extracts compile commands from it.

    Args:
        project_dir (str): Path to the project directory where `make` will be executed.
        debug (bool): If True, prints additional debug information.

    Returns:
        list: A list of compile commands extracted from the `make` output.
    """
    print(f"[+] Running make clean in {project_dir}")
    subprocess.run(["make", "clean"],
                            cwd=project_dir,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            universal_newlines=True)

    print(f"[+] Running V=1 make in {project_dir}")
    make_out = subprocess.run(["make", "V=1"],
                              cwd=project_dir,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT,
                              universal_newlines=True)    
    print(f"[+] Extracting compile commands from make output")
    commands = []
    for line in make_out.stdout.splitlines():
        if debug:
            print("command", line)
        if re.search(r"\.c\b", line):
            commands.append(line)
        else:
            if debug:
                print("command is skipped")
    return commands


def transform_to_preprocess(command: str, debug=False) -> tuple:
    """
    Transforms a compile command into a preprocessing command by modifying its arguments.

    Args:
        command (str): A compile command extracted from the `make` output.

    Returns:
        tuple: A tuple containing:
            - pre_tokens (list): The transformed preprocessing command as a list of tokens.
            - output_file (str): The name of the output file for the preprocessing step.
    """
    tokens = shlex_split(command)
    pre_tokens = []
    output_file = None
    skip_next = False

    for i, tok in enumerate(tokens):
        if debug:
            print(f"Processing token {i}: {tok}")
        
        if skip_next:
            skip_next = False
            continue
        if tok in ["-c", "-o", "-MT", "-MD", "-MP", "-MF"]:
            skip_next = True
            continue
        if tok == "-g" or tok.startswith("-O"):
            continue
        if tok.endswith(".c"):
            # Rename original .c file to .c.orig
            output_file = tok.replace(".c", "-pre.c")
        pre_tokens.append(tok)

    pre_tokens.append("-E")
    pre_tokens.append("-o")
    pre_tokens.append(output_file)
    return pre_tokens, output_file


def preprocess_sources(project_dir: str, debug=False):
    """
    Preprocesses all C source files in the specified project directory by transforming
    compile commands into preprocessing commands and executing them.

    Also makes sure to add the following two lines on top, to avoid macro issues
    define __attribute__(x)
    #define __extension__(x)

    Args:
        project_dir (str): Path to the project directory containing the source files.
    """
    commands = run_make_verbose(project_dir, debug)
    print(f"[+] Found {len(commands)} compile commands to transform")

    for cmd in commands:
        pre_tokens, out_file = transform_to_preprocess(cmd, debug)
        if not out_file:
            continue
        if debug:
            print(f"[DEBUG] Preprocessing command: {' '.join(pre_tokens)}")
        print(f"[+] Generating {out_file}")
        try:
            subprocess.run(pre_tokens, cwd=project_dir, check=True)
            # Add required lines to the top of the preprocessed file
            with open(os.path.join(project_dir, out_file), "r+") as f:
                content = f.read()
                f.seek(0, 0)
                f.write("#define __attribute__(x)\n#define __extension__(x)\n" + content)
        
            # Rename toy.c to toy.c.orig
            unaltered_file = os.path.join(project_dir, out_file.replace("-pre.c", ".c"))
            original_file = os.path.join(project_dir, out_file.replace("-pre.c", ".c.orig"))

            if os.path.exists(unaltered_file):
                os.rename(unaltered_file, original_file)
            else:
                print(f"[ERROR] File not found: {unaltered_file}")

            # Rename toy-pre.c to toy.c
            preprocessed_file = os.path.join(project_dir, out_file)
            final_file = preprocessed_file.replace("-pre.c", ".c")

            if os.path.exists(preprocessed_file):
                os.rename(preprocessed_file, final_file)
            else:
                print(f"[ERROR] File not found: {preprocessed_file}")
            
            # Run make clean for good measure
            subprocess.run(["make", "clean"],
                            cwd=project_dir,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            universal_newlines=True)
        
        except subprocess.CalledProcessError as e:
            print(f"[-] Failed to run: {' '.join(pre_tokens)}")
            print(f"    Error: {e}")


def create_tarball(source_dir: str, output_tar: str):
    """
    Creates a tarball (compressed archive) of the specified source directory.

    Args:
        source_dir (str): Path to the directory to be archived.
        output_tar (str): Path to the output tarball file.
    """
    with tarfile.open(output_tar, "w:gz") as tar:
        tar.add(source_dir, arcname=os.path.basename(source_dir))
    print(f"[+] Created tarball: {output_tar}")


def main():
    """
    Main entry point for the script. Parses command-line arguments, preprocesses
    C source files, and creates a tarball of the preprocessed files.

    You want your folder in target_bin directory, so it will create a <file>-pre.tar.gz file

    python3 ./scripts/preprocess.py ./target_bin/<source_dir>
    """
    parser = argparse.ArgumentParser(description="Generate preprocessed C source files from a project")
    parser.add_argument("source_dir", type=str, help="Path to the source code folder")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args()

    source_path = os.path.abspath(args.source_dir)
    if not os.path.isdir(source_path):
        print(f"[-] Provided source directory does not exist: {source_path}")
        exit(1)
    preprocess_sources(source_path, args.debug)

    # Create the tarball of the pre-processed code
    parent_dir = os.path.dirname(source_path)  # target_bin directory
    tar_file_path = os.path.join(parent_dir, f"{os.path.basename(args.source_dir)}-pre.tar.gz")
    create_tarball(args.source_dir, tar_file_path)

if __name__ == "__main__":
    main()
