"""Select a subset of a LAVA project's seed corpus using AFL++ coverage.

Run `lava-seed-minimize -p PROJECT` from a workspace with `host.json`.
The command builds a temporary native AFL++ target using the project's build
instructions and runs afl-cmin against copies of seeds from `<config_dir>/inputs`.
It writes the selected files to `<config_dir>/seed-min` with their original
paths and records kept and filtered seeds in the adjacent
`seed-min.manifest.json`. In the recorded command, `-i inputs -o seed-min`
is relative to the temporary working directory. The recorded elapsed time
covers only afl-cmin.
Pass `--keep-build` to retain the instrumented target for auditing.
Move both outputs aside to run the command again.
"""

import argparse
import hashlib
import json
import os
import shlex
import shutil
import subprocess
from contextlib import nullcontext
from pathlib import Path
from tempfile import TemporaryDirectory, mkdtemp
from time import perf_counter

from ..utils.funcs import configure_project, make_and_install, unpack_tar
from ..utils.vars import LavaPaths, get_project_env


def sha256(path: Path) -> str:
    """Return the hexadecimal SHA-256 digest of a file."""
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def seed_inventory(directory: Path) -> list[dict]:
    """List seed paths, sizes, and digests in path order, excluding AFL traces."""
    return [
        {
            "path": path.relative_to(directory).as_posix(),
            "size_bytes": path.stat().st_size,
            "sha256": sha256(path),
        }
        for path in sorted(directory.rglob("*"))
        if path.is_file() and path.relative_to(directory).parts[0] != ".traces"
    ]


def require_tool(name: str) -> str:
    """Find a tool on PATH while preserving the compiler wrapper's name."""
    path = shutil.which(name)
    if path is None:
        raise FileNotFoundError(f"{name} is missing from PATH. Install AFL++.")
    # Keep the compiler wrapper's basename: AFL++ uses it to choose its mode.
    return os.path.abspath(path)


def afl_package_version() -> str | None:
    """Return the installed AFL++ Debian package version if available."""
    if shutil.which("dpkg-query"):
        result = subprocess.run(
            ["dpkg-query", "-W", "-f=${Version}", "afl++"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    return None


def build_target(lava_paths: LavaPaths, build_root: Path) -> list[str]:
    """Build a native AFL++ target and return its command with an @@ placeholder."""
    # afl-cmin executes the target on the host, independently of the PANDA guest.
    build_env = get_project_env(str(lava_paths.llvm_path))
    build_env.update(CC=require_tool("afl-clang-fast"), CXX=require_tool("afl-clang-fast++"))
    lava_paths.config["afl_cmin"] = build_env
    lava_paths.config["config_dir"] = str(lava_paths.config_dir)

    unpack_tar(lava_paths, main_directory=str(build_root))
    source = str(build_root / lava_paths.tar_source_root)
    install_dir = configure_project(lava_paths, main_directory=source, environment="afl_cmin")
    make_and_install(lava_paths, main_directory=source, environment="afl_cmin")
    return [
        arg.format(install_dir=install_dir, input_file="@@")
        for arg in shlex.split(lava_paths.config["command"])
    ]


def minimize_corpus(seeds: Path, output: Path, target_command: list[str]) -> Path:
    """Run afl-cmin on staged copies and publish the selected corpus and manifest."""
    cmin = require_tool("afl-cmin")
    target = shutil.which(target_command[0])
    if target is None:
        raise FileNotFoundError(f"Target is missing or not executable: {target_command[0]}")

    manifest_path = output.with_name(f"{output.name}.manifest.json")
    if os.path.lexists(output) or os.path.lexists(manifest_path):
        raise FileExistsError(f"Move the previous results at {output} and {manifest_path} before rerunning.")

    input_seeds = seed_inventory(seeds)
    candidates = [seed for seed in input_seeds if seed["size_bytes"]]
    if not candidates:
        raise ValueError(f"No nonempty seeds in {seeds}")

    with TemporaryDirectory(prefix=".seed-min-", dir=output.parent) as temporary_dir:
        work_dir = Path(temporary_dir)
        staged_inputs = work_dir / "inputs"
        staged_output = work_dir / "seed-min"
        staged_inputs.mkdir()
        # Some afl-cmin versions write into the input directory and identify
        # seeds by basename. Stage copies with unique names and restore paths.
        staged_seeds = {
            f"seed-{index:08d}": seed for index, seed in enumerate(candidates)
        }
        for name, seed in staged_seeds.items():
            shutil.copyfile(seeds / seed["path"], staged_inputs / name)

        command = [
            cmin, "-i", staged_inputs.name, "-o", staged_output.name, "--",
            os.path.abspath(target), *target_command[1:],
        ]
        started = perf_counter()
        subprocess.run(command, cwd=work_dir, check=True)
        elapsed_seconds = perf_counter() - started

        selected = seed_inventory(staged_output)
        if not selected:
            raise RuntimeError("afl-cmin selected no seeds")

        result_dir = work_dir / "restored"
        result_dir.mkdir()
        selected_paths = set()
        for seed in selected:
            original = staged_seeds.get(seed["path"])
            if original is None or original["sha256"] != seed["sha256"]:
                raise RuntimeError(f"Unexpected afl-cmin output: {seed['path']}")
            destination = result_dir / original["path"]
            destination.parent.mkdir(parents=True, exist_ok=True)
            (staged_output / seed["path"]).rename(destination)
            selected_paths.add(original["path"])

        manifest = {
            "command": command,
            "working_directory": str(work_dir),
            "input_directory": str(seeds),
            "output_directory": str(output),
            "aflplusplus_deb_version": afl_package_version(),
            "afl_cmin_sha256": sha256(Path(cmin)),
            "afl_environment": {
                key: value for key, value in os.environ.items() if key.startswith("AFL_")
            },
            "target_sha256": sha256(Path(target)),
            "elapsed_seconds": elapsed_seconds,
            "input_seeds": input_seeds,
            "selected_seeds": [seed for seed in input_seeds if seed["path"] in selected_paths],
            "filtered_seeds": [seed for seed in input_seeds if seed["path"] not in selected_paths],
        }

        staged_manifest = work_dir / manifest_path.name
        staged_manifest.write_text(json.dumps(manifest, indent=4) + "\n", encoding="utf-8")
        # Publish only complete results. Linking reserves the manifest path
        # exclusively if two minimizations finish at the same time.
        manifest_path.hardlink_to(staged_manifest)
        try:
            result_dir.rename(output)
        except OSError:
            manifest_path.unlink()
            raise

    return output


def main():
    """Build and minimize the LAVA project selected on the command line."""
    parser = argparse.ArgumentParser(description="Minimize a LAVA project's inputs with AFL++ coverage.")
    parser.add_argument("--project", "-p", required=True, dest="project_name", help="LAVA project name")
    parser.add_argument(
        "--keep-build", action="store_true",
        help="retain the AFL++ target build in the project's generation directory",
    )
    args = parser.parse_args()

    try:
        require_tool("afl-cmin")
        lava_paths = LavaPaths(args)
        seeds = lava_paths.config_dir / "inputs"
        output = lava_paths.config_dir / "seed-min"
        manifest_path = output.with_name(f"{output.name}.manifest.json")
        if os.path.lexists(output) or os.path.lexists(manifest_path):
            raise FileExistsError(f"Move the previous results at {output} and {manifest_path} before rerunning.")
        if not seeds.is_dir():
            raise FileNotFoundError(f"Seed directory does not exist: {seeds}")

        generation_dir = lava_paths.generate_project_root_directory.resolve()
        generation_dir.mkdir(parents=True, exist_ok=True)
        if args.keep_build:
            retained_build = mkdtemp(prefix="afl-cmin-build-", dir=generation_dir)
            print(f"AFL++ build directory: {retained_build}", flush=True)
            build_context = nullcontext(retained_build)
        else:
            build_context = TemporaryDirectory(prefix="afl-cmin-build-", dir=generation_dir)
        with build_context as build_dir:
            target_command = build_target(lava_paths, Path(build_dir))
            minimize_corpus(seeds, output, target_command)
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"{parser.prog}: {error}\n")

    print(f"Minimized seeds: {output}")
    print(f"Manifest: {manifest_path}")


if __name__ == "__main__":
    main()
