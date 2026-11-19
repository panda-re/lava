#!/usr/bin/env python3
"""Prepare only the libxml2 FuzzBench source and corpus.

Evidence: https://github.com/google/fuzzbench/tree/3234e151d70f6093272a9b4155e68ee57faf986c/benchmarks/libxml2_xml
The pinned benchmark metadata and Dockerfile identify source c7260a47f19e01f4f663b6a56fbdc2dafd8a6e7e.
The download URL/hash below preserve that upstream archive unchanged. Harness
and seed packaging choices follow that benchmark's build recipe; seed evidence
is documented separately in this directory's fuzzbench_inputs.py.
LAVA may discover prepare.sh before opening its configured tarball. This script
skips auto-preparation for the existing CLI JSON rather than replacing its inputs.
Manual runs require an explicit archive path, never access a parent configuration,
and may stage inputs with --inputs-dir. --setup-tree preserves modified drivers.
"""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

CONFIG_DIR = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location('local_libxml2_seeds', CONFIG_DIR / 'fuzzbench_inputs.py')
seeds = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(seeds)
TARGET = 'libxml2'
SOURCE = ('https://github.com/GNOME/libxml2/archive/c7260a47f19e01f4f663b6a56fbdc2dafd8a6e7e.tar.gz', 'libxml2-fuzzbench-c7260a4.tar.gz', '082fdf8d09c08e069de6d6bc3651a441229863fe8b4c2aeeb65067f85dc94c9c', 'fuzz/xml.c', 'fuzz/fuzzbench_driver.c')
HARNESS_BINARIES = ('xml',)


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1048576), b""):
            h.update(block)
    return h.hexdigest()


def save_json(path, value):
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        json.dump(value, stream, indent=2)
        stream.write("\n")
    try:
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def ensure_archive(tar_dir, tarfile=None):
    url, name, expected, _, _ = SOURCE
    tar_dir.mkdir(parents=True, exist_ok=True)
    archive = tarfile if tarfile is not None else tar_dir / name
    archive.parent.mkdir(parents=True, exist_ok=True)
    if archive.exists():
        if digest(archive) != expected:
            raise ValueError(f"Archive checksum mismatch; preserving existing file: {archive}")
        print(f"Archive already verified: {archive}", flush=True)
        return archive
    with tempfile.NamedTemporaryFile(dir=archive.parent, suffix=".part", delete=False) as stream:
        temporary = Path(stream.name)
    try:
        seeds.run("curl", "-fL", "--retry", "2", url, "-o", str(temporary))
        if digest(temporary) != expected:
            raise ValueError("Downloaded archive checksum differs from the audited archive")
        temporary.replace(archive)
    finally:
        temporary.unlink(missing_ok=True)
    print(f"Downloaded and verified: {archive}", flush=True)
    return archive


def setup_tree(tree):
    _, _, _, harness, driver = SOURCE
    if not (tree / harness).is_file():
        raise ValueError(f"Expected upstream harness is missing: {tree / harness}")
    if driver is None:
        if not (tree / "fuzz/test-corpus.c").is_file():
            raise ValueError("OpenSSL upstream file runner is missing")
        print("OpenSSL already has its upstream file runner; no adapter needed.")
        return
    destination = tree / driver
    data = (CONFIG_DIR / "fuzzbench_driver.c").read_bytes()
    if destination.exists():
        if destination.read_bytes() == data:
            print(f"Adapter already present: {destination}")
        else:
            print(f"Preserving existing/possibly instrumented adapter: {destination}")
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Never replace an existing file, including during concurrent setup.
    with destination.open("xb") as stream:
        stream.write(data)
    print(f"Copied adapter into fresh tree: {destination}")


def seeds_ready(output, state, identity):
    try:
        record = json.loads(state.read_text())
        if record["identity"] != identity or record["inputs_directory"] != str(output):
            return False
        manifest = output.parent / (output.name + ".fuzzbench-manifest.json")
        if digest(manifest) != record["manifest_sha256"]:
            return False
        data = json.loads(manifest.read_text())
        expected = {entry["name"]: entry["sha256"] for entry in data["entries"]
                    if entry["status"] != "too_large"}
        return bool(expected) and set(expected) == {p.name for p in output.iterdir()} and all(
            (output / name).is_file() and digest(output / name) == h
            for name, h in expected.items())
    except (OSError, ValueError, KeyError, TypeError):
        return False


def prepare_inputs(archive, work, output, jobs):
    identity = {"target": TARGET, "revision": seeds.PIN,
                "archive_sha256": SOURCE[2],
                "preparation_sha256": digest(Path(__file__)),
                "seed_helper_sha256": digest(CONFIG_DIR / "fuzzbench_inputs.py")}
    state = work / "prepared.json"
    if seeds_ready(output, state, identity):
        print(f"Inputs already verified; skipping extraction/generation: {output}")
        return
    if output.exists() and any(not p.is_file() or len(p.name) != 40
                               or any(c not in "0123456789abcdef" for c in p.name)
                               for p in output.iterdir()):
        raise ValueError(f"Existing CLI fixtures are preserved in {output}; "
                         "choose --inputs-dir with an empty directory")
    # Disposable extraction: never use LAVA's instrumented work tree here.
    with tempfile.TemporaryDirectory(dir=work, prefix="source-") as temporary:
        source = Path(temporary) / "src"
        source.mkdir()
        seeds.run("tar", "xzf", str(archive), "--strip-components=1", "-C", str(source))
        # Native seed-generator build, independent of LAVA phase flags.
        env = os.environ.copy()
        env.update(CC="clang-14", CXX="clang++-14", CFLAGS="-O0 -g", CXXFLAGS="-O0 -g")
        env.pop("LDFLAGS", None)
        env.pop("CPPFLAGS", None)
        subprocess.run(["./autogen.sh", "--disable-shared", "--without-debug",
                        "--without-ftp", "--without-http", "--without-legacy",
                        "--without-python"], cwd=source, env=env, check=True)
        subprocess.run(["make", f"-j{jobs}", "libxml2.la"],
                       cwd=source, env=env, check=True)
        with tempfile.TemporaryDirectory(dir=work, prefix="corpus-") as corpus_temp:
            files, root = seeds.seed_files(source, Path(corpus_temp))
            entries, count = seeds.write_inputs(files, root, output)
        manifest = output.parent / (output.name + ".fuzzbench-manifest.json")
        save_json(manifest, {"target": TARGET, "expected_source_revision": seeds.PIN,
                            "fuzzbench_revision": seeds.FB_COMMIT,
                            "archive": str(archive), "archive_sha256": SOURCE[2],
                            "output": str(output), "unique_inputs": count, "entries": entries})
        save_json(state, {"identity": identity, "inputs_directory": str(output),
                          "manifest_sha256": digest(manifest), "unique_inputs": count})
        print(f"Prepared {count} unique inputs in {output}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tar-dir", type=Path, help="archive directory; LAVA passes LAVA_TAR_DIR")
    parser.add_argument("--tarfile", type=Path, help="explicit archive path; LAVA passes LAVA_TARFILE")
    parser.add_argument("--inputs-dir", type=Path, help="default: this project's inputs/")
    parser.add_argument("--work-dir", type=Path, help="default: this project's .fuzzbench-prepare/")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--source-only", action="store_true")
    modes.add_argument("--setup-tree", type=Path, help="copy support before instrumentation")
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    try:
        # The existing project JSONs still run CLI workloads. Auto-discovery must
        # not silently replace them with this harness's source/corpus.
        if os.environ.get("LAVA_PROJECT_CONFIG") and not sys.argv[1:]:
            project = json.loads(Path(os.environ["LAVA_PROJECT_CONFIG"]).read_text())
            command = shlex.split(project["command"])
            if (Path(project["tarfile"]).name != SOURCE[1] or not command
                    or Path(command[0]).name not in HARNESS_BINARIES):
                print("Skipping FuzzBench preparation: this JSON still selects a different source/CLI workload.")
                return
        if args.setup_tree is not None:
            setup_tree(args.setup_tree.resolve())
            return
        tarfile = args.tarfile
        if tarfile is None and args.tar_dir is None and os.environ.get("LAVA_TARFILE"):
            tarfile = Path(os.environ["LAVA_TARFILE"])
        tar_dir = args.tar_dir or (tarfile.parent if tarfile else None)
        if tar_dir is None and os.environ.get("LAVA_TAR_DIR"):
            tar_dir = Path(os.environ["LAVA_TAR_DIR"])
        if tar_dir is None:
            parser.error("Pass --tar-dir or --tarfile; automatic LAVA preparation supplies the path")
        work = (args.work_dir or CONFIG_DIR / ".fuzzbench-prepare").resolve()
        output = (args.inputs_dir or Path(os.environ.get("LAVA_INPUTS_DIR", str(CONFIG_DIR / "inputs")))).resolve()
        work.mkdir(parents=True, exist_ok=True)
        with (work / "prepare.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            archive = ensure_archive(tar_dir.resolve(), tarfile.resolve() if tarfile else None)
            if not args.source_only:
                prepare_inputs(archive, work, output, args.jobs)
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
