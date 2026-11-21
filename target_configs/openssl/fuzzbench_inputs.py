#!/usr/bin/env python3
"""openssl FuzzBench seed provenance.

The pinned build.sh zips fuzz/corpora/${fuzzer}/*; x509 selects raw DER cases.
The source archive excludes this corpus via .gitattributes export-ignore, so
we fetch its exact historical Git tree when absent, not a current OSS-Fuzz ZIP.
Source revision: b0593c086dd303af31dc1e30233149978dd613c4
FuzzBench recipe: https://github.com/google/fuzzbench/tree/3234e151d70f6093272a9b4155e68ee57faf986c/benchmarks/openssl_x509
Normalization (1 MiB limit, SHA-1 names/content deduplication):
https://github.com/google/fuzzbench/blob/3234e151d70f6093272a9b4155e68ee57faf986c/experiment/runner.py
This file is intentionally project-local and requires no sibling configurations.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

TARGET = 'openssl'
PIN = 'b0593c086dd303af31dc1e30233149978dd613c4'
FB_COMMIT = '3234e151d70f6093272a9b4155e68ee57faf986c'


def run(*args):
    subprocess.run(args, check=True)


def seed_files(source, temporary):
    corpus = source / "fuzz/corpora/x509"
    if not corpus.is_dir():
        # Source archives omit this directory through upstream export-ignore.
        checkout = temporary / "openssl-corpus"
        run("git", "init", str(checkout))
        run("git", "-C", str(checkout), "remote", "add", "origin",
            "https://github.com/openssl/openssl.git")
        run("git", "-C", str(checkout), "fetch", "--depth=1", "origin", PIN)
        run("git", "-C", str(checkout), "restore", "--source=" + PIN,
            "--worktree", "--", "fuzz/corpora/x509")
        corpus = checkout / "fuzz/corpora/x509"
    return sorted(p for p in corpus.iterdir() if p.is_file()), corpus


def write_inputs(files, source, output):
    """Write content-addressed seeds, refusing to mix in unrecognized inputs."""
    selected, entries = {}, []
    for path in files:
        if not path.is_file():
            continue
        size = path.stat().st_size
        entry = {"source": str(path.relative_to(source)), "bytes": size}
        if size > 1048576:
            entry["status"] = "too_large"
        else:
            data = path.read_bytes()
            name = hashlib.sha1(data).hexdigest()
            entry.update(name=name, sha256=hashlib.sha256(data).hexdigest(),
                         status="duplicate" if name in selected else "retained")
            if name in selected and selected[name] != data:
                raise ValueError("SHA-1 collision")
            selected[name] = data
        entries.append(entry)
    if not selected:
        raise ValueError("No seed files found; check the source revision/path")
    if output.exists():
        for existing in output.iterdir():
            if (not existing.is_file() or existing.name not in selected
                    or existing.read_bytes() != selected[existing.name]):
                raise ValueError(f"Refusing to mix/replace existing inputs: {existing}. "
                                 "Use --output with an empty directory.")
    output.mkdir(parents=True, exist_ok=True)
    for name, data in selected.items():
        (output / name).write_bytes(data)
    return entries, len(selected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="pinned unpacked source directory")
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parent / "inputs")
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    try:
        with tempfile.TemporaryDirectory(prefix="fuzzbench-seeds-") as temp:
            files, corpus_root = seed_files(source, Path(temp))
            entries, count = write_inputs(files, corpus_root, output)
        report = {"target": TARGET, "expected_source_revision": PIN,
                  "fuzzbench_revision": FB_COMMIT, "source_directory": str(source),
                  "output": str(output), "unique_inputs": count,
                  "note": "Use the pinned source; supplied trees are not fully rehashed.",
                  "entries": entries}
        manifest = output.parent / (output.name + ".fuzzbench-manifest.json")
        manifest.write_text(json.dumps(report, indent=2) + "\n")
        print(f"{len(entries)} source files -> {count} unique inputs in {output}")
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
