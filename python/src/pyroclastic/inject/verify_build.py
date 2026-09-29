#!/usr/bin/env python3
"""
lava-verify: rebuild an injected build from its tarball alone and check it still
reproduces the manifest.

    lava-verify target_injections/toy/bugs/5/build2

Extracts build<N>/build_<N>_injection.tar.gz into build<N>/rebuild/, configures and
builds it exactly the way inject.py's validation did (configure with the project's
env_var environment, make/install with inject), then:
  - runs every clean seed and expects the manifest's expected_exit_code, and
  - runs every input in crashes/ and expects it to crash again.

This proves build<N>/ (tarball + manifest + crashes) stands on its own, without the
LAVA database or the bugs/<n>/<source_root> git checkout. It still needs a LAVA
environment (the project config, clang, compiledb) to build.
"""
import argparse
import json
import os
import shutil
import sys
import tarfile
from pathlib import Path

from ..utils.vars import LavaPaths
from ..utils.funcs import configure_project, make_and_install
from ..inject.inject import decode_output, run_modified_program


def extract_tarball(tarball: Path, dest: Path):
    with tarfile.open(tarball) as tar:
        try:
            # 'data' refuses absolute paths, links out of dest, device files, etc.
            tar.extractall(dest, filter='data')
        except TypeError:
            # Python without tarfile extraction filters
            tar.extractall(dest)


def rebuild(lp: LavaPaths, src: Path) -> bool:
    """Same steps as inject_bugs() + build_and_package(), minus the git branches."""
    configure_project(lp, main_directory=str(src))
    rv, (stdout, stderr) = make_and_install(lp, main_directory=str(src), environment="inject",
                                            capture_build=True)
    if rv != 0:
        print(f"\n[!] Rebuild failed with status {rv}. Last lines of output:")
        tail = (decode_output(stdout) + decode_output(stderr)).strip().splitlines()[-30:]
        print("\n".join(tail))
        return False
    return True


def crashed(rv: int) -> bool:
    # Same test as validate_bug(): bash reports a signal as 128 + signal
    return (rv % 256) > 128 and rv != -9


def check(lp: LavaPaths, manifest: dict, build_dir: Path, install_dir: Path) -> bool:
    project = lp.config
    ok = True

    expected = manifest["options"].get("expected_exit_code", 0)
    seed_dir = Path(project["config_dir"]) / "inputs"
    seeds = sorted(p for p in seed_dir.iterdir() if p.is_file()) if seed_dir.is_dir() else []
    print(f"\n=== Clean seeds ({len(seeds)}), expecting exit code {expected}")
    for seed in seeds:
        rv, _ = run_modified_program(project, str(install_dir), str(seed), shell=True)
        status = "OK" if rv == expected else "FAIL"
        ok &= status == "OK"
        print(f"  [{status}] {seed.name}: exit {rv}")

    crash_bugs = [b for b in manifest["bugs"] if b.get("crash")]
    print(f"\n=== Crashing inputs ({len(crash_bugs)})")
    results = []
    for bug in crash_bugs:
        crash_file = build_dir / bug["crash"]
        if not crash_file.is_file():
            results.append(("FAIL", bug, f"missing {bug['crash']}"))
            continue
        rv, _ = run_modified_program(project, str(install_dir), str(crash_file), shell=True)
        if not crashed(rv):
            results.append(("FAIL", bug, f"exit {rv}, did not crash (manifest: {bug['exit_code']})"))
        elif rv != bug["exit_code"]:
            # Still a crash, just a different signal: worth knowing, not a failure
            results.append(("OK", bug, f"exit {rv}, crashed (manifest: {bug['exit_code']})"))
        else:
            results.append(("OK", bug, f"exit {rv}"))

    for status, bug, detail in results:
        ok &= status == "OK"
        print(f"  [{status}] bug {bug['id']} {bug['type']} at {bug['atp']['file']}:{bug['atp']['line']}: {detail}")

    reproduced = sum(1 for status, _, _ in results if status == "OK")
    print(f"\n{reproduced}/{len(crash_bugs)} crashes reproduced from the tarball")
    return ok


def main():
    parser = argparse.ArgumentParser(
        prog="lava-verify",
        description="Rebuild an injected build from its tarball alone and check that it "
                    "reproduces the crashes recorded in its manifest.json.")
    parser.add_argument("build_dir", help="A bugs/<n>/build<N>/ directory made by inject")
    parser.add_argument("-p", "--project", help="Project name or config JSON "
                                                "(default: the manifest's project)")
    parser.add_argument("-o", "--out", help="Where to extract and build "
                                            "(default: <build_dir>/rebuild, replaced each run)")
    parser.add_argument("--no-check", action="store_true",
                        help="Only rebuild; don't run the seeds and crashing inputs")
    args = parser.parse_args()

    build_dir = Path(args.build_dir).resolve()
    manifest_path = build_dir / "manifest.json"
    if not manifest_path.is_file():
        sys.exit(f"No manifest.json in {build_dir}. Is this a bugs/<n>/build<N>/ directory?")
    manifest = json.loads(manifest_path.read_text())
    if not manifest.get("tarball"):
        sys.exit(f"The manifest in {build_dir} lists no tarball (did packaging fail?)")
    if not manifest.get("complete", True):
        print(f"[!] This manifest is incomplete ({manifest.get('error')}); "
              f"only the bugs it tested can be checked.")

    lp = LavaPaths(argparse.Namespace(project_name=args.project or manifest["project"]))

    if args.out:
        out = Path(args.out).resolve()
        # Never delete a directory we weren't told is ours
        if out.exists() and any(out.iterdir()):
            sys.exit(f"{out} already exists and isn't empty; pick another --out")
    else:
        out = build_dir / "rebuild"
        if out.exists():
            print(f"Removing previous rebuild at {out}")
            shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)

    tarball = build_dir / manifest["tarball"]
    print(f"Extracting {tarball} into {out}")
    extract_tarball(tarball, out)
    src = out / manifest["source_root"]
    if not src.is_dir():
        sys.exit(f"Expected {src} after extracting, but it isn't there")

    print(f"\n=== Rebuilding build{manifest['build']} of {manifest['project']} in {src}")
    if not rebuild(lp, src):
        sys.exit(1)
    install_dir = src / "lava-install"
    print(f"Rebuilt and installed into {install_dir}")

    if args.no_check:
        return
    if not check(lp, manifest, build_dir, install_dir):
        print("\n[!] The rebuilt binary does NOT match the manifest")
        sys.exit(1)
    print("\nThe rebuilt binary matches the manifest")


if __name__ == "__main__":
    main()
