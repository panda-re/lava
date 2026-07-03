import json
import os
import argparse
import subprocess
import sys
from pathlib import Path


class LavaPaths(object):
    def __init__(self, args: argparse.Namespace):
        self.config = parse_vars(args.project_name)
        self.name = self.config['name'] # Project name
        self.directory = Path(self.config['directory'])
        self.bugs_directory = self.directory / self.name / "bugs"
        self.logs_directory = self.directory / self.name / "logs"
        self.sql_file = Path(__file__).parent.parent / "data" / "lava.sql"
        tar_files = subprocess.check_output(['tar', 'tf', self.config['tarfile']], stderr=sys.stderr)
        self.tar_source_root = tar_files.decode().splitlines()[0].split(os.path.sep)[0]
        self.source_directory = self.directory / self.name / self.tar_source_root
        self.project_dir = self.directory / self.name
        self.tar_to_unzip_path = Path(self.config['tarfile'])
        self.llvm_path = Path(self.config.get('llvm', '/usr/lib/llvm-14'))

        # Used by the Coverage/Generate Inputs step
        self.generate_project_root_directory = Path(self.config['generation_dir']) / self.name
        self.generate_project_root_unpacked_tar_directory = self.generate_project_root_directory / self.tar_source_root
        self.generate_executable_install_dir = ''
        self.generate_directory_inputs_path = ''

        # Injection
        self.output_dir = self.config['output_dir']
        self.lavadb = os.path.join(self.output_dir, 'lavadb')
        self.lava_tool = 'lavaTool'
        self.queries_build = os.path.join(self.output_dir, self.tar_source_root)
        self.bugs_top_dir = os.path.join(self.output_dir, 'bugs')
        self.bugs_parent = ''
        self.bugs_build = ''
        self.bugs_install = ''

    def set_bugs_parent(self, bugs_parent: str):
        assert self.bugs_top_dir == os.path.dirname(bugs_parent)
        self.bugs_parent = bugs_parent
        self.bugs_build = os.path.join(self.bugs_parent, self.tar_source_root)
        self.bugs_install = os.path.join(str(self.bugs_build), 'lava-install')


def get_valid_architectures():
    return ['x86_64', 'aarch64', 'arm', 'i386']


class Project:
    """
    Simple getter/setter class so we can support .get like a JSON file
    """

    def __init__(self, data):
        self.values = data

    def __getitem__(self, key):
        return self.values[key]

    def __setitem__(self, key, value):
        self.values[key] = value

    def __contains__(self, key):
        return key in self.values

    def get(self, field, default):
        if field in self.values:
            return self.values[field]
        else:
            return default

    def keys(self):
        return self.values.keys()


def validate_host(host: dict):
    # Path to binaries
    assert 'tar_dir' in host
    # Path to configs
    assert 'config_dir' in host
    # path to qemu exec (correct guest)
    assert 'qemu' in host
    # path for input generation/coverage testing
    assert 'generation_dir' in host
    assert host['qemu'] in get_valid_architectures()


def validate_project(project_dict: dict):
    # name of project
    assert 'name' in project_dict
    # command line to run the target program (already instrumented with taint and attack queries)
    assert 'command' in project_dict
    # path to tarfile for target (original source)
    assert 'tarfile' in project_dict
    # namespace in db for prospective bugs
    assert 'db' in project_dict


def get_project_env(llvm_dir: str, arch: str = "x86_64", mode: str = "default"):
    """
    Generates environment variables based on target architecture.
    mode: 'default', 'inject', 'llvm_cov' or 'panda'
    """
    clang = os.path.join(llvm_dir, 'bin' , 'clang')
    clang_pp = os.path.join(llvm_dir, 'bin', 'clang++')

    # 1. Base flags common to ALL architectures
    base_cflags = [
        "-O0", "-DHAVE_CONFIG_H", "-g", "-gdwarf-2",
        "-fno-stack-protector", "-D_FORTIFY_SOURCE=0",
        "-I.", "-I..", "-I../include", "-I./src/",
        "-D_GNU_SOURCE",
        "-Wno-implicit-function-declaration"
    ]

    # 2. Architecture-Specific Flags
    arch_flags = {
        "x86_64": [],
        "i386": ["-m32"],
        "arm": ["--target=arm-linux-gnueabi", "-marm", "-march=armv5t", "--gcc-toolchain=/usr"],
        "aarch64": ["--target=aarch64-linux-gnu", "-march=armv8-a", "--gcc-toolchain=/usr"]
    }

    # 3. Mode-Specific Flags
    mode_extras = {
        "default": [],
        # On injection step, we will mess with points, so we need this flag
        "inject": ["-Wno-int-conversion"],
        # When compiling for PANDA, we need to ensure static linking
        "panda": ["-static"],
        # Modern LLVM coverage (uses llvm_cov/llvm-profdata)
        "llvm_cov": ["-fprofile-instr-generate", "-fcoverage-mapping"]
    }

    # Build the final CFLAGS string
    selected_mode_flags = mode_extras.get(mode, [])
    final_cflags = base_cflags + arch_flags.get(arch, []) + selected_mode_flags

    env = {
        'CC': clang,
        'CXX': clang_pp,
        'CFLAGS': " ".join(final_cflags),
        'CXXFLAGS': " ".join(final_cflags)
    }

    # If we are doing coverage, we often need to pass the same flags to the linker
    ldflags = []
    if mode == "llvm_cov":
        ldflags.extend(selected_mode_flags)
    elif mode == "panda":
        # Force the linker to strictly build a non-PIE, static executable (Add PIE later...?)
        ldflags.extend(["-static"])

    if ldflags:
        env['LDFLAGS'] = " ".join(ldflags)
    return env


def parse_vars(project_name: str):
    host_json_path = Path.cwd() / "host.json"
    with open(host_json_path, 'r') as f:
        host = json.load(f)

    try:
        validate_host(host)
    except AssertionError:
        print("Your host.json file is missing a required field")
        raise

    config_path = "{0}/{1}/{1}.json".format(host['config_dir'], project_name)
    if not os.path.isfile(config_path):
        raise RuntimeError("Could not find project config file at {}".format(config_path))

    with open(config_path, 'r') as host_f:
        project_data = json.load(host_f)

    try:
        validate_project(project_data)
    except AssertionError as e:
        print("Your project config file is missing a required field:\n{}".format(e))
        raise

    project_data["host_path"] = host_json_path
    for field, prefix in [("tarfile", "tar_dir")]:
        project_data[field] = os.path.join(host[prefix], project_data[field])

    for field, suffix in [("db", "db_suffix")]:
        project_data[field] = project_data[field] + host[suffix]

    for field in ["inputs"]:
        if field not in project_data.keys():
            continue
        target_val = []
        for inp in project_data["inputs"]:
            target_val.append("{config_dir}/{name}/{field}".format(config_dir=host["config_dir"],
                                                                   name=project_data["name"], field=inp))
        project_data["inputs"] = target_val

    for field in ["injfixupsscript", "fixupsscript"]:
        if field not in project_data.keys():
            continue
        project_data[field] = ("{config_dir}/{name}/{field}".format(config_dir=host["config_dir"],
                                                                    name=project_data["name"], field=project_data[field]))

    # Database config
    project_data["database"] = host.get("host", "database")
    project_data["database_port"] = host.get("port", 5432)
    project_data["database_user"] = host.get("pguser", "postgres")

    # Other config
    project_data["qemu"] = host["qemu"]
    project_data["generation_dir"] = host["generation_dir"]
    project_data["output_dir"] = os.path.join(host["output_dir"], project_data["name"])
    project_data["directory"] = host["output_dir"]
    project_data["config_dir"] = os.path.join(host["config_dir"], project_data["name"])
    project_data["debug"] = host.get("debug", False)

    # Replace format strings in project configs
    project_data["install"] = project_data["install"].format(config_dir=project_data["config_dir"])
    project_data["llvm-dir"] = host.get("llvm", "/usr/lib/llvm-14")
    project_data["complete_rr"] = host.get("complete_rr", False)
    project_data["use_c_fbi"] = host.get("use_c_fbi", True)
    project_data["env_var"] = get_project_env(project_data["llvm-dir"], host["qemu"], "default")
    project_data["inject"] = get_project_env(project_data["llvm-dir"], host["qemu"], "inject")
    project_data["panda"] = get_project_env(project_data["llvm-dir"], host["qemu"], "panda")
    project_data["llvm_cov"] = get_project_env(project_data["llvm-dir"], host["qemu"], "llvm_cov")
    return Project(project_data)


if __name__ == '__main__':
    # Basic test
    import sys
    import pprint

    project = parse_vars(sys.argv[1])
    # project = parse_vars("toy")
    pprint.pprint(project.values)
    project["foo"] = "good_fake_val"
    assert "good" in (project.get('fake', 'good_fake_val'))
    assert "good" in (project.get('foo', 'bad_fake_val'))
    assert "bad" not in (project.get('qemu', 'bad_fake_val'))
