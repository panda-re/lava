import json
import os
from pathlib import Path


def get_valid_architectures():
    return ['panda-system-x86_64', 'panda-system-aarch64', 'panda-system-arm', 'panda-system-i386']


def get_host_config():
    """
    Finds host.json in a prioritized search order to support both
    CI/CD (local repo) and Installed (Wheel) modes.
    """
    # 1. Check for an environment variable override (Best for CI/CD)
    env_path = os.environ.get("LAVA_HOST_CONFIG")
    if env_path and os.path.exists(env_path):
        return env_path

    # 2. Check the current directory (Repo mode)
    cwd_path = Path.cwd() / "host.json"
    if cwd_path.exists():
        return str(cwd_path)

    # 3. Check the standard installed location
    home_path = Path.home() / ".lava" / "host.json"
    if home_path.exists():
        return str(home_path)

    raise FileNotFoundError("Could not find host.json. Run 'lava init' first.")


class Project:
    """ Simple getter/setter class so we can support .get like a JSON file"""

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
    # Path to configs
    assert 'config_dir' in host
    # path to qemu exec (correct guest)
    assert 'qemu' in host
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


def parse_vars(project_name: str):
    host_json_path = get_host_config()
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

    for field, prefix in [("tarfile", "tar_dir")]:
        project_data[field] = host[prefix] + os.path.sep + project_data[field]

    for field, suffix in [("db", "db_suffix")]:
        project_data[field] = project_data[field] + host[suffix]

    for field in ["inputs"]:
        if field not in project_data.keys(): continue
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
    project_data["output_dir"] = host["output_dir"] + os.path.sep + project_data["name"]
    project_data["directory"] = host["output_dir"]
    project_data["config_dir"] = host["config_dir"] + os.path.sep + project_data["name"]
    project_data["debug"] = host.get("debug", False)

    # Replace format strings in project configs
    project_data["install"] = project_data["install"].format(config_dir=project_data["config_dir"])
    project_data["llvm-dir"] = host.get("llvm", "/usr/lib/llvm-14")
    project_data["llvm-version"] = project_data["llvm-dir"].split('-')[-1]
    project_data["complete_rr"] = host.get("complete_rr", False)
    project_data["env_var"] = \
            {'CC': os.path.join(project_data["llvm-dir"], 'bin/clang'),
            'CXX': os.path.join(project_data["llvm-dir"], 'bin/clang++'),
            'CFLAGS': '-O0 -DHAVE_CONFIG_H -g -gdwarf-2 -fno-stack-protector -D_FORTIFY_SOURCE=0 -I. -I.. -I../include -I./src/'}
    project_data["full_env_var"] = \
            {'CC': os.path.join(project_data["llvm-dir"], 'bin/clang'),
            'CXX': os.path.join(project_data["llvm-dir"], 'bin/clang++'),
            'CFLAGS': '-Wno-int-conversion -O0 -DHAVE_CONFIG_H -g -gdwarf-2 -fno-stack-protector -D_FORTIFY_SOURCE=0 -I. -I.. -I../include -I./src/'}
    project_data["panda_compile"] = \
            {'CC': os.path.join(project_data["llvm-dir"], 'bin/clang'),
            'CXX': os.path.join(project_data["llvm-dir"], 'bin/clang++'),
            'CFLAGS': '-static -O0 -DHAVE_CONFIG_H -g -gdwarf-2 -fno-stack-protector -D_FORTIFY_SOURCE=0 -I. -I.. -I../include -I./src/'}

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
