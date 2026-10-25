# LAVA: Large Scale Automated Vulnerability Addition

[![Publish Lava Package and Container](../../actions/workflows/publish_docker.yml/badge.svg)](../../actions/workflows/publish_docker.yml)

[![Lava Tests](../../actions/workflows/parallel_tests.yml/badge.svg)](../../actions/workflows/parallel_tests.yml)

Evaluating and improving bug-finding tools is currently difficult due to
a shortage of ground truth corpora (i.e., software that has known bugs
with triggering inputs). LAVA attempts to solve this problem by
automatically injecting bugs into software. Every LAVA bug is
accompanied by an input that triggers it whereas normal inputs are
extremely unlikely to do so. These vulnerabilities are synthetic but, we
argue, still realistic, in the sense that they are embedded deep within
programs and are triggered by real inputs. Our work forms the basis of
an approach for generating large ground-truth vulnerability corpora on
demand, enabling rigorous tool evaluation and providing a high-quality
target for tool developers.

LAVA is the product of a collaboration between MIT Lincoln Laboratory,
NYU, and Northeastern University.

# Quick Start

## Docker
The latest version of LAVA's `master` branch is automatically built as a docker images based on Ubuntu 22.04 and published to [Docker Hub](https://hub.docker.com/r/pandare/lava). Most users will want to use the `lava` container which has PANDA and LAVA installed along with their runtime dependencies, but no build artifacts or source code to reduce the size of the container.

To use the `lava` container you can pull it from Docker Hub:
```
$ docker pull pandare/lava
```
Or build from this repository:
```
$ DOCKER_BUILDKIT=1 docker build -t pandare/lava:local .
```

If Docker Engine runs directly inside WSL and build steps cannot access the
network (for example, APT reports `Temporary failure resolving`), try using
WSL's host network for the build:

```bash
DOCKER_BUILDKIT=1 docker build --network=host -t pandare/lava:local .
```

This applies to build steps only; containers launched later use their own
network settings.

### Container workspace

From a workspace containing `target_bins/` and `target_configs/`, use the
launcher to open a shell or run a command. It mounts the workspace at the same
absolute path so paths written to `host.json` remain valid between runs.
Replace `/path/to/lava` with the checkout containing the launcher:

```bash
/path/to/lava/scripts/docker-shell.sh
/path/to/lava/scripts/docker-shell.sh -- lava-init
/path/to/lava/scripts/docker-shell.sh -- lava --help
```

Docker runs as your UID/GID and stores its writable home in
`.lava-container-home/` within the workspace. If your host `~/.panda/` exists,
the launcher mounts it as the container's PANDA cache so existing QCOWs and
kernel files are reused. Downloads and cache changes persist in that host
directory. Use `--panda-cache /path/to/cache` to select another existing cache.
Without a host cache, PANDA stores downloads in `.lava-container-home/.panda/`.
The launcher uses
`pandare/lava:latest` by default; use `--image pandare/lava:v3.3.4` to select a
release, or `--image pandare/lava:local` for the local build above.

PostgreSQL must already be running. Export `POSTGRES_USER` and
`POSTGRES_PASSWORD`, to the database endpoint reachable from inside the container. For a database on a Docker network, pass `--network NETWORK` and use its container name as `host`.
`localhost` inside Docker refers to the LAVA container itself. Once configured:

```bash
/path/to/lava/scripts/docker-shell.sh --network NETWORK -- lava -ak toy
```

`-k` deletes existing project data without confirmation. The launcher replaces
the old project-name-first interface; commands now follow `--`.

### HPC with Apptainer / Singularity

On an allocated compute node, use the runtime provided by the cluster. Pull a
versioned image once into persistent storage, then reuse it for jobs:

```bash
apptainer pull /path/to/scratch/lava-v3.3.4.sif docker://pandare/lava:v3.3.4
/path/to/lava/scripts/docker-shell.sh --runtime apptainer \
  --image /path/to/scratch/lava-v3.3.4.sif -- lava-init
/path/to/lava/scripts/docker-shell.sh --runtime apptainer \
  --image /path/to/scratch/lava-v3.3.4.sif -- lava -tc toy
```

Use `--runtime singularity` if that is the installed command. These runtimes
use the host user's identity and network; configure `host.json` for a reachable
PostgreSQL service and export the same credentials. The launcher neither starts
the database nor requests a scheduler allocation. Run it inside your cluster's
interactive allocation or batch script. This does not establish that a release
image supports the complete pipeline; verify the image installation and run a
toy project before submitting a large mining job.

## Ubuntu, Debian
### Local Installation
On a system running Ubuntu 22.04, you should be able to just run `bash install.sh`. 
Note that this [install script](https://github.com/panda-re/lava/blob/master/install.sh) will install packages and make changes to your system. 
You can remove the binaries using `sudo apt-get remove lava`.

Once you finish installing the binary, then you can install locally running `pip install .`. 

**NOTE** that the Python package requires a SQL file generated from compiling the binaries that is placed into `python/src/pyroclastic/data/lava.sql`. 
Without this file, the Python package will not work correctly.

### Regular installation
Alternatively, you can manually install LAVA's dependencies and then build from source. 
Download the Debian packages located in the [releases](https://github.com/panda-re/lava/releases). Then install the python package `pip install pyroclastic`.

## Final steps

### Utilizing host.json
Next, run `init-host` to generate a `host.json` in your current working directory directory.
This file is used by LAVA to store settings specific
to your machine. You can edit these settings as necessary, but the default
values should work, see [vars.py](https://github.com/panda-re/lava/blob/master/python/src/pyroclastic/utils/vars.py).

A few values to keep in mind are the following:
* **host** is the name of the Postgres SQL database with all the LAVA bugs. Currently, it defaults to `database`, although if you installed LAVA locally, you likely should change this to `localhost`

**NOTE**: You also need two environment variables for the Postgres SQL database:
* `POSTGRES_PASS` This is the password for the Postgres SQL user`
* `POSTGRES_USER` This is the hostname for the Postgres SQL database

### Project configurations
Project configurations are located in the `target_configs` directory, where
every configuration is located at `target_configs/projectname/projectname.json`.
Paths specified within these configuration files are relative to values set
in your `host.json` file.

### Setting up postgres SQL database
As alluded to, you should create a Postgres SQL user. You can use a script to [using the environment variables](https://github.com/panda-re/lava/blob/master/scripts/setup_postgres.sh) for the following:
* Create the user with provided username and password from environment variables.
* Update Postgres SQL database on host to accept traffic from external sources (e. g. LAVA Docker container)

# Usage

Finally, you can run `lava` to actually inject bugs into a program. 
Just provide the name of a project that is in the `target_configs` directory, for example:

```
lava -ak toy
```

You should now have a buggy copy of toy!

If you want to inject bugs into a new target, you will likely need to make some
modifications. Check out [How-to-Lava](https://github.com/panda-re/lava/blob/master/docs/how-to-lava.md) for guidance.

# Documentation
Check out the [docs](https://github.com/panda-re/lava/blob/master/docs/) folder to get started.

# Authors

LAVA is the result of several years of development by many people; a
partial (alphabetical) list of contributors is below:

* Andy Davis
* Brendan Dolan-Gavitt
* Andrew Fasano
* Zhenghao Hu
* Patrick Hulin
* Amy Jiang
* Engin Kirda
* Tim Leek
* Andrea Mambretti
* Andrew Quijano
* Wil Robertson
* Aaron Sedlacek
* Rahul Sridhar
* Frederick Ulrich
* Ryan Whelan
