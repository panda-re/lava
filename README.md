# LAVA: Large Scale Automated Vulnerability Addition

[![Publish Lava Package and Container](https://github.com/panda-re/lava/actions/workflows/publish_docker.yml/badge.svg)](https://github.com/panda-re/lava/actions/workflows/publish_docker.yml)

[![Lava Tests](https://github.com/panda-re/lava/actions/workflows/parallel_tests.yml/badge.svg)](https://github.com/panda-re/lava/actions/workflows/parallel_tests.yml)

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
$ DOCKER_BUILDKIT=1 docker build lava .
```

## Ubuntu, Debian
### Local Installation
On a system running Ubuntu 22.04, you should be able to just run `bash install.sh`. 
Note that this [install script](https://github.com/panda-re/lava/blob/master/install.sh) will install packages and make changes to your system. 
You can remove the binaries using `sudo apt-get remove lava`.

Once you finish installing the binary, then you can install locally running `pip install python/`. 

**NOTE** that the Python package requires a SQL file generated from compiling the binaries that is placed into `python/src/pyroclastic/data/lava.sql`. 
Without this file, the Python package will not work correctly.

### Regular installation
Alternatively, you can manually install LAVA's dependencies and then build from source. 
Download the Debian packages located in the [releases](https://github.com/panda-re/lava/releases). Then install the python package `pip install pyroclastic`.

## Final steps

### Utilizing host.json
Next, run `init_host` to generate a `host.json` in your `~/.lava` directory.
This file is used by LAVA to store settings specific
to your machine. You can edit these settings as necessary, but the default
values should work, see [vars.py](https://github.com/panda-re/lava/blob/master/python/src/pyroclastic/utils/vars.py).

A few values to keep in mind are the following:
* **pguser** This is the name of database user, currently defaults to `postgres`
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
