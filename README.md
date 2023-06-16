# Chaff README

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

## Building chaff

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
On a system running Ubuntu 22.04, you should be able to just run `bash install.sh`. Note that this [install script](./install.sh) will install packages and make changes to your system.

## Final steps

### Utilizing host.json
Next, run `init-host.py` to generate a `host.json`.
This file is used by LAVA to store settings specific
to your machine. You can edit these settings as necessary, but the default
values should work, see [vars.sh](scripts/vars.sh).

A few values to keep in mind are the following:
* **buildhost** This is the location of where LAVA is being executed from. Currently, it defaults to `localhost`
* **docker** is the name of the docker image to use that has the LAVA binaries. Currently it defaults to `lava32`, but you can switch this to `pandare/lava`
* **pguser** This is the name of database user, currently defaults to `postgres`
* **pgpass** This is the password of the database user, currently defaults to `postgrespostgres`
* **host** is the name of the Postgres SQL database with all the LAVA bugs. Currently it defaults to `database`, although if you installed LAVA locally, you likely should change this to `localhost`

### Project configurations
Project configurations are located in the `target_configs` directory, where
every configuration is located at `target_configs/projectname/projectname.json`.
Paths specified within these configuration files are relative to values set
in your `host.json` file.

### Setting up postgres SQL database
As alluded to, you should create a Postgres SQL user. You can use a script to [use default credentials](scripts/setup_postgres.sh) for the following:
* Create the user with default password
* Update Postgres SQL database on host to accept traffic from external sources (e. g. LAVA Docker container)
* Switch password encryption to md5 (Do we need this?)

# Usage

Finally, you can run `./scripts/lava.sh` to actually inject bugs into a program. Just provide the name of a project that is in the `target_configs` directory, for example:

```
cd chaff/docker
docker build -t lava32chaff .
```
(The Docker image uses Debian snapshot as repository, which can be slow at times possibly due to
rate limiting. If apt-get commands are taking too long, interrupt and restart the build. It might
speed things up.)

Next spawn a shell in the Docker image

```
./scripts/docker-shell.sh
```

In this shell, build panda and then build the LAVA tools

```
./panda/setup.sh
python2 ./setup_container.py
```

(`panda/setup.sh` may fail in install step but that error is fine.)

## Preparing host

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
