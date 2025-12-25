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
As alluded to, you should create a Postgres SQL user. You can use a script to [use default credentials](setup_postgres.sh) for the following:
* Create the user with default password
* Update Postgres SQL database on host to accept traffic from external sources (e. g. LAVA Docker container)
* Switch password encryption to md5 (Do we need this?)

# Usage

Finally, you can run `./scripts/lava.sh` to actually inject bugs into a program. Just provide the name of a project that is in the `target_configs` directory, for example:

```
./scripts/lava.sh toy
```

You should now have a buggy copy of toy!

If you want to inject bugs into a new target, you will likely need to make some
modifications. Check out [How-to-Lava](docs/how-to-lava.md) for guidance.

# Documentation
Check out the [docs](docs/) folder to get started.


# Current Status
## Version 2.0.0

Expected results from test suite:
```
Project       RESET    CLEAN    ADD      MAKE     TAINT    INJECT   COMP
blecho        PASS     PASS     PASS     PASS     PASS     PASS     PASS
libyaml       PASS     PASS     PASS     PASS     PASS     PASS     PASS
file          PASS     PASS     PASS     PASS     PASS     PASS     PASS
toy           PASS     PASS     PASS     PASS     PASS     PASS     PASS
pcre2         PASS     PASS     PASS     PASS     PASS     PASS     PASS
jq            PASS     PASS     PASS     PASS     PASS     PASS     PASS
grep          PASS     PASS     PASS     PASS     PASS     FAIL
libjpeg       PASS     PASS     PASS     PASS     FAIL
tinyexpr      PASS     PASS     PASS     PASS     FAIL
duktape       PASS     PASS     PASS     FAIL
tweetNaCl     PASS     PASS     FAIL
gzip          FAIL
```

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
