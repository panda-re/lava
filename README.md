# Chaff README

These instructions were tested on Ubuntu 22.04.

## Building chaff

Build the Docker image

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

- `sudo apt install postgresql python-pip libodb-pgsql-2.4 jq`
- Install docker. [See here for instructions](https://docs.docker.com/engine/install/ubuntu/)
- `pip2 install colorama`
- Run `setup_postgresql.py` using `python2` to set up DB and some DB config.
- To enable accessing database from docker container, add
    - add `listen_addresses = '172.17.0.1, localhost'` and `password_encryption = md5` to
      `/etc/postgresql/<version>/main/postgresql.conf`.
    - add `host all all 172.17.0.0/16 md5` to `/etc/postgresql/<version>/main/pg_hba.conf`.
    - replace all `scram-sha-256` with `md5` in `/etc/postgresql/<version>/main/pg_hba.conf`
    - Reset password by logging into psql.
    - Restart postgresql.
    - Run docker shell and see if logging in using `psql -h 172.17.0.1 -U postgres` works using the
      password.

## Inserting chaff bugs

- `python2 ./init-host.py`
- `./scripts/lava.sh -ak <target>`
- For more options, run `./scripts/lava.sh -h`
