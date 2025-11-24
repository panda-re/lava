#!/bin/bash

# Single argument of project name will get Docker name
# from project config. Then 2nd optional argument is command to run
# With no arguments, just give us a shell

lava="$(dirname $(dirname $(readlink -f $0)))"

# This project_name is a dummy value, we just want shell access
project_name="toy"
. `dirname $0`/vars.sh

echo "You are connecting to the Docker container: ${dockername}"

if [ "$#" -ne 0 ]; then
    project_name=$1
    echo "using project ${project_name}"
    cmd="${@:2}"
    # Docker name (lava32 or lava32debug) comes from config
    . `dirname $0`/vars.sh

    docker_map_args="-v $tarfiledir:$tarfiledir"
    if [[ "$directory" = "$tarfiledir"* ]]; then true; else
      docker_map_args="$docker_map_args -v $directory:$directory"
    fi

    if ! ( docker images ${dockername} | grep -q ${dockername} ); then
        docker build -t ${dockername} "$(dirname $(dirname $(readlink -f $0)))/docker/debug"
    fi
else 
    echo "No extra args"
fi

[ "$extradockerargs" = "null" ] && extradockerargs="";
whoami="$(whoami)"
path=""
cmd="sudo -u $whoami bash -c -- \"$cmd\""

# If no 2nd argument specified, start interactive shell instead
if [ -z "$2" ] ; then
    cmd="login -f $whoami LANG=C.UTF-8 LANGUAGE=en_US LC_ALL=C.UTF-8"
    # path="$PWD"
    # TODO start shell at current path
fi

set -x
# to run debugger you need --privileged here
docker run --rm -it \
    --privileged \
    -e "HTTP_PROXY=$HTTP_PROXY" \
    -e "HTTPS_PROXY=$HTTPS_PROXY" \
    -e "http_proxy=$http_proxy" \
    -e "https_proxy=$https_proxy" \
    -e "LANG=C.UTF-8" \
    -e "LANGUAGE=en_US" \
    -e "LC_ALL=C.UTF-8" \
    -v /var/run/postgresql:/var/run/postgresql \
    -v /etc/passwd:/etc/passwd:ro \
    -v /etc/group:/etc/group:ro \
    -v /etc/shadow:/etc/shadow:ro \
    -v /etc/gshadow:/etc/gshadow:ro \
    -v "$HOME":"$HOME" \
    --cap-add=SYS_PTRACE \
    $docker_map_args \
    $extradockerargs \
    ${dockername} sh -c "trap '' PIPE; $cmd"
