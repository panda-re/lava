#!/bin/bash

json="$(readlink -f $1)"
cmd="${@:2}"
container="lava32debug"
#Alternatively you can use the "lava32" container

lava="$(dirname "$( cd "$( dirname "${BASH_SOURCE[0]}"  )" && pwd  )")"
db="$(jq -r .db $json)"
extradockerargs="$(jq -r .extra_docker_args $json)"
tarfile="$(jq -r .tarfile $json)"
tarfiledir="$(dirname $tarfile)"
directory="$(jq -r .directory $json)"
name="$(jq -r .name $json)"
inputs=`jq -r '.inputs' $json  | jq 'join (" ")' | sed 's/\"//g' `
buildhost="$(jq -r '.buildhost // "docker"' $json)"
pandahost="$(jq -r '.pandahost // "localhost"' $json)"
testinghost="$(jq -r '.testinghost // "docker"' $json)"
fixupscript="$(jq -r .fixupscript $json)"
makecmd="$(jq -r .make $json)"
container="$(jq -r .docker $json)"

docker_map_args="-v $tarfiledir:$tarfiledir"
if [[ "$directory" = "$tarfiledir"* ]]; then true; else
  docker_map_args="$docker_map_args -v $directory:$directory"
fi

if ! ( docker images ${container} | grep -q ${container} ); then
    docker build -t ${container} "$(dirname $(dirname $(readlink -f $0)))/docker/debug"
fi

[ "$extradockerargs" = "null" ] && extradockerargs="";

whoami="$(whoami)"
cmd="sudo -u $whoami $cmd"
if [ -z "$2" ] ; then
    cmd="login -f $whoami LANG=en_US.UTF-8 LANGUAGE=en_US LC_ALL=en_US.UTF-8"
fi

set +x
docker run --rm -it \
    -e "HTTP_PROXY=$HTTP_PROXY" \
    -e "HTTPS_PROXY=$HTTPS_PROXY" \
    -e "http_proxy=$http_proxy" \
    -e "https_proxy=$https_proxy" \
    -e "LANG=en_US.UTF-8" \
    -e "LANGUAGE=en_US:en" \
    -e "LC_ALL=en_US.UTF-8" \
    -v /var/run/postgresql:/var/run/postgresql \
    -v /etc/passwd:/etc/passwd:ro \
    -v /etc/group:/etc/group:ro \
    -v /etc/shadow:/etc/shadow:ro \
    -v /etc/gshadow:/etc/gshadow:ro \
    -v "$HOME":"$HOME" \
    $docker_map_args \
    $extradockerargs \
    ${container} sh -c "trap '' PIPE; $cmd"
