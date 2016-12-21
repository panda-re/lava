#!/bin/bash

json="$(readlink -f $1)"

lava="$(dirname "$( cd "$( dirname "${BASH_SOURCE[0]}"  )" && pwd  )")"
db="$(jq -r .db $json)"
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
echo docker run --rm -it \
    -e "HTTP_PROXY=$HTTP_PROXY" \
    -e "HTTPS_PROXY=$HTTPS_PROXY" \
    -e "http_proxy=$http_proxy" \
    -e "https_proxy=$https_proxy" \
    -v /var/run/postgresql:/var/run/postgresql \
    -v /etc/passwd:/etc/passwd:ro \
    -v /etc/group:/etc/group:ro \
    -v /etc/shadow:/etc/shadow:ro \
    -v /etc/gshadow:/etc/gshadow:ro \
    -v "$HOME":"$HOME" \
    $docker_map_args \
    lava32 sh -c "apt-get install sudo gdb; trap '' PIPE; login -f $(whoami)"
docker run --rm -it \
    -e "HTTP_PROXY=$HTTP_PROXY" \
    -e "HTTPS_PROXY=$HTTPS_PROXY" \
    -e "http_proxy=$http_proxy" \
    -e "https_proxy=$https_proxy" \
    -v /var/run/postgresql:/var/run/postgresql \
    -v /etc/passwd:/etc/passwd:ro \
    -v /etc/group:/etc/group:ro \
    -v /etc/shadow:/etc/shadow:ro \
    -v /etc/gshadow:/etc/gshadow:ro \
    -v "$HOME":"$HOME" \
    $docker_map_args \
    lava32 sh -c "apt-get install -y sudo gdb; trap '' PIPE; login -f $(whoami)"
