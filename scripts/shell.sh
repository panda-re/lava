#!/bin/bash

set -x

lava=$(dirname $(dirname $(readlink -f "$0")))
#. `dirname $0`/vars.sh
hostjson="$lava/host.json"
tar_dir="$(jq -r '.tar_dir // ""' $hostjson)"
output_dir="$(jq -r '.output_dir // ""' $hostjson)"
tarfiledir="$tar_dir"
directory=$output_dir

pb_head_dir="/usr/include/protobuf-c"
google_head_dir="/usr/include/google"

docker_map_args="-v $lava:$lava -v $tarfiledir:$tarfiledir"
if [[ "$directory" = "$tarfiledir"* ]]; then true; else
    docker_map_args="$docker_map_args -v $directory:$directory"
fi

#docker_map_args="$docker_map_args -v $pb_head_dir:$pb_head_dir -v $google_head_dir:$google_head_dir"

command=bash

docker run --rm -it \
    -e "HTTP_PROXY=$HTTP_PROXY" \
    -e "HTTPS_PROXY=$HTTPS_PROXY" \
    -e "http_proxy=$http_proxy" \
    -e "https_proxy=$https_proxy" \
    -v /var/run/postgresql:/var/run/postgresql \
    -v "$HOME/.pgpass:$HOME/.pgpass" \
    -v /etc/passwd:/etc/passwd:ro \
    -v /etc/group:/etc/group:ro \
    -v /etc/shadow:/etc/shadow:ro \
    -v /etc/gshadow:/etc/gshadow:ro \
    -v /home:/home:ro \
    --add-host=database:172.17.0.1 \
    $docker_map_args \
    $1 sh -c "trap '' PIPE; su -l $(whoami) -c \"export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/lib/llvm-11/lib; $command\"" \

