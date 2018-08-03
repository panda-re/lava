#!/bin/bash

set -x

lava="$(dirname "$( cd "$( dirname "${BASH_SOURCE[0]}"  )" && pwd  )")"


# Start host_fninstr.sh, a watchdog that runs fninstr.sh on the host as necessary
# Argument = number of targets to rebuild
NUM_TARGETS="2"
$lava/src_clang/_tests/host_fninstr.sh "$lava/src_clang/_tests" $NUM_TARGETS &> $lava/src_clang/_tests/log_hostfninstr.txt &
PID="$!"
echo "Started host_fninstr with pid=$PID"

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
    -v "$lava":"$lava" \
    lava32 sh -c "trap '' PIPE; su -l $(whoami) -c 'make -j$(nproc) -C \"$lava\"/src_clang && $lava/src_clang/_tests/run.sh \"$lava\"'"

kill $PID 2>/dev/null # Kill host_fninstr.sh
