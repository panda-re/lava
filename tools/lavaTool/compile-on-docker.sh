#!/bin/bash

set -x

lava="$(dirname "$( cd "$( dirname "${BASH_SOURCE[0]}"  )" && pwd  )")"
llvm_home="/llvm-3.6.2"

docker run --rm -it \
    -e "HTTP_PROXY=$HTTP_PROXY" \
    -e "HTTPS_PROXY=$HTTPS_PROXY" \
    -e "http_proxy=$http_proxy" \
    -e "https_proxy=$https_proxy" \
    -e "LLVM_DIR=$llvm_home" \
    -v /var/run/postgresql:/var/run/postgresql \
    -v /etc/passwd:/etc/passwd:ro \
    -v /etc/group:/etc/group:ro \
    -v /etc/shadow:/etc/shadow:ro \
    -v /etc/gshadow:/etc/gshadow:ro \
    -v $HOME:$HOME \
    -v "$lava":"$lava" \
    lava32 sh -c "trap '' PIPE; su -l $(whoami) -c 'cmake -B$lava/build -H$lava -DCMAKE_INSTALL_PREFIX=$lava/install' && su -l $(whoami) -c 'make --no-print-directory -j$(nproc) -C \"$lava\"/build/lavaTool install'"
