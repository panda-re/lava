#!/bin/bash


LAVA_DIR="$(dirname "$( cd "$( dirname "${BASH_SOURCE[0]}"  )" && pwd  )")"

docker run \
    --rm -v $LAVA_DIR:$LAVA_DIR lava32 \
    make -B -C $LAVA_DIR/src_clang -j${PANDA_NPROC:-$(nproc || sysctl -n hw.ncpu)}
