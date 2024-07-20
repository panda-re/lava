#!/bin/bash
set -ex

progress() {
  echo
  echo -e "\e[32m[lava_install]\e[0m \e[1m$1\e[0m"
}

if [ -z "${LLVM_DIR}" ]; then
    echo "LLVM_DIR is not set ${LLVM_DIR}, setting it to /usr/lib/llvm-11"
    export LLVM_DIR=/usr/lib/llvm-11
else
    echo "LLVM_DIR is set to '${LLVM_DIR}'"
fi


LAVA_DIR=$(dirname "$(realpath "$0")")
echo "LAVA_DIR: $LAVA_DIR"

progress "Compile btrace"
pushd "$LAVA_DIR/tools/btrace"
./compile.sh
popd

progress "Compiling lavaTool"

rm -rf "$LAVA_DIR/tools/build"
mkdir -p "$LAVA_DIR/tools/build"
mkdir -p "$LAVA_DIR/tools/install"

cmake -B"$LAVA_DIR/tools/build" -H"${LAVA_DIR}/tools" -DCMAKE_INSTALL_PREFIX="${LAVA_DIR}/tools/install"
make --no-print-directory -j4 install -C "${LAVA_DIR}/tools/build/lavaTool"

progress "Compiling fbi"

make --no-print-directory -j4 install -C "${LAVA_DIR}/tools/build/fbi"
