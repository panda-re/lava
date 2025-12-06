#!/bin/bash

#LLVM_DIR="$HOME/bpf/install"
LLVM_DIR="/llvm-3.3-install"
PANDA_DIR="$( realpath $( dirname "${BASH_SOURCE[0]}" ) )"

mkdir -p ${PANDA_DIR}/build
pushd ${PANDA_DIR}/build
QEMU_CFLAGS='-D_GLIBCXX_USE_CXX11_ABI=0' CXXFLAGS='-D_GLIBCXX_USE_CXX11_ABI=0' "../src/configure" \
    --target-list=x86_64-softmmu \
    --prefix="${PANDA_DIR}/install" \
    --cc=gcc-6 --cxx=g++-6 \
    --enable-llvm --with-llvm="${LLVM_DIR}" \
    --python=python2 \
    --extra-plugins-path="${PANDA_DIR}/.."

make -j ${PANDA_NPROC:-$(nproc || sysctl -n hw.ncpu)}
popd
