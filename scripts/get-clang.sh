#!/bin/bash

#release="3.8.0"
release="3.6.2"
llvm_version="llvm-$release"

wget http://llvm.org/releases/$release/$llvm_version.src.tar.xz
tar -xJf $llvm_version.src.tar.xz

mv $llvm_version.src $llvm_version
cd $llvm_version

pushd tools

clang_version="cfe-$release"
wget http://llvm.org/releases/$release/$clang_version.src.tar.xz
tar -xJf $clang_version.src.tar.xz
mv $clang_version.src clang

pushd clang/tools
wget http://llvm.org/releases/$release/clang-tools-extra-$release.src.tar.xz
tar -xJf clang-tools-extra-$release.src.tar.xz
mv clang-tools-extra-$release.src extra
popd

popd

./configure --enable-optimized --disable-assertions --enable-targets=x86,arm --enable-shared --enable-pic --host=$(gcc -dumpmachine) --build=$(gcc -dumpmachine)
REQUIRES_RTTI=1 make -j $(nproc)
