#!/bin/bash

#release="3.8.0"
release="3.6.1"
llvm_version="llvm-$release"

##### FIRST INSTALL GCC 4.9 #####
sudo add-apt-repository ppa:ubuntu-toolchain-r/test
sudo apt-get update
sudo apt-get -y install gcc-4.9 g++-4.9
#################################

wget http://llvm.org/releases/$release/$llvm_version.src.tar.xz
tar -xJf $llvm_version.src.tar.xz

mv $llvm_version.src $llvm_version
cd $llvm_version
pushd tools

clang_version="cfe-$release"
wget http://llvm.org/releases/$release/$clang_version.src.tar.xz
tar -xJf $clang_version.src.tar.xz
mv $clang_version.src clang

cd clang/tools
wget http://llvm.org/releases/$release/clang-tools-extra-$release.src.tar.xz
tar -xJf clang-tools-extra-$release.src.tar.xz
mv clang-tools-extra-$release.src extra

popd
CC=`which gcc-4.9` CXX=`which g++-4.9` ./configure
make -j
#mkdir $llvm_version-build
#cd $llvm_version-build
#$cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release ../$llvm_version
#make -j
