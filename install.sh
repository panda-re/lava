#!/bin/bash
sudo add-apt-repository ppa:phulin/panda
sudo cp /etc/apt/sources.list /etc/apt/sources.list~
sudo sed -Ei 's/^# deb-src /deb-src /' /etc/apt/sources.list
sudo apt-get update
sudo apt-get install python-pip git protobuf-compiler protobuf-c-compiler libprotobuf-c0-dev libprotoc-dev python-protobuf libelf-dev libcapstone-dev libdwarf-dev python-pycparser llvm-3.3 clang-3.3 libc++-dev libwiretap-dev libwireshark-dev odb
sudo apt-get build-dep qemu
sudo pip install --upgrade pip
sudo pip install colorama