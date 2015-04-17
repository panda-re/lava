#!/bin/bash

# Assumes you run this from /home/$USER/src

rm -r file-5.11
cp -r file-5.11-orig file-5.11

# Assumes you've gathered and saved original compile_commands.json
cp file_compile_commands_complete.json file-5.11/compile_commands.json
cd file-5.11
cp ~/git/lava/include/pirate_mark_lava.h src/
cp ~/git/lava/include/panda_hypercall_struct.h src/
./configure --prefix=`pwd`/install
/home/$USER/git/lava/src_clang/get_c_files.py /home/$USER/src/file-5.11 | \
    while read line; do /home/$USER/git/lava/src_clang/build/lavaTool \
    -lava-db=/home/$USER/src/file-5.11/lavadb.db -p=/home/$USER/src/file-5.11 $line; done
make -j $(nproc)
make install
cd ..

