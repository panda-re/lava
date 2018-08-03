#!/bin/bash

die() {
    echo >&2 "$@"
    exit 1
}

[ "$#" -eq 1 ] || die "USAGE: $0 [lava_root_dir]";

LAVA=$1
pushd `pwd` > /dev/null
cd ${LAVA}/src_clang/_tests


# Go into directory X, run lavaFnTool and then lavaTool on x.c
runtest() {
    cd $1
    if [ ! -f ./compile_commands.json ]; then
        make clean
        ../../../btrace/sw-btrace make
        ../../../btrace/sw-btrace-to-compiledb btrace.log
        rm btrace.log
    fi

    ../../build/lavaFnTool ./$1.c
    ../../build/lavaTool -debug -lava-wl ./$1.c.fn -src-prefix=`pwd`  -action=inject $1.c
    cd ..
}

runtest evil
runtest torture

popd > /dev/null
