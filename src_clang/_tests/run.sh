#!/bin/bash

die() {
    echo >&2 "$@"
    exit 1
}

[ "$#" -eq 1 ] || die "USAGE: $0 [lava_root_dir]";

LAVA=$1
pushd `pwd` > /dev/null
cd ${LAVA}/src_clang/_tests

if [ ! -f ./compile_commands.json ]; then
    ../../btrace/sw-btrace make
    ../../btrace/sw-btrace-to-compiledb btrace.log
    rm btrace.log
fi

../build/lavaFnTool ./evil.c 
../build/lavaTool -debug -lava-wl ./evil.c.fn -action=inject ./evil.c 
popd > /dev/null
