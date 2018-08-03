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
    touch ./built

    echo "Ran lavaFnTool. Waiting for host_fninstr..."

    # Wait for host_fninstr to run
    while [ -f  ./built ]; do sleep 0.1; done

    echo "host_fninstr finished!"

    ../../build/lavaTool -debug -lava-wl ./$1.fnwl -arg_dataflow -src-prefix=`pwd`  -action=inject $1.c

    cp $1.c{,.bak}
    ../../build/clang-apply-replacements .
    make clean
    make &> log.txt

    mv $1{.c,.df.c}
    mv $1.c{.bak,}

    cd ..
}

runtest evil
runtest torture


echo
echo
echo "Evil"
cat evil/log.txt

echo
echo

echo "Torture"
cat torture/log.txt

wc_evil=$(wc -l ./evil/log.txt)
wc_torture=$(wc -l ./torture/log.txt)

echo
echo "Evil gcc line count: $wc_evil"
echo "Torture gcc line count: $wc_torture"

popd > /dev/null
