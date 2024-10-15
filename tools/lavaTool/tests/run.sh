#!/bin/bash

die() {
    echo >&2 "$@"
    exit 1
}

[ "$#" -eq 1 ] || die "USAGE: $0 [lava_root_dir]";

LAVA=$1
pushd `pwd` > /dev/null
cd ${LAVA}/lavaTool/tests

# Go into directory X, run lavaFnTool and then lavaTool on x.c
runtest() {
    cd $1
    if [ ! -f ./compile_commands.json ]; then
        make clean
        ../../../btrace/sw-btrace make
        ../../../btrace/sw-btrace-to-compiledb btrace.log
        rm btrace.log
    fi

    ../../../install/bin/lavaFnTool ./$1.c &> lavaFnTool.log
    touch ./built

    echo "Ran lavaFnTool. Waiting for host_fninstr..."

    # Wait for host_fninstr to run
    while [ -f  ./built ]; do sleep 0.1; done

    echo "host_fninstr finished!"

    ../../../install/bin/lavaTool -debug -lava-wl ./$1.fnwl -arg_dataflow -src-prefix=`pwd`  -action=inject $1.c &> lavaTool.log

    cp $1.c{,.bak}
    /usr/lib/llvm-11/bin/clang-apply-replacements .
    make clean
    make &> cc.log

    mv $1{.c,.df.c}
    mv $1.c{.bak,}

    cd ..
}

runtest attr
runtest evil
runtest torture


echo
echo
echo "Attribute"
cat attr/cc.log

echo
echo
echo "Evil"
cat evil/cc.log

echo
echo
echo "Torture"
cat torture/cc.log

wc_attribute=$(wc -l ./attr/cc.log)
wc_evil=$(wc -l ./evil/cc.log)
wc_torture=$(wc -l ./torture/cc.log)

echo
echo "Attribute gcc line count: $wc_attribute"
echo "Evil gcc line count: $wc_evil"
echo "Torture gcc line count: $wc_torture"

popd > /dev/null
