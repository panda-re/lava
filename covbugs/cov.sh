#!/bin/bash
#set -x
set -e

# Usage ./cov [root_dir] [inputs]
# Configure PROG and PROG_DIR below

DIR=$1
pushd $DIR

shift

#echo $@

#make clean | true
CFLAGS=--coverage make install
PROG_DIR="sqlite/src/src"
PROG="sqlite"

popd

rm -f result.info
rm -rf scratch | true
mkdir scratch 

doit=false

for input in $(ls $@); do
    echo $input
    safename=$(basename $input)

    ${PROG_DIR}/${PROG} < ${input} | true # Non-zero exits are allowed
    geninfo ${PROG_DIR} -o scratch/cov_$safename.info

    if [ -e result.info ]; then # If exists, append
        lcov --add-tracefile scratch/cov_$safename.info -t test_$safename -a result.info -t old -o result.info
    else # Else just copy
        lcov --add-tracefile scratch/cov_$safename.info -t test_$safename -o result.info
    fi
done

rm -rf scratch
