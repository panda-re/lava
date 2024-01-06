#!/bin/bash


lava="$(dirname $(dirname $(readlink -f $0)))"
project_name="$1"
. `dirname $0`/vars.sh
. `dirname $0`/funcs.sh

fnwhitelist=$directory/$name/fnwhitelist
fnpickle=$directory/$name/getfns.pickle

# Filter out function pointer calls in the call trace
#python $lava/scripts/dataflow.py -o $fnwhitelist -i $fnpickle -p $project_name

set -e # Exit on error

progress "sanitize" 0  "Preparing Env..."
targetname=$(tar tf "$tarfile" | head -n 1 | cut -d / -f 1)
sandir="$directory/$name/san"
rm -rf $sandir

mkdir $sandir
pushd $sandir
tar -xf "$tarfile"

progress "sanitize" 0  "Preprocessing code..."
cd "$targetname"
mkdir -p lava-install
configure_file=${configure_cmd%% *}
if [ -e "$configure_file" ]; then
    CC=/llvm-3.6.2/Release/bin/clang CXX=/llvm-3.6.2/Release/bin/clang++ CFLAGS="-O0 -DHAVE_CONFIG_H -g -gdwarf-2 -fno-stack-protector -D_FORTIFY_SOURCE=0 -I. -I.. -I../include -I./src/" $configure_cmd --prefix=$(pwd)/lava-install
fi

cat ${lava}/makefile.fixup >> Makefile && \
make lava_preprocess

progress "sanitize" 0  "Making with btrace..."
ORIGIN_IFS=$IFS
IFS='&&'
read -ra MAKES <<< $makecmd
for i in ${MAKES[@]}; do
    IFS=' '
    read -ra ARGS <<< $i
    echo "$lava/tools/btrace/sw-btrace ${ARGS[@]}"
    $lava/tools/btrace/sw-btrace ${ARGS[@]}
    IFS='&&'
done
IFS=$ORIGIN_IFS

progress "sanitize" 0  "Installing..."
bash -c $install

llvm_src=$(grep LLVM_SRC_PATH $lava/tools/lavaTool/config.mak | cut -d' ' -f3)

progress "sanitize" 0  "Creating compile_commands.json..."
$lava/tools/btrace/sw-btrace-to-compiledb $llvm_src/Release/lib/clang/3.6.2/include
if [ -e "$directory/$name/extra_compile_commands.json" ]; then
    sed -i '$d' compile_commands.json
    echo "," >> compile_commands.json
    tail -n +$((2)) "$directory/$name/extra_compile_commands.json" >> compile_commands.json
fi

cd ..

c_files=$(python $lava/tools/lavaTool/get_c_files.py $targetname)
c_dirs=$(for i in $c_files; do dirname $i; done | sort | uniq)

progress "sanitize" 0 "Run sanitizer..."
stdbuf -o0 echo lava/tools/install/bin/duasan -db=$db -p=$sandir/$targetname/compile_commands.json -src-prefix=$(readlink -f $targetname) $c_files
$lava/tools/install/bin/duasan -db=$db \
    -p="$sandir/$targetname/compile_commands.json" \
    -src-prefix=$(readlink -f "$targetname") \
    $c_files
#for this_c_file in $c_files; do
#    stdbuf -o0 echo lava/tools/install/bin/duasan -db=$db -p=$sandir/$targetname/compile_commands.json -src-prefix=$(readlink -f $targetname) $this_c_file
#    $lava/tools/install/bin/duasan -db=$db \
#        -p="$sandir/$targetname/compile_commands.json" \
#        -src-prefix=$(readlink -f "$targetname") \
#        $this_c_file
#done

popd
