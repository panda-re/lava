#!/bin/bash
# Query insertion script.
#
# Takes one argument, the project name
# That json file must contain all of the following
#
# name         name for project, usually the name of the software (binutils-2.25, openssh-2.1, etc)
# directory    directory in which src-2-src query injection will occur -- should be somewhere on the nas
# tarfile      path to software tar file
# configure    how to configure the software (./configure plus arguments) (will just use /bin/true if not present)
# make         how to make the software (make might have args or might have FOO=bar required precursors)
# install      how to install the software (note that configure will be run with --prefix ...lava-install)
#
# script proceeds to untar the software, run btrace on it to extract a compile_commands.json file,
# which contains all information needed to compile every file in the project.
# then, the script runs lavaTool using that compile_commands.json file, on every source file,
# adding extra source code to perform taint queries.  At the time of this writing, the taint
# queries were for every argument of every fn call, injected both before and after the call.
# Also, the return value of the fn is queried.  Oh, and lavaTool also injects "queries" that
# indicate when a potential attack point has been encountered.  At the time of this writing,
# that includes calls to memcpy and malloc.
#
# After lavaTool has transformed this source, it exits.  You should now try to make the project
# and deal with any complaints (often src-to-src breaks the code a little). Once you have a working
# version of the compiled exec with queries you will need to log on to a 64-bit machine
# and run the bug_mining.py script (which uses PANDA to trace taint).
#

# Load lava-functions and vars
. `dirname $0`/funcs.sh

tick

set -e # Exit on error
#set -x # Debug mode

if [ $# -lt 1 ]; then
  echo "Usage: $0 [ATP_Type] JSONfile"
elif [ $# -lt 2 ]; then
  echo "No ATP_Type specified.  Defaulting to all."
  ATP_TYPE=""
  json="$(readlink -f $1)"
elif [ $# -eq 2 ]; then
  ATP_TYPE="-$1"
  json="$(readlink -f $2)"
else
  echo "Usage: $0 [ATP_Type] JSONfile"
  exit 1
fi

lava="$(dirname $(dirname $(readlink -f $0)))"
project_name="$1"
. `dirname $0`/vars.sh

progress "queries" 0  "Entering $directory/$name."
mkdir -p "$directory/$name"
cd "$directory/$name"

progress "queries" 0  "Untarring $tarfile..."
source=$(tar tf "$tarfile" | head -n 1 | cut -d / -f 1)

if [ -e "$source" ]; then
  progress "queries" 0  "Deleting $directory/$name/$source..."
  rm -rf "$directory/$name/$source"
fi
tar xf "$tarfile"

progress "queries" 0  "Entering $source."
cd "$source"

progress "queries" 0  "Creating git repo."
rm -rf .git || true #Remove any existing git repo
git init
git config user.name LAVA
git config user.email "nobody@nowhere"
git add -A .
git commit -m 'Unmodified source.'

progress "queries" 0  "Configuring..."
mkdir -p lava-install
$configure_cmd --prefix=$(pwd)/lava-install


progress "queries" 0  "Making with btrace..."
ORIGIN_IFS=$IFS
IFS='&&'
read -ra MAKES <<< $makecmd
for i in ${MAKES[@]}; do
    IFS=' '
    read -ra ARGS <<< $i
    $lava/tools/btrace/sw-btrace ${ARGS[@]}
    IFS='&&'
done
IFS=$ORIGIN_IFS


progress "queries" 0  "Installing..."
bash -c $install


# figure out where llvm is
llvm_src=$(grep LLVM_SRC_PATH $lava/tools/lavaTool/config.mak | cut -d' ' -f3)


progress "queries" 0  "Creating compile_commands.json..."
$lava/tools/btrace/sw-btrace-to-compiledb $llvm_src/Release/lib/clang/3.6.2/include
if [ -e "$directory/$name/extra_compile_commands.json" ]; then
    sed -i '$d' compile_commands.json
    echo "," >> compile_commands.json
    tail -n +$((2)) "$directory/$name/extra_compile_commands.json" >> compile_commands.json
fi
git add compile_commands.json
git commit -m 'Add compile_commands.json.'

cd ..

c_files=$(python $lava/tools/lavaTool/get_c_files.py $source)
c_dirs=$(for i in $c_files; do dirname $i; done | sort | uniq)

progress "queries" 0  "Copying include files..."
for i in $c_dirs; do
  echo "   $i"
  if [ -d $i ]; then
    cp $lava/tools/include/*.h $i/
  fi
done

if [ "$dataflow" = "true" ]; then
    progress "queries" 0 "Using dataflow as specified in project.json"

# Run another clang tool that provides information about functions,
# i.e., which have only prototypes, which have bodies.
    progress "queries" 0 "Figure out functions"
    for i in $c_files; do
        $lava/tools/install/bin/lavaFnTool $i
    done

# analyze that output and figure out
    fnfiles=$(echo $c_files | sed 's/\.c/\.c\.fn/g')
    fninstr=$directory/$name/fninstr

    echo "Creating fninstr [$fninstr]"
    echo -e "\twith command: \"python $lava/scripts/fninstr.py -d -o $fninstr $fnfiles\""
    python $lava/scripts/fninstr.py -d -o $fninstr $fnfiles

    # Insert queries with DF - could merge this with the else if logic below instead of duplicating
    # TODO: Just make lavaTool load dataflow from project.json instead of passing as CLI arg.
    # Since it's okay to pass the whitelist either way
    progress "queries" 0  "Inserting queries with dataflow"
    for i in $c_files; do
        $lava/tools/install/bin/lavaTool -action=query \
        -lava-db="$directory/$name/lavadb" \
        -p="$source/compile_commands.json" \
        -arg_dataflow \
        -lava-wl="$fninstr" \
        -src-prefix=$(readlink -f "$source") \
        $ATP_TYPE \
        -db="$db" \
        $i
    done
else

    progress "queries" 0  "Inserting queries..."
    for i in $c_files; do
        $lava/tools/install/bin/lavaTool -action=query \
        -lava-db="$directory/$name/lavadb" \
        -p="$source/compile_commands.json" \
        -src-prefix=$(readlink -f "$source") \
        $ATP_TYPE \
        -db="$db" \
        $i
    done
fi

for i in $c_dirs; do
    echo "  Applying replacements to $i"
    pushd $i
    $llvm_src/Release/bin/clang-apply-replacements .
    popd
done

progress "queries" 0  "Done inserting queries. Time to make and run actuate.py on a 64-BIT machine!"

tock
echo "add queries complete $time_diff seconds"

