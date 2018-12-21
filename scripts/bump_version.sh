#!/bin/bash

# Version bumper for lava project
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
# Lava main src directory
LAVA_HOME=$DIR/..
# Console colors
R='\033[0;31m' # red
G='\033[0;32m' # green
NC='\033[0m'   # no color

# Script version
version="2.0.0"

# List of files to be bumped
declare -a FILE_LIST=("$LAVA_HOME/tools/CMakeLists.txt"
"$LAVA_HOME/scripts/add_queries.sh"
"$LAVA_HOME/scripts/lava.sh"
"$LAVA_HOME/scripts/verify.sh"
"$LAVA_HOME/scripts/bump_version.sh"
"$LAVA_HOME/scripts/inject.sh"
"$LAVA_HOME/scripts/competition.py"
"$LAVA_HOME/scripts/inject.py"
"$LAVA_HOME/scripts/bug_mining.py")

# Error color printer
error() {
    cprint $R "$1: Error $2"
}
# Color printer
cprint() {
    echo -e $1$2${NC}
}

# Bumper for cmake tools
cmake_file_bump () {
    ver_line=`grep -E 'project.*VERSION' $1`
    cprint $R "Bumping...$ver_line in $1"
    sed -i -E "s/[0-9]+\.[0-9]+\.[0-9]+/$2/g" $1
    ver_line=`grep -E 'project.*VERSION' $1`
    cprint $G "To $ver_line"
}

# Bumper for shell scripts
bash_file_bump() {
    ver_line=`grep -E 'version=' $1`
    cprint $R "Bumping $ver_line in $1"
    sed -i -E "s/version=\"[0-9]+\.[0-9]+\.[0-9]+\"$/version=\"$2\"/g" $1
    ver_line=`grep -E 'version=' $1`
    cprint $G "To $ver_line"
}

# Bumper for python scripts
python_file_bump() {
    ver_line=`grep -E 'version=' $1`
    cprint $R "Bumping $ver_line in $1"
    sed -i -E "s/version=\"[0-9]+\.[0-9]+\.[0-9]+\"$/version=\"$2\"/g" $1
    ver_line=`grep -E 'version=' $1`
    cprint $G "To $ver_line"
}

USAGE() {
    echo "bump_version v. $version"
    echo "Description: script to bump version within the project"
    echo "USAGE: bump_version.sh X.X.X"
}

if [[ ! ($1 =~ ^[[:digit:]]+\.[[:digit:]]+\.[[:digit:]]+$) ]]; then
    error $0 "Invalid Input"
    USAGE
    exit
fi

for i in ${FILE_LIST[@]}
do
    filename=`basename $i`
    cprint $G "Considering $i"
    if [[ $filename == "CMakeLists.txt" ]]; then
        cmake_file_bump $i $1
    fi

    if [[ $filename == *\.sh ]]; then
        bash_file_bump $i $1
    fi

    if [[ $filename == *\.py ]]; then
        python_file_bump $i $1
    fi

done



