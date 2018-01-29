#!/bin/bash

USAGE() {
  echo "USAGE: $0 /path/to/json"
  echo "Example to run lavaTool on file"
  echo "Before using this you must have run everything.sh -ak on your file.json"
  exit 1
}

if [ -z "$1" ]; then
    USAGE
fi

json=$(dirname "`pwd`/$1")/$(basename $1)

if [ -z "$json" ]; then
    echo "Something went wrong"
    exit 2
fi

directory="$(jq -r .directory $json)"
name="$(jq -r .name $json)"
lava=$(dirname $(dirname $(readlink -f "$0")))

${lava}/scripts/docker-shell.sh $json "${lava}/src_clang/build/lavaTool -action=inject -bug-list=3245,14875 -src-prefix=${directory}/${name}/bugs/0/file-5.22 -project-file=${json} -main-files=${directory}/${name}/bugs/0/file-5.22/src/file.c ${directory}/${name}/bugs/0/file-5.22/src/apprentice.c"
