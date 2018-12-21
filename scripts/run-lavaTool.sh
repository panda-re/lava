#!/bin/bash

USAGE() {
  echo "USAGE: $0 /path/to/json"
  echo "Example to run lavaTool on file"
  echo "Before using this you must have run lava.sh -ak on your file.json"
  exit 1
}

if [ -z "$1" ]; then
    USAGE
fi

json=$(dirname "`pwd`/$1")/$(basename $1)
. `dirname $0`/vars.sh

if [ -z "$json" ]; then
    echo "Something went wrong"
    exit 2
fi

pushd
cd ${directory}/${name}/bugs/0/file-5.22/src/
git reset --hard
rm *.yaml
popd

#${lava}/scripts/docker-shell.sh $json "${lava}/src_clang/build/lavaTool -action=inject -bug-list=6310, -src-prefix=${directory}/${name}/bugs/0/file-5.22 -project-file=${json} -main-files=${directory}/${name}/bugs/0/file-5.22/src/file.c ${directory}/${name}/bugs/0/file-5.22/src/cdf.c"
#${lava}/scripts/docker-shell.sh $json "${lava}/src_clang/build/lavaTool -action=inject -bug-list=110,150 -src-prefix=${directory}/${name}/bugs/0/file-5.22 -project-file=${json} -main-files=${directory}/${name}/bugs/0/file-5.22/src/file.c ${directory}/${name}/bugs/0/file-5.22/src/encoding.c"
#${lava}/scripts/docker-shell.sh $json "${lava}/src_clang/build/lavaTool -action=inject -bug-list=110,150 -src-prefix=${directory}/${name}/bugs/0/file-5.22 -project-file=${json} -main-files=${directory}/${name}/bugs/0/file-5.22/src/file.c ${directory}/${name}/bugs/0/file-5.22/src/magic.c -competition"

echo "In ${directory}/${name}/..."

${lava}/scripts/docker-shell.sh $json /home/fasano/lava/src_clang/build/lavaTool -action=inject -bug-list=174,1568,1960,2477,3609,66334,71687,73291,79238,80729,82653,85136,86858,89210,136422,149463,203467,233188,281179,527201,552737,552747,552748,613484,613495,613520,613889,614026 -src-prefix=/home/fortenforge/lava/file_fortenforge/competition/bugs/file-5.22 -project-file=/home/fasano/lava/file_fortenforge.json -main-files=/home/fortenforge/lava/file_fortenforge/competition/bugs/file-5.22/src/file.c /home/fortenforge/lava/file_fortenforge/competition/bugs/file-5.22/src/softmagic.c -competition

