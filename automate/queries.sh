# Query insertion script. 
#!/bin/bash

progress() {
  echo
  echo -e "\e[32m[queries]\e[0m \e[1m$1\e[0m"
}

set -e # Exit on error

if [ $# -lt 1 ]; then
  echo "Usage: $0 JSONfile"
  exit 1
fi

json="$(realpath $1)"
lava="$(dirname $(dirname $(realpath $0)))"

directory="$(jq -r .directory $json)"
name="$(jq -r .name $json)"

progress "Entering $directory/$name"...
mkdir -p "$directory/$name"
cd "$directory/$name"

tarfile="$(jq -r .tarfile $json)"

progress "Untarring $tarfile..."
tar xf "$(jq -r .tarfile $json)"
source=$(ls)
c_files=$(python $lava/src_clang/get_c_files.py $source)
c_dirs=$(dirname $c_files | sort | uniq)

progress "Copying include files..."
for i in $c_dirs; do
  echo "   $i"
  cp $lava/include/*.h $i/
done

progress "Inserting queries..."
$lava/src_clang/build/lavaTool

progress "Done inserting queries. Time to make and run automate."
