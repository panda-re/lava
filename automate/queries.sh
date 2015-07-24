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

progress "Entering $directory/$name."
mkdir -p "$directory/$name"
cd "$directory/$name"

tarfile="$(jq -r .tarfile $json)"

progress "Untarring $tarfile..."
source=$(tar tf "$tarfile" | head -n 1 | cut -d / -f 1)
if [ -e "$source" ]; then
  rm -rf "$source"
fi
tar xf "$tarfile"

progress "Entering $source."
cd "$source"

progress "Creating git repo."
git init
git add -A .
git commit -m 'Unmodified source.'

progress "Configuring..."
mkdir -p lava-install
$(jq -r .configure $json) --prefix=$(pwd)/lava-install

progress "Making..."
$lava/btrace/sw-btrace $(jq -r .make $json)

progress "Installing..."
$(jq -r .install $json)

progress "Creating compile_commands.json..."
$lava/btrace/sw-btrace-to-compiledb /home/moyix/git/llvm/Debug+Asserts/lib/clang/3.6.1/include
git add compile_commands.json
git commit -m 'Add compile_commands.json.'

cd ..

tar czf "btraced.tar.gz" "$source"

c_files=$(python $lava/src_clang/get_c_files.py $source)
c_dirs=$(for i in $c_files; do dirname $i; done | sort | uniq)

progress "Copying include files..."
for i in $c_dirs; do
  echo "   $i"
  cp $lava/include/*.h $i/
done

progress "Inserting queries..."
for i in $c_files; do
  $lava/src_clang/build/lavaTool -action=query -lava-db=lavadb \
    -p="$source/compile_commands.json" "$i"
done

progress "Done inserting queries. Time to make and run actuate.py on a 64-BIT machine!"
